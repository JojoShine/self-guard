import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
  Controller,
  Post,
  Get,
  Body,
  Req,
  UseGuards,
  HttpCode,
  Inject,
} from "@nestjs/common";
import {DEMO_EMAIL,DEMO_SETTING,safeDemoAccount,demoRequestAllowed} from "./public-demo";
import { Db } from "./db";
import { checkPassword, hashToken, newToken, equalSecret } from "./security";
import { parse } from "./validation";
import { z } from "zod";
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@Inject(Db) private db: Db) {}
  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const token = bearer(req);
    if (!token) throw new UnauthorizedException("请先登录");
    const s = await this.db.session.findUnique({
      where: { tokenHash: hashToken(token) },
      include: { user: true },
    });
    if (!s || s.expiresAt < new Date() || s.user.disabled)
      throw new UnauthorizedException("会话已失效");
    // The reserved public identity always fails closed, even if its role is changed.
    if (s.user.email === DEMO_EMAIL) {
      const setting = await this.db.setting.findUnique({where:{key:DEMO_SETTING}});
      if (!safeDemoAccount(setting?.value,s.user) || !demoRequestAllowed(req.method,req.path,process.env.BASE_PATH||""))
        throw new ForbiddenException("体验账号只能操作独立体验空间及查看指定演示记录");
    }
    req.user = {
      id: s.user.id,
      email: s.user.email,
      name: s.user.name,
      role: s.user.role,
      dataScope: s.user.dataScope,
    };
    return true;
  }
}
export function bearer(req: any) {
  const h = req.headers.authorization;
  return typeof h === "string" && h.startsWith("Bearer ") ? h.slice(7) : "";
}
export function allow(req: any, roles: string[]) {
  if (!roles.includes(req.user?.role))
    throw new ForbiddenException("没有执行此操作的权限");
}
export function component(req: any, name: string) {
  if (!equalSecret(bearer(req), process.env[name]))
    throw new UnauthorizedException("组件身份无效");
}
@Controller("auth")
export class AuthController {
  private demoPasswordCheck?:{key:string;valid:boolean};
  constructor(@Inject(Db) private db: Db) {}
  @Get("demo")
  async demo() {
    const setting = await this.db.setting.findUnique({where:{key:DEMO_SETTING}});
    const user = await this.db.user.findUnique({where:{email:DEMO_EMAIL}});
    const config = safeDemoAccount(setting?.value,user);
    if (!config || !user) return {enabled:false};
    const key=hashToken(user.passwordHash+"\0"+config.password);
    if(this.demoPasswordCheck?.key!==key)this.demoPasswordCheck={key,valid:checkPassword(config.password,user.passwordHash)};
    if(!this.demoPasswordCheck.valid)return {enabled:false};
    return {enabled:true,email:config.email,password:config.password};
  }
  private async reserveLogin(key: string) {
    return this.db.$transaction(async tx => {
      // Serialize reservations and capacity checks across every API replica.
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()), hashtext('selfguard-auth-rate'))::text`;
      const [clock] = await tx.$queryRaw<Array<{ now: bigint }>>`SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now`;
      const now = Number(clock.now);
      await tx.setting.deleteMany({where:{key:{startsWith:'auth-rate:'},value:{path:['until'],lt:now}}});
      const previous = await tx.setting.findUnique({where:{key}});
      const counter = previous?.value as {count:number;until:number}|undefined;
      if (counter && counter.count >= 10)
        throw new ForbiddenException("登录尝试过多，请稍后重试");
      if (!previous && await tx.setting.count({where:{key:{startsWith:'auth-rate:'}}}) >= 10000)
        throw new ForbiddenException("请稍后重试");
      const value = {count:(counter?.count || 0)+1,until:counter?.until || now+900000};
      await tx.setting.upsert({where:{key},create:{key,value},update:{value}});
      return now;
    });
  }
  private async clearLogin(key: string) {
    await this.db.$transaction(async tx => {
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()), hashtext('selfguard-auth-rate'))::text`;
      await tx.setting.deleteMany({where:{key}});
    });
  }
  @Post("login")
  @HttpCode(200)
  async login(@Body() body: unknown, @Req() req: any) {
    const v = parse(
      z
        .object({
          email: z.string().email().max(254),
          password: z.string().min(1).max(256),
        })
        .strict(),
      body,
    );
    const key = 'auth-rate:' + hashToken(req.ip || "unknown");
    const now = await this.reserveLogin(key);
    const u = await this.db.user.findUnique({
      where: { email: v.email.toLowerCase() },
    });
    if (!u || u.disabled || !checkPassword(v.password, u.passwordHash)) {
      throw new UnauthorizedException("邮箱或密码错误");
    }
    if (u.email === DEMO_EMAIL) {
      const setting = await this.db.setting.findUnique({where:{key:DEMO_SETTING}});
      if (!safeDemoAccount(setting?.value,u)) throw new ForbiddenException("体验账号当前不可用");
    }
    await this.clearLogin(key);
    const token = newToken();
    await this.db.session.create({
      data: {
        userId: u.id,
        tokenHash: hashToken(token),
        expiresAt: new Date(now + 8 * 3600000),
      },
    });
    await this.db.audit.create({
      data: { actor: u.email, action: "LOGIN", resource: "auth" },
    });
    return {
      token,
      user: { id: u.id, email: u.email, name: u.name, role: u.role, dataScope: u.dataScope },
    };
  }
  @Get("me") @UseGuards(AuthGuard) me(@Req() req: any) {
    return req.user;
  }
  @Post("logout") @UseGuards(AuthGuard) async logout(@Req() req: any) {
    await this.db.session.deleteMany({
      where: { tokenHash: hashToken(bearer(req)) },
    });
    return { ok: true };
  }
}
