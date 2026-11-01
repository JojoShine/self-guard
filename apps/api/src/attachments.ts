import {assertScope, assertEvidence} from "./scope";
import {
  Controller,
  UseGuards,
  Inject,
  Get,
  Post,
  Param,
  Body,
  Req,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { AuthGuard, allow } from "./auth";
import { Platform } from "./platform";
import { parse } from "./validation";
import { z } from "zod";
export function attachmentData(body: unknown) {
  const v = parse(
    z
      .object({
        name: z
          .string()
          .trim()
          .min(1)
          .max(200)
          .refine(
            (s) => !/[\\/\x00-\x1f]/.test(s),
            "文件名不能包含路径或控制字符",
          ),
        contentType: z.enum([
          "text/plain",
          "application/json",
          "application/pdf",
          "image/png",
          "image/jpeg",
          "application/octet-stream",
        ]),
        data: z
          .string()
          .min(4)
          .max(1398104)
          .regex(/^[A-Za-z0-9+/]*={0,2}$/),
      })
      .strict(),
    body,
  );
  const data = Buffer.from(v.data, "base64");
  if (
    data.length === 0 ||
    data.length > 1048576 ||
    data.toString("base64") !== v.data
  )
    throw new BadRequestException("需要有效的 Base64 文件，大小不超过 1 MiB");
  return { ...v, data, size: data.length };
}
@Controller()
@UseGuards(AuthGuard)
export class AttachmentsController {
  constructor(@Inject(Platform) private p: Platform) {}
  private async target(resource: string, id: string, user:any) {
    if (!["assets", "findings", "incidents", "tasks"].includes(resource))
      throw new NotFoundException();
    await assertScope(this.p.db,user,resource,id);
  }
  @Get(":resource/:id/attachments") async list(
    @Param("resource") resource: string,
    @Param("id") id: string,
    @Req() req:any,
  ) {
    assertEvidence(req.user);
    await this.target(resource, id, req.user);
    return {
      items: await this.p.db.attachment.findMany({
        where: { resource, resourceId: id },
        select: {
          id: true,
          name: true,
          contentType: true,
          size: true,
          author: true,
          createdAt: true,
        },
        orderBy: { createdAt: "desc" },
        take: 50,
      }),
    };
  }
  @Get(":resource/:id/attachments/:attachmentId") async get(
    @Param("resource") resource: string,
    @Param("id") id: string,
    @Param("attachmentId") attachmentId: string,
    @Req() req: any,
  ) {
    assertEvidence(req.user);
    await this.target(resource, id, req.user);
    const a = await this.p.db.attachment.findFirst({
      where: { id: attachmentId, resource, resourceId: id },
    });
    if (!a) throw new NotFoundException();
    await this.p.db.audit.create({
      data: {
        actor: req.user.email,
        action: "DOWNLOAD_ATTACHMENT",
        resource,
        resourceId: id,
        detail: { attachmentId },
      },
    });
    return { ...a, data: Buffer.from(a.data).toString("base64") };
  }
  @Post(":resource/:id/attachments") async upload(
    @Param("resource") resource: string,
    @Param("id") id: string,
    @Body() body: unknown,
    @Req() req: any,
  ) {
    allow(req, ["ADMIN", "ANALYST", "OPERATOR"]);
    assertEvidence(req.user);
    await this.target(resource, id, req.user);
    const v = attachmentData(body);
    return this.p.db.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${resource + id}))::text`;
      const current = await tx.attachment.aggregate({
        where: { resource, resourceId: id },
        _count: true,
        _sum: { size: true },
      });
      if (
        current._count >= 50 ||
        (current._sum.size || 0) + v.size > 20 * 1048576
      )
        throw new BadRequestException("该记录附件已达到 50 个或 20 MiB 上限");
      const a = await tx.attachment.create({
        data: { ...v, resource, resourceId: id, author: req.user.email },
        select: {
          id: true,
          name: true,
          contentType: true,
          size: true,
          author: true,
          createdAt: true,
        },
      });
      await this.p.audit(
        tx,
        req.user.email,
        "UPLOAD_ATTACHMENT",
        resource,
        id,
        { attachmentId: a.id, name: a.name, size: a.size },
      );
      return a;
    });
  }
}
