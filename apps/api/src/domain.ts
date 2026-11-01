import { BadRequestException, ConflictException } from "@nestjs/common";
export function findingTransition(
  kind: string,
  from: string,
  to: string,
  context: { reason?: string; expiresAt?: string },
): string {
  const map: Record<string, string[]> =
    kind === "RISK"
      ? {
          OPEN: ["CONFIRMED", "IN_PROGRESS", "ACCEPTED", "FALSE_POSITIVE"],
          CONFIRMED: ["IN_PROGRESS", "ACCEPTED", "FALSE_POSITIVE"],
          IN_PROGRESS: ["VERIFYING", "ACCEPTED", "FALSE_POSITIVE"],
          VERIFYING: ["IN_PROGRESS"],
          CLOSED: ["OPEN"],
          ACCEPTED: ["OPEN"],
          FALSE_POSITIVE: ["OPEN"],
        }
      : {
          OPEN: ["IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"],
          IN_PROGRESS: ["RESOLVED", "FALSE_POSITIVE"],
          RESOLVED: ["OPEN"],
          FALSE_POSITIVE: ["OPEN"],
        };
  if (!(map[from] || []).includes(to))
    throw new BadRequestException("非法状态转换；风险关闭需要独立复测");
  if (
    ["ACCEPTED", "FALSE_POSITIVE", "RESOLVED"].includes(to) &&
    !context.reason?.trim()
  )
    throw new BadRequestException("需要处置原因");
  if (
    to === "ACCEPTED" &&
    (!context.expiresAt ||
      !Number.isFinite(Date.parse(context.expiresAt)) ||
      Date.parse(context.expiresAt) <= Date.now())
  )
    throw new BadRequestException("风险接受需要未来到期时间");
  return to;
}
export function taskTransition(from: string, action: string): string {
  const map: Record<string, Record<string, string>> = {
    PENDING: { approve: "APPROVED", reject: "REJECTED" },
    APPROVED: { claim: "RUNNING" },
    RUNNING: { success: "VERIFYING", failure: "FAILED", timeout: "UNKNOWN" },
    VERIFYING: { verify: "SUCCEEDED", failVerification: "FAILED" },
  };
  const next = map[from]?.[action];
  if (!next) throw new ConflictException("任务状态已变化或不允许此操作");
  return next;
}
export function validateTaskParameters(value: any): {
  path: string;
  mode: string;
} {
  if (
    !value ||
    typeof value.path !== "string" ||
    !value.path.startsWith("/") ||
    value.path === "/" ||
    value.path.includes("\0") ||
    value.path.split("/").includes("..") ||
    value.path.length > 4096 ||
    !["0600", "0640", "0644"].includes(value.mode)
  )
    throw new BadRequestException(
      "需要绝对文件路径及受支持的安全权限 0600/0640/0644",
    );
  return { path: value.path, mode: value.mode, ...validateHealthService(value) };
}
export function redactEvent(value: any) {
  return {
    path: String(value.path || "/")
      .split("?")[0]
      .slice(0, 1024),
    method: String(value.method || "GET").slice(0, 16),
    remoteIp: String(value.remoteIp || "").slice(0, 100),
    action: String(value.action || "OBSERVE").slice(0, 24),
    ruleId: String(value.ruleId || "").slice(0, 100),
  };
}
export function validateConfigParameters(value: any) {
  const path = value?.path;
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path === "/" ||
    path.includes("\0") ||
    path.split("/").includes("..") ||
    path.length > 4096
  )
    throw new BadRequestException("需要绝对文件路径");
  if (
    typeof value.key !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value.key)
  )
    throw new BadRequestException("仅支持明确的 KEY=VALUE 配置项");
  for (const field of ["expectedValue", "value"])
    if (
      typeof value[field] !== "string" ||
      value[field].length > 4096 ||
      /[\x00-\x1f\x7f]/.test(value[field])
    )
      throw new BadRequestException("配置值不能包含换行或控制字符");
  return {
    path,
    key: value.key,
    expectedValue: value.expectedValue,
    value: value.value,
    ...validateHealthService(value),
  };
}
export function validateServiceParameters(value:any){
 if(!value||typeof value.service!=='string'||!/^[A-Za-z0-9_.@-]+\.service$/.test(value.service)||!['active','inactive'].includes(value.expectedState)||!['active','inactive'].includes(value.state))throw new BadRequestException('需要明确的服务单元、旧状态和目标状态');
 return {service:value.service,expectedState:value.expectedState,state:value.state};
}

function validateHealthService(value:any):{healthService?:string}{if(value.healthService===undefined||value.healthService==='')return {};if(typeof value.healthService!=='string'||!/^[A-Za-z0-9_.@-]+\.service$/.test(value.healthService))throw new BadRequestException('健康检查仅接受明确的服务单元');return {healthService:value.healthService};}
