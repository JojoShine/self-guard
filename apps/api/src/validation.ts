import {sshAccessInput} from './asset-remote-contract';
import { BadRequestException } from "@nestjs/common";
import { z } from "zod";
export function parse<T extends z.ZodTypeAny>(
  schema: T,
  value: unknown,
): z.output<T> {
  const r = schema.safeParse(value);
  if (!r.success)
    throw new BadRequestException(
      r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
    );
  return r.data;
}
export const text = z.string().trim().min(1).max(500);
export const severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED"]);
export const role = z.enum(["ADMIN", "ANALYST", "OPERATOR", "VIEWER"]);
export const findingInput = z
  .object({
    externalId: text,
    title: text,
    kind: z.enum(["RISK", "ALERT"]),
    severity,
    source: text,
    evidence: z.string().max(16000),
    assetId: z.string().uuid().optional(),
  })
  .strict();
export const ruleInput = z
  .object({
    name: text,
    kind: z.enum(["BASELINE", "LOG", "FIM", "VULNERABILITY"]),
    severity,
    enabled: z.boolean().optional(),
    intervalSeconds: z.number().int().min(60).max(604800).nullable().optional(),
    config: z.record(z.string(), z.unknown()),
  })
  .strict();
export const siteInput = z
  .object({
    name: text,
    hostname: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-zA-Z0-9.-]+$/)
      .transform((s) => s.toLowerCase()),
    upstream: z
      .string()
      .url()
      .refine((s) => {
        const u = new URL(s);
        return (
          ["http:", "https:"].includes(u.protocol) &&
          !u.username &&
          !u.password &&
          !u.hash
        );
      }, "HTTP upstream without credentials required"),
    mode: z.enum(["OBSERVE", "BLOCK"]).optional(),
    enabled: z.boolean().optional(),
    config: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();
export const assetInput = z
  .object({
    executorPublicKey:z.string().refine(s=>{const b=Buffer.from(s,'base64');return b.length===32&&b.toString('base64')===s},'需要32字节Ed25519公钥的标准Base64').nullable().optional(),
    hostname: text,
    sshAccess: sshAccessInput.optional(),
    os: text,
    osDistribution: z.string().trim().min(1).max(128).nullable().optional(),
    osVersion: z.string().trim().min(1).max(128).nullable().optional(),
    ip: z.string().max(100).optional(),
    business: text.nullable().optional(),
    owner: text.optional(),
    tags: z.array(text).max(30).optional(),
    importance: z.enum(["LOW", "NORMAL", "HIGH", "CRITICAL"]).optional(),
  })
  .strict();
export const pageInput = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  q: z.string().max(200).optional(),
  status: z.string().max(40).optional(),
  kind: z.string().max(40).optional(),
  severity: severity.optional(),
  assetId: z.string().uuid().optional(),
  resourceId: z.string().uuid().optional(),
  business:z.string().max(200).optional(),
  owner:z.string().max(254).optional(),
  sortBy:z.enum(["createdAt","updatedAt","title","name","hostname","severity"]).default("createdAt"),
  order:z.enum(["asc","desc"]).default("desc"),
  createdFrom:z.string().datetime().optional(),createdTo:z.string().datetime().optional(),
});
