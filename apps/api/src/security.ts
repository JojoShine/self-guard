import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createHash,
} from "node:crypto";
export const hashToken = (s: string) =>
  createHash("sha256").update(s).digest("hex");
export const newToken = () => randomBytes(32).toString("base64url");
export function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  return salt + ":" + scryptSync(password, salt, 64).toString("hex");
}
export function checkPassword(password: string, hash: string) {
  const [salt, key] = hash.split(":");
  if (!salt || !key) return false;
  const a = Buffer.from(key, "hex"),
    b = scryptSync(password, salt, 64);
  return a.length === b.length && timingSafeEqual(a, b);
}
export function equalSecret(a: string | undefined, b: string | undefined) {
  if (!a || !b) return false;
  return timingSafeEqual(Buffer.from(hashToken(a)), Buffer.from(hashToken(b)));
}
