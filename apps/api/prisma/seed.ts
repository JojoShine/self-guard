import { PrismaClient } from "@prisma/client";
import { hashPassword } from "../src/security";
const db = new PrismaClient();
async function main() {
  const email = process.env.ADMIN_EMAIL || "admin@selfguard.local",
    password = process.env.ADMIN_PASSWORD;
  if (!password || password.length < 16)
    throw new Error("ADMIN_PASSWORD must have at least 16 characters");
  await db.user.upsert({
    where: { email },
    update: {},
    create: {
      email,
      name: "平台管理员",
      role: "ADMIN",
      passwordHash: hashPassword(password),
    },
  });
  console.log(
    "Bootstrap administrator checked; no demo security records inserted.",
  );
}
main().finally(() => db.$disconnect());
