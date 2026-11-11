import {BadRequestException,ForbiddenException,GoneException} from '@nestjs/common';
import {seal,unseal} from './maintenance';
import type {SecurityUser} from './database-contract';
import type {Prisma} from '@prisma/client';

export const SQL_RETENTION_DAYS=7;
export function sqlExpiresAt(at:Date){return new Date(at.getTime()+SQL_RETENTION_DAYS*86400000);}
export function canReadDatabaseSql(user:SecurityUser){return user.role==='ADMIN'||(user.dataScope?.canReadEvidence!==false&&user.dataScope?.canReadSqlEvidence===true);}
export function assertDatabaseSql(user:SecurityUser){if(!canReadDatabaseSql(user))throw new ForbiddenException('没有查看SQL原文的独立权限');}
export function sealDatabaseSql(auditId:string,sql:string){return seal(JSON.stringify({auditId,sql}));}
export function openDatabaseSql(auditId:string,ciphertext:string){const value:unknown=JSON.parse(unseal(ciphertext));if(!value||typeof value!=='object'||!('auditId' in value)||value.auditId!==auditId||!('sql' in value)||typeof value.sql!=='string')throw new BadRequestException('SQL证据绑定无效');return value.sql;}
export function assertSqlLive(expiresAt:Date,now=new Date()){if(expiresAt<=now)throw new GoneException('SQL原文已到期，审计元数据仍可查询');}
export async function cleanupDatabaseSql(tx:Pick<Prisma.TransactionClient,'databaseSqlEvidence'>,now=new Date()){return tx.databaseSqlEvidence.deleteMany({where:{expiresAt:{lte:now}}});}
