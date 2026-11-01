import {Controller,Get,Inject,ServiceUnavailableException} from '@nestjs/common';
import {readdirSync,readFileSync} from 'node:fs';import {join} from 'node:path';import {createHash} from 'node:crypto';import {Db} from './db';import {basePath} from './platform-path';
export async function migrationReady(db:Pick<Db,'$queryRawUnsafe'>){
 const directory=join(process.cwd(),'prisma/migrations');
 const expected=readdirSync(directory,{withFileTypes:true}).filter(entry=>entry.isDirectory()).map(entry=>({name:entry.name,checksum:createHash('sha256').update(readFileSync(join(directory,entry.name,'migration.sql'))).digest('hex')}));
 const rows=await db.$queryRawUnsafe<Array<{migration_name:string;checksum:string;finished_at:Date|null;rolled_back_at:Date|null}>>('SELECT migration_name,checksum,finished_at,rolled_back_at FROM "_prisma_migrations"');
 if(rows.some(row=>!row.finished_at&&!row.rolled_back_at)||expected.some(item=>!rows.some(row=>row.migration_name===item.name&&row.finished_at&&!row.rolled_back_at&&row.checksum===item.checksum)))throw Error('Database migrations not ready');
}
@Controller(basePath(process.env.BASE_PATH||'').slice(1))
export class DeploymentHealthController{
 constructor(@Inject(Db)private db:Db){}
 @Get('healthz')async ready(){try{await migrationReady(this.db);return {ready:true}}catch{throw new ServiceUnavailableException('Database or migrations not ready')}}
 @Get('livez')live(){return {alive:true}}
}
