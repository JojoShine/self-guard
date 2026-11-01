const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
async function main(){const task=process.argv[2];if(task==='healthcheck'){const prefix=process.env.BASE_PATH||'';const r=await fetch('http://127.0.0.1:'+(process.env.PORT||8080)+prefix+'/healthz',{signal:AbortSignal.timeout(4000)});if(!r.ok||(await r.json()).ready!==true)throw Error('Application not ready');return;}
const {PrismaClient}=require('@prisma/client'),db=new PrismaClient();try{
 if(task==='migrate'){
  const result=spawnSync(process.execPath,[path.join(__dirname,'../node_modules/prisma/build/index.js'),'migrate','deploy'],{stdio:'inherit'});if(result.status!==0)throw Error('Migration failed');
  await db.$executeRawUnsafe('REVOKE ALL ON TABLE "_prisma_migrations" FROM selfguard_runtime');await db.$executeRawUnsafe('GRANT SELECT ON TABLE "_prisma_migrations" TO selfguard_runtime');return;
 }
 if(task==='bootstrap'){
  const email=process.env.ADMIN_EMAIL,password=process.env.ADMIN_PASSWORD;if(!email||!password||password.length<16)throw Error('Bootstrap credentials required');
  const {hashPassword}=require('../dist/security');await db.user.upsert({where:{email:email.toLowerCase()},update:{},create:{email:email.toLowerCase(),name:'平台管理员',role:'ADMIN',passwordHash:hashPassword(password)}});console.log('Bootstrap checked; existing accounts and data preserved');return;
 }
 throw Error('Unknown deployment task');
}finally{await db.$disconnect()}}
main().catch(error=>{console.error(error.message);process.exitCode=1});
