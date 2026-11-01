import {Db} from '../src/db';import {seal,unseal} from '../src/maintenance';
export async function rotateSecrets(db:Db,dryRun=true){
 if(!process.env.DATA_ENCRYPTION_PREVIOUS_KEY)throw new Error('需要先配置新主密钥和旧密钥过渡窗口');
 return db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-secret-rotation'))::text`;
 const configs=await tx.setting.findMany({where:{key:{startsWith:'webhook:'}}}),certificates=await tx.siteCertificate.findMany();
 for(const c of configs){const value={...(c.value as any)};for(const field of ['endpoint','secret'])if(value[field])value[field]=seal(unseal(value[field]));if(!dryRun)await tx.setting.update({where:{key:c.key},data:{value}})}
 for(const c of certificates){const keyCiphertext=seal(unseal(c.keyCiphertext));if(!dryRun)await tx.siteCertificate.update({where:{id:c.id},data:{keyCiphertext}})}
 if(!dryRun)await tx.audit.create({data:{actor:'operator:key-rotation',action:'ROTATE_ENCRYPTION',resource:'settings',detail:{webhooks:configs.length,certificates:certificates.length}}});return {dryRun,webhooks:configs.length,certificates:certificates.length};
 },{timeout:30000});
}
if(require.main===module){const db=new Db();rotateSecrets(db,!process.argv.includes('--apply')).then(r=>console.log(JSON.stringify(r))).catch(()=>{console.error('轮换验证失败，未修改事务中的任何密文；请核对过渡密钥并保留备份');process.exitCode=1}).finally(()=>db.$disconnect());}
