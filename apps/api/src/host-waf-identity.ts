import {UnauthorizedException,ForbiddenException} from '@nestjs/common';
import {bearer} from './auth';import {equalSecret,hashToken} from './security';
import {Db} from './db';
// Null denotes the existing centrally managed component; an array is an exact
// asset-node assignment. Host nodes never receive the global WAF credential.
export async function authorizeHostWaf(db:Db,req:any,siteIds:string[],nodeId?:string):Promise<string[]|null>{
 const token=bearer(req);if(equalSecret(token,process.env.WAF_TOKEN))return null;
 if(!token)throw new UnauthorizedException('WAF 节点身份无效');
 const credential=await db.setting.findUnique({where:{key:'host-waf-credential:'+hashToken(token)}}),assetId=(credential?.value as any)?.assetId;
 if(typeof assetId!=='string')throw new UnauthorizedException('WAF 节点身份无效');
 const asset=await db.asset.findUnique({where:{id:assetId},select:{id:true,tokenHash:true,archivedAt:true}});
 if(!asset||asset.archivedAt||!asset.tokenHash||(credential!.value as any).assetTokenHash!==asset.tokenHash)throw new UnauthorizedException('所属资产身份已撤销');
 if(nodeId!==undefined&&nodeId!=='host-'+asset.id)throw new ForbiddenException('节点编号与资产不一致');
 const bindings=await db.setting.findMany({where:{key:{startsWith:'host-waf-site:'},value:{path:['assetId'],equals:asset.id}}});
 const allowed=bindings.filter(row=>(row.value as any)?.assetId===asset.id).map(row=>row.key.slice('host-waf-site:'.length));
 if(siteIds.some(id=>id!==''&&!allowed.includes(id)))throw new ForbiddenException('只能操作分配给此资产的站点');
 req.hostWafNode='host-'+asset.id;
 return allowed;
}
