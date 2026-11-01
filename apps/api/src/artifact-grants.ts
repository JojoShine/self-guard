import {createPublicKey,verify} from 'node:crypto';import {z} from 'zod';
const grantInput=z.object({payload:z.string().min(1).max(24000),signature:z.string().max(100)}).strict();
const bodyInput=z.object({id:z.string().min(1).max(200),assetId:z.string().min(1).max(200),template:z.literal('DOWNLOAD_AGENT_RELEASE'),parameters:z.object({releaseId:z.string().min(1).max(200),sha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict(),expiresAt:z.string().datetime()}).strict();
export function verifyDownloadGrant(input:unknown,expected:{id:string;assetId:string;releaseId:string;sha256:string},publicKey:string,now=new Date()){
 try{const envelope=grantInput.parse(input),raw=Buffer.from(envelope.payload,'base64'),signature=Buffer.from(envelope.signature,'base64'),key=Buffer.from(publicKey,'base64');
  if(raw.toString('base64')!==envelope.payload||signature.length!==64||signature.toString('base64')!==envelope.signature||key.length!==32||key.toString('base64')!==publicKey)return false;
  const publicObject=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key])});if(!verify(null,raw,publicObject,signature))return false;
  const body=bodyInput.parse(JSON.parse(raw.toString('utf8'))),expiry=Date.parse(body.expiresAt);return expiry>now.getTime()&&expiry<=now.getTime()+5*60000&&body.id===expected.id&&body.assetId===expected.assetId&&body.parameters.releaseId===expected.releaseId&&body.parameters.sha256===expected.sha256;
 }catch{return false;}
}
