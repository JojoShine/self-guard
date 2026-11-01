import {createPrivateKey,sign} from 'node:crypto';

type SignableTask = {
  id: string;
  assetId: string;
  template: string;
  parameters: unknown;
  expiresAt: Date | string;
  windowEnd?: Date | string | null;
};

export function authorizeTask(task: SignableTask): {payload:string;signature:string}|undefined {
  const encoded=process.env.TASK_SIGNING_PRIVATE_KEY;
  if(!encoded)return undefined;
  let key;
  try {
    const der=Buffer.from(encoded,'base64');
    if(der.toString('base64')!==encoded)throw new Error('invalid base64');
    key=createPrivateKey({key:der,format:'der',type:'pkcs8'});
    if(key.asymmetricKeyType!=='ed25519')throw new Error('invalid algorithm');
  }catch{
    throw new Error('任务签名密钥配置无效');
  }
  const expiresAt=new Date(Math.min(new Date(task.expiresAt).getTime(),task.windowEnd?new Date(task.windowEnd).getTime():Infinity,Date.now()+5*60000)).toISOString();
  const bytes=Buffer.from(JSON.stringify({id:task.id,assetId:task.assetId,template:task.template,parameters:task.parameters,expiresAt}),'utf8');
  return {payload:bytes.toString('base64'),signature:sign(null,bytes,key).toString('base64')};
}
