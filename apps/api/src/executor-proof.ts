import {createPublicKey,verify} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';

const envelopeInput=z.object({payload:z.string(),signature:z.string()}).strict();
const payloadInput=z.object({
  taskId:z.string(),
  assetId:z.string(),
  result:z.object({success:z.boolean(),evidence:z.string(),details:z.record(z.string(),z.unknown())}).strict(),
}).strict();
const spkiPrefix=Buffer.from('302a300506032b6570032100','hex');
function decode(value:string,maxBytes:number) {
  if(value.length>4*Math.ceil(maxBytes/3))throw new Error('oversized');
  const bytes=Buffer.from(value,'base64');
  if(!bytes.length||bytes.length>maxBytes||bytes.toString('base64')!==value)throw new Error('invalid base64');
  return bytes;
}

export function verifyExecutorResult(
  publicKeyRawBase64:string,
  taskId:string,
  assetId:string,
  result:{success:boolean;evidence:string;details?:Record<string,unknown>},
):boolean {
  try {
    const proof=result.details?.executorProof;
    if(typeof proof!=='string'||proof.length>90000)return false;
    const envelope=envelopeInput.parse(JSON.parse(proof));
    const publicBytes=decode(publicKeyRawBase64,32);
    const signature=decode(envelope.signature,64);
    const bytes=decode(envelope.payload,65536);
    if(publicBytes.length!==32||signature.length!==64)return false;
    const key=createPublicKey({key:Buffer.concat([spkiPrefix,publicBytes]),format:'der',type:'spki'});
    if(!verify(null,bytes,key,signature))return false;
    const json=bytes.toString('utf8');
    if(!Buffer.from(json,'utf8').equals(bytes))return false;
    const payload=payloadInput.parse(JSON.parse(json));
    const {executorProof,...details}=result.details||{};
    return payload.taskId===taskId&&payload.assetId===assetId&&isDeepStrictEqual(payload.result,{success:result.success,evidence:result.evidence,details});
  }catch{
    return false;
  }
}
