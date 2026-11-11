import {createCipheriv,createDecipheriv,createHash,hkdfSync,randomBytes,randomUUID} from 'node:crypto';
import {constants} from 'node:fs';
import {mkdir,lstat,open,link,unlink,readdir,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {z} from 'zod';
import {EvidenceBinding,assertEvidenceLive} from './access-contract';

function bindingBytes(v:EvidenceBinding){return Buffer.from(JSON.stringify([v.sourceId,v.eventId,v.direction,v.sequence,v.capturedAt,v.sha256]));}
const objectPattern=/^[a-f0-9]{64}\.evidence$/;
const temporaryPattern=/^[a-f0-9-]{36}\.pending$/;
const budgetInput=z.object({version:z.literal(1),bytes:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),put:z.object({object:z.string().regex(objectPattern),temporary:z.string().regex(temporaryPattern),bytes:z.number().int().min(32).max(262176)}).strict().optional(),remove:z.array(z.object({object:z.string().regex(/^(?:[a-f0-9]{64}\.evidence|[a-f0-9-]{36}\.pending)$/),bytes:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)}).strict()).max(500).optional()}).strict().refine(v=>!(v.put&&v.remove));
type Budget=z.infer<typeof budgetInput>;
export class EvidenceQuotaError extends Error{constructor(){super('密文证据及未完成预留已达配额');}}
async function scanEvidenceBytes(root:string){let total=0,files:string[];try{files=await readdir(root)}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return 0;throw e;}for(const name of files){if(!objectPattern.test(name)&&!temporaryPattern.test(name))continue;const stat=await lstat(join(root,name));if(!stat.isFile()||stat.isSymbolicLink())throw new Error('证据目录存在无效对象');total+=stat.size;}if(!Number.isSafeInteger(total))throw new Error('证据计数超出范围');return total;}
async function readBudget(root:string):Promise<Budget>{let f;try{f=await open(join(root,'.usage.json'),constants.O_RDONLY|constants.O_NOFOLLOW);}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return{version:1,bytes:await scanEvidenceBytes(root)};throw e;}try{const stat=await f.stat();if(!stat.isFile()||stat.size>131072||(stat.mode&0o077))throw new Error('证据配额记录无效');return budgetInput.parse(JSON.parse(await f.readFile('utf8')));}finally{await f.close();}}
export async function accessEvidenceUsage(root:string){return{bytes:(await readBudget(root)).bytes};}

export class AccessEvidenceStore{
 constructor(private root:string,private keyHex:string,private previousKeys:string[]=[]){if(![keyHex,...previousKeys].every(key=>/^[a-f0-9]{64}$/i.test(key)))throw new Error('访问证据需要配置32字节加密密钥');}
 private key(sourceId:string,keyHex=this.keyHex){return Buffer.from(hkdfSync('sha256',Buffer.from(keyHex,'hex'),Buffer.from(sourceId),'selfguard-access-evidence-v1',32));}
 private path(object:string){if(!/^[a-f0-9]{64}\.evidence$/.test(object))throw new Error('证据对象标识无效');return join(this.root,object);}
 private async ensureRoot(){await mkdir(this.root,{recursive:true,mode:0o700});const dir=await lstat(this.root);if(!dir.isDirectory()||dir.isSymbolicLink()||(dir.mode&0o077))throw new Error('证据目录必须私有且不能是符号链接');}
 private async budgetWrite(value:Budget){const name=join(this.root,'.usage-'+randomUUID()+'.pending'),f=await open(name,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);try{await f.writeFile(JSON.stringify(value));await f.sync();}finally{await f.close();}try{await rename(name,join(this.root,'.usage.json'));const d=await open(this.root,constants.O_RDONLY);try{await d.sync();}finally{await d.close();}}finally{await unlink(name).catch(e=>{if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e});}}
 private async budgetRecover(){await this.ensureRoot();const value=await readBudget(this.root);if(value.put){let exists=false;try{const file=await lstat(this.path(value.put.object));if(!file.isFile()||file.isSymbolicLink()||file.size!==value.put.bytes)throw new Error('未完成证据对象无效');exists=true;}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}await unlink(join(this.root,value.put.temporary)).catch(e=>{if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e});if(!exists)value.bytes=Math.max(0,value.bytes-value.put.bytes);delete value.put;await this.budgetWrite(value);}if(value.remove){for(const file of value.remove){try{await lstat(join(this.root,file.object));}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;value.bytes=Math.max(0,value.bytes-file.bytes);}}delete value.remove;await this.budgetWrite(value);}return value;}
 // All mutations share the database evidence-admission lock across API replicas.
 async removeMany(objects:string[]){if(objects.length>500)throw new Error('证据清理批次过大');const value=await this.budgetRecover(),files:{object:string;bytes:number}[]=[];for(const object of objects){if(!objectPattern.test(object)&&!temporaryPattern.test(object))throw new Error('证据对象标识无效');try{const info=await lstat(join(this.root,object));if(!info.isFile()||info.isSymbolicLink())throw new Error('证据对象无效');files.push({object,bytes:info.size});}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}}if(!files.length)return;value.remove=files;await this.budgetWrite(value);for(const file of files)await unlink(join(this.root,file.object)).catch(e=>{if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e});value.bytes=Math.max(0,value.bytes-files.reduce((n,f)=>n+f.bytes,0));delete value.remove;await this.budgetWrite(value);}
 async put(binding:EvidenceBinding,bytes:Buffer,maximumBytes=Number.MAX_SAFE_INTEGER){
  assertEvidenceLive(new Date(binding.capturedAt));
  if(bytes.length>262144||createHash('sha256').update(bytes).digest('hex')!==binding.sha256)throw new Error('证据分段校验失败');
  const budget=await this.budgetRecover();
  const aad=bindingBytes(binding),object=createHash('sha256').update(aad).digest('hex')+'.evidence',iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key(binding.sourceId),iv);cipher.setAAD(aad);
  const encrypted=Buffer.concat([Buffer.from('SGE1'),iv,cipher.update(bytes),cipher.final(),cipher.getAuthTag()]);
  try{const existing=await this.read(binding,object);if(!existing.equals(bytes))throw new Error('证据对象冲突');return object;}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  if(!Number.isSafeInteger(maximumBytes)||maximumBytes<1||budget.bytes+encrypted.length>maximumBytes)throw new EvidenceQuotaError();
  const temporaryName=randomUUID()+'.pending';budget.bytes+=encrypted.length;budget.put={object,temporary:temporaryName,bytes:encrypted.length};await this.budgetWrite(budget);
  const temporary=join(this.root,temporaryName);const f=await open(temporary,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(encrypted);await f.sync();}finally{await f.close();}
  try{try{await link(temporary,this.path(object));}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;const old=await this.read(binding,object);if(!old.equals(bytes))throw new Error('证据对象冲突');}
   const directory=await open(this.root,constants.O_RDONLY);try{await directory.sync();}finally{await directory.close();}
  }finally{await unlink(temporary);}
  delete budget.put;await this.budgetWrite(budget);return object;
 }
 async read(binding:EvidenceBinding,object:string){
  assertEvidenceLive(new Date(binding.capturedAt));const filename=this.path(object),f=await open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  let encrypted:Buffer;try{const info=await f.stat();if(!info.isFile()||info.size>262188)throw new Error('证据对象无效');encrypted=await f.readFile();}finally{await f.close();}
  if(encrypted.length<32||encrypted.subarray(0,4).toString()!=='SGE1')throw new Error('证据封装无效');
  let bytes:Buffer|undefined;for(const key of [this.keyHex,...this.previousKeys]){try{const decipher=createDecipheriv('aes-256-gcm',this.key(binding.sourceId,key),encrypted.subarray(4,16));decipher.setAAD(bindingBytes(binding));decipher.setAuthTag(encrypted.subarray(-16));bytes=Buffer.concat([decipher.update(encrypted.subarray(16,-16)),decipher.final()]);break;}catch{ /* A configured prior key may own this immutable object. All failures still fail closed. */ }}
  if(!bytes)throw new Error('证据认证校验失败或密钥不可用');
  if(createHash('sha256').update(bytes).digest('hex')!==binding.sha256)throw new Error('证据校验失败');return bytes;
 }
 async remove(object:string){await this.removeMany([object]);}
 async cleanupOrphans(known:Set<string>,before:Date){let files:string[];try{files=await readdir(this.root);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return 0;throw error;}const candidates:string[]=[];const deadline=Date.now()+5000;for(const file of files){if(Date.now()>deadline||candidates.length>=500)break;if(/^\.usage-[a-f0-9-]{36}\.pending$/.test(file)){const stat=await lstat(join(this.root,file));if(stat.isFile()&&stat.mtime<before)await unlink(join(this.root,file));continue;}if((!objectPattern.test(file)&&!temporaryPattern.test(file))||known.has(file))continue;const stat=await lstat(join(this.root,file));if(!stat.isFile()||stat.isSymbolicLink()||stat.mtime>=before)continue;candidates.push(file);}await this.removeMany(candidates);return candidates.length;}
}
