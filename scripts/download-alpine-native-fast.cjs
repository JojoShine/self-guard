// Download only the frozen owned Alpine fixture, preserving the existing prefix.
const fs=require('node:fs'),fsp=require('node:fs/promises'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{spawn}=require('node:child_process'),{pipeline}=require('node:stream/promises');
const root=process.cwd(),id=process.argv[2]||'alpine-3.23-arm64';assert.ok(['alpine-3.23-arm64','alpine-3.23-amd64'].includes(id));
const entry=JSON.parse(fs.readFileSync('docs/implementation/Linux验收镜像.json')).entries.find(row=>row.id===id),architecture=id.endsWith('amd64')?'x86_64':'aarch64';
assert.equal(entry.url,'https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/cloud/nocloud_alpine-3.23.4-'+architecture+'-uefi-cloudinit-r0.qcow2');assert.match(entry.digest,/^sha512:[a-f0-9]{128}$/);
const total=id.endsWith('amd64')?200671232:235077632,chunk=8<<20,file=path.join(root,'.artifacts/tools',entry.filename),directory=fs.mkdtempSync(path.join(root,'.artifacts/native-agent/alpine-parts-'));fs.chmodSync(directory,0o700);
async function hash(file){const h=crypto.createHash('sha512');for await(const bytes of fs.createReadStream(file))h.update(bytes);return h.digest('hex')}
async function main(){
 const initial=fs.existsSync(file)?fs.statSync(file):null;if(initial?.size===total&&await hash(file)===entry.digest.slice(7)){console.log('Frozen Alpine image already verified');return}
 const prefix=Math.floor(Math.min(initial?.size||0,total)/chunk)*chunk,parts=[];for(let start=prefix;start<total;start+=chunk)parts.push({start,end:Math.min(total-1,start+chunk-1)});
 let index=0;await Promise.all(Array.from({length:6},async()=>{for(;;){const part=parts[index++];if(!part)return;const name=String(part.start),output=path.join(directory,name+'.part'),headers=path.join(directory,name+'.headers');
  const child=spawn('curl',['--fail','--silent','--show-error','--connect-timeout','15','--max-time','240','--retry','2','--max-filesize',String(part.end-part.start+1),'--range',part.start+'-'+part.end,'--dump-header',headers,'--output',output,entry.url],{stdio:['ignore','ignore','pipe']});let diagnostic='';child.stderr.on('data',bytes=>{if(diagnostic.length<2000)diagnostic+=bytes});const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve)});assert.equal(code,0,'Frozen range transfer failed: '+diagnostic);
  const ranges=[...fs.readFileSync(headers,'utf8').matchAll(/^content-range:\s*bytes\s+(\d+)-(\d+)\/(\d+)\s*$/gim)];assert.ok(ranges.length);const actual=ranges.at(-1);assert.deepEqual(actual.slice(1).map(Number),[part.start,part.end,total]);assert.equal(fs.statSync(output).size,part.end-part.start+1);console.log('Verified range '+part.start+'..'+part.end);
 }}));
 const candidate=path.join(directory,'candidate.img');await fsp.writeFile(candidate,Buffer.alloc(0),{flag:'wx',mode:0o600});if(prefix)await pipeline(fs.createReadStream(file,{end:prefix-1}),fs.createWriteStream(candidate,{flags:'a'}));
 for(const part of parts)await pipeline(fs.createReadStream(path.join(directory,String(part.start)+'.part')),fs.createWriteStream(candidate,{flags:'a'}));
 assert.equal(fs.statSync(candidate).size,total);assert.equal(await hash(candidate),entry.digest.slice(7),'Official frozen image checksum mismatch');
 if(initial){const current=fs.statSync(file);assert.equal(current.ino,initial.ino);assert.equal(current.size,initial.size);assert.equal(current.mtimeMs,initial.mtimeMs,'Another download changed the original prefix')}else assert.ok(!fs.existsSync(file));
 const handle=await fsp.open(candidate,'r');await handle.sync();await handle.close();await fsp.rename(candidate,file);console.log('PASS complete frozen Alpine image SHA512; preserved prefix '+prefix+' bytes');
}
main().catch(error=>{console.error(error.message);console.error('Owned partial ranges retained at '+path.relative(root,directory));process.exitCode=1});
