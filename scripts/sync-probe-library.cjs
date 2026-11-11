#!/usr/bin/env node
// Refresh the official download artifact and pinned policy; catalog publication remains an explicit admin action.
const {resolve,join}=require('node:path');
const root=resolve(__dirname,'..');
const exists=require('node:fs').existsSync,apiRoot=exists(join(root,'apps/api/package.json'))?join(root,'apps/api'):root;
const compiled=exists(join(apiRoot,'dist/intelligence-proxy.js'));
if(!compiled){process.env.TSX_TSCONFIG_PATH=join(apiRoot,'tsconfig.json');require(require.resolve('tsx/cjs',{paths:[apiRoot]}))}
const {sourceProxyAgent}=require(join(apiRoot,compiled?'dist/intelligence-proxy.js':'src/intelligence-proxy.ts'));
const {publicAddress}=require(join(apiRoot,compiled?'dist/advisories.js':'src/advisories.ts'));
const {request}=require('node:https'),{lookup}=require('node:dns');
const {mkdir,writeFile,rename,rm,open}=require('node:fs/promises');
const {createHash}=require('node:crypto');
const allowed=new Set(['api.github.com','github.com','codeload.github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','raw.githubusercontent.com']);
async function response(url,redirects=0){
 const target=new URL(url);if(target.protocol!=='https:'||!allowed.has(target.hostname)||target.username||target.password||target.port||redirects>5)throw Error('Official HTTPS source or redirect rejected');
 const agent=sourceProxyAgent(target);
 return new Promise((resolve,reject)=>{const req=request(target,{agent,rejectUnauthorized:true,maxHeaderSize:16384,headers:{'user-agent':'SelfGuard-Rule-Library/1.0','accept-encoding':'identity'},lookup:(name,options,cb)=>lookup(name,{all:true,verbatim:true},(error,addresses)=>{if(error)return cb(error);if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))return cb(Error('Official DNS returned a non-public address'));options?.all?cb(null,addresses):cb(null,addresses[0].address,addresses[0].family)})},res=>{const deadline=setTimeout(()=>res.destroy(Error('Official download exceeded 10 minutes')),600000);deadline.unref();res.once('close',()=>{clearTimeout(deadline);if(agent)agent.destroy()});if([301,302,303,307,308].includes(res.statusCode)){res.resume();if(!res.headers.location)return reject(Error('Official redirect missing'));response(new URL(res.headers.location,target),redirects+1).then(resolve,reject)}else if(res.statusCode!==200){res.resume();reject(Error('Official source HTTP '+res.statusCode))}else if(res.headers['content-encoding']&&res.headers['content-encoding']!=='identity'){res.resume();reject(Error('Unexpected source encoding'))}else resolve(res)});req.setTimeout(30000,()=>req.destroy(Error('Official source timed out')));req.once('error',reject);req.end()});
}
async function small(url,budget=1024*1024){const res=await response(url),parts=[];let count=0;for await(const part of res){count+=part.length;if(count>budget){res.destroy();throw Error('Metadata budget exceeded')}parts.push(part)}return Buffer.concat(parts)}
async function main(){
 const releaseBytes=await small('https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest'),release=JSON.parse(releaseBytes.toString()),version=release.tag_name;
 if(!/^v\d+\.\d+\.\d+$/.test(version)||release.draft||release.prerelease)throw Error('Official stable release identity invalid');
 const checksum=release.assets.find(a=>a.name===`nuclei-templates-${version.slice(1)}_checksums.txt`);if(!checksum||checksum.browser_download_url!==`https://github.com/projectdiscovery/nuclei-templates/releases/download/${version}/nuclei-templates-${version.slice(1)}_checksums.txt`)throw Error('Official release checksum asset unavailable');
 const checksums=await small(checksum.browser_download_url,65536),filename=`nuclei-templates-${version.slice(1)}.zip`,line=checksums.toString().split(/\r?\n/).find(v=>v.trim().endsWith(filename)),sha256=line?.match(/^([a-f0-9]{64})\s+/)?.[1];if(!sha256)throw Error('Official ZIP checksum unavailable');
 const directory=resolve(process.env.PROBE_RULE_DOWNLOAD_DIR||join(root,'.artifacts/downloads/nuclei'));await mkdir(directory,{recursive:true});const archive=join(directory,filename),pending=archive+'.pending-'+process.pid,sourceUrl=`https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${version}.zip`;
 const handle=await open(pending,'wx',0o600),digest=createHash('sha256');let count=0;try{const stream=await response(sourceUrl);for await(const part of stream){count+=part.length;if(count>512*1024*1024){stream.destroy();throw Error('Official archive exceeds512MiB')}digest.update(part);await handle.writeFile(part)}if(digest.digest('hex')!==sha256)throw Error('Official release archive checksum mismatch');await handle.close();await rename(pending,archive)}finally{await handle.close().catch(()=>{});await rm(pending,{force:true})}
 const licenseBytes=await small(`https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/${version}/LICENSE.md`,65536),licenseSha256=createHash('sha256').update(licenseBytes).digest('hex');if(licenseSha256!=='5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c')throw Error('Official license changed; review policy before publication');
 const source={version,sha256,sourceUrl,repository:'https://github.com/projectdiscovery/nuclei-templates',license:'MIT',licenseSha256},policy=resolve(process.env.PROBE_RULE_LIBRARY_SOURCE||join(root,'.artifacts/probe-rule-library-source.json'));await mkdir(resolve(policy,'..'),{recursive:true});const candidate=policy+'.pending-'+process.pid;await writeFile(candidate,JSON.stringify(source,null,2)+'\n',{mode:0o600});await rename(candidate,policy);await writeFile(join(directory,'templates-release.json'),releaseBytes);await writeFile(join(directory,'templates-checksums.txt'),checksums);await writeFile(join(directory,'LICENSE.md'),licenseBytes);
 console.log(JSON.stringify({version,sha256,archive,sourcePolicy:policy,meaning:'Downloaded and checksum verified. Use administrator rule-library sync to validate the complete archive and publish its catalog. No rule was enabled.'}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
