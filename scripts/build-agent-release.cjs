const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
function run(command,args,options={}){const result=spawnSync(command,args,{cwd:root,stdio:'inherit',...options});if(result.status!==0)throw Error(command+' failed');return result;}
function sourceDigest(){const hash=crypto.createHash('sha256');for(const name of fs.readdirSync(path.join(root,'services/agent')).filter(n=>n.endsWith('.go')||n==='go.mod').sort()){hash.update(name+'\0');hash.update(fs.readFileSync(path.join(root,'services/agent',name)));}return hash.digest('hex');}
function releaseKey(){
 const envFile=path.join(root,'.env'),text=fs.readFileSync(envFile,'utf8'),matches=[...text.matchAll(/^AGENT_UPGRADE_PUBLIC_KEY=(.*)$/gm)].map(m=>m[1].trim()).filter(Boolean);if(new Set(matches).size>1)throw Error('Conflicting release trust roots');
 const keyFile=process.env.AGENT_RELEASE_KEY_FILE||path.join(root,'.artifacts/signing/agent-release.pk8');fs.mkdirSync(path.dirname(keyFile),{recursive:true,mode:0o700});
 let key;if(fs.existsSync(keyFile)){const stat=fs.lstatSync(keyFile);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077))throw Error('Release key must be a private regular file');key=crypto.createPrivateKey({key:fs.readFileSync(keyFile),format:'der',type:'pkcs8'});}else{if(matches[0])throw Error('Existing release root requires its matching private key; refusing rotation');key=crypto.generateKeyPairSync('ed25519').privateKey;fs.writeFileSync(keyFile,key.export({format:'der',type:'pkcs8'}),{mode:0o600,flag:'wx'});}
 if(key.asymmetricKeyType!=='ed25519')throw Error('Ed25519 release key required');const publicKey=crypto.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 if(matches[0]&&matches[0]!==publicKey)throw Error('Release key does not match configured root');
 if(!matches[0]){const updated=/^AGENT_UPGRADE_PUBLIC_KEY=.*$/m.test(text)?text.replace(/^AGENT_UPGRADE_PUBLIC_KEY=.*$/m,'AGENT_UPGRADE_PUBLIC_KEY='+publicKey):text.trimEnd()+'\nAGENT_UPGRADE_PUBLIC_KEY='+publicKey+'\n';const temporary=envFile+'.release-key.pending';fs.writeFileSync(temporary,updated,{mode:0o600,flag:'wx'});fs.renameSync(temporary,envFile);}
 return {key,publicKey};
}
function main(){const [version,sequenceText]=process.argv.slice(2),sequence=Number(sequenceText);if(!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)||!Number.isSafeInteger(sequence)||sequence<1||sequence>2147483647)throw Error('Usage: build-agent-release.cjs VERSION SEQUENCE');
 const {key,publicKey}=releaseKey(),digest=sourceDigest(),releaseDir=path.join(root,'.artifacts/releases',version);fs.mkdirSync(releaseDir,{recursive:true});
 for(const arch of ['amd64','arm64']){const directory=path.join(releaseDir,arch);if(fs.existsSync(directory))throw Error('Release output exists; immutable versions cannot be overwritten');fs.mkdirSync(directory);
  run('docker',['run','--rm','-v',root+':/workspace','-w','/workspace/services/agent','-e','GOCACHE=/workspace/.artifacts/go-cache','-e','GOOS=linux','-e','GOARCH='+arch,'-e','CGO_ENABLED=0','golang:1.27.3-alpine','go','build','-trimpath','-ldflags','-s -w -X main.agentVersion='+version,'-o','/workspace/.artifacts/releases/'+version+'/'+arch+'/selfguard-agent','.']);
  const file=path.join(directory,'selfguard-agent'),bytes=fs.readFileSync(file),manifest={version,sequence,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),size:bytes.length,os:'linux',architecture:arch,expiresAt:new Date(Date.now()+90*86400000).toISOString()},raw=Buffer.from(JSON.stringify(manifest)),signature=crypto.sign(null,raw,key);
  fs.writeFileSync(path.join(directory,'manifest.json'),raw);fs.writeFileSync(path.join(directory,'manifest.sig'),signature);
  const sbom={bomFormat:'CycloneDX',specVersion:'1.6',version:1,metadata:{component:{type:'application',name:'selfguard-agent',version}},components:[{type:'application',name:'selfguard-agent',version,hashes:[{alg:'SHA-256',content:manifest.sha256}]},{type:'library',name:'Go standard library',version:'1.27.3',purl:'pkg:golang/stdlib@1.27.3'}]};
  const envelope={manifestBytes:raw.toString('base64'),signature:signature.toString('base64'),sourceDigest:digest,license:'LicenseRef-SelfGuard-Internal',sbom,channel:'canary'};
  fs.writeFileSync(path.join(directory,'release.json'),JSON.stringify(envelope,null,2));fs.writeFileSync(path.join(directory,'sbom.json'),JSON.stringify(sbom,null,2));
  fs.writeFileSync(path.join(directory,'README.txt'),'本包只包含固定版本 Linux '+arch+' 制品。\n通过受信任管理页面取得 SHA-256 和发行公钥后验证，不把包内自带公钥作为信任依据。\n离线主机可使用 --install-offline 预置，再在联网后使用安装授权完成接入。未验收不算在线成功。\n');
  run('tar',['-czf',path.join(releaseDir,'selfguard-agent-'+version+'-linux-'+arch+'.tar.gz'),'-C',directory,'selfguard-agent','manifest.json','manifest.sig','release.json','sbom.json','README.txt']);
  console.log('Built signed Linux '+arch+' release; digest '+manifest.sha256);
 }
 fs.writeFileSync(path.join(releaseDir,'trust-root.txt'),publicKey+'\n');console.log('Release artifacts saved at '+releaseDir+'. Private signing key stays outside the distribution.');
}
if(require.main===module){try{main();}catch(e){console.error(e.message);process.exitCode=1;}}
module.exports={sourceDigest,releaseKey};
