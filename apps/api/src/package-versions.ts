import {comparePythonVersions,compareMavenVersions} from './application-versions';
import {compareDebianVersions,type OsvRangeEvent} from './versions';
type Order=-1|0|1;
export type PackageScheme='DEBIAN'|'RPM'|'APK'|'SEMVER'|'GO'|'PEP440'|'MAVEN';
function lexical(a:string,b:string):Order{return a===b?0:a<b?-1:1}
function integer(a:string,b:string):Order{a=a.replace(/^0+/,'')||'0';b=b.replace(/^0+/,'')||'0';return a.length===b.length?lexical(a,b):a.length<b.length?-1:1}
function bounded(value:string){if(typeof value!=='string'||!value.length||value.length>4096)throw Error('无效或过长的软件版本')}
// SemVer 2.0.0 precedence; ecosystem-specific prefixes are handled before parsing.
function semantic(value:string){bounded(value);const m=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(value);if(!m)throw Error('版本不符合 SemVer 2.0');const pre=m[4]?.split('.')||[];if(pre.some(v=>/^\d+$/.test(v)&&v.length>1&&v[0]==='0'))throw Error('预发行数字不能包含前导零');return {core:m.slice(1,4),pre}}
function compareSemantic(a:string,b:string):Order{const left=semantic(a),right=semantic(b);for(let i=0;i<3;i++){const c=integer(left.core[i],right.core[i]);if(c)return c}if(!left.pre.length||!right.pre.length)return left.pre.length? -1:right.pre.length?1:0;for(let i=0;i<Math.max(left.pre.length,right.pre.length);i++){if(i>=left.pre.length)return -1;if(i>=right.pre.length)return 1;const x=left.pre[i],y=right.pre[i],xn=/^\d+$/.test(x),yn=/^\d+$/.test(y),c=xn&&yn?integer(x,y):xn!==yn?xn?-1:1:lexical(x,y);if(c)return c}return 0}
function rpm(value:string){bounded(value);const m=/^(?:(\d+):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?$/.exec(value);if(!m)throw Error('版本不符合 RPM EVR');return {epoch:m[1]||'0',version:m[2],release:m[3]||''}}
function compareRpmPart(a:string,b:string):Order{
 const segments=(v:string)=>v.match(/~|\^|\d+|[A-Za-z]+/g)||[],left=segments(a),right=segments(b);let i=0,j=0;
 while(i<left.length||j<right.length){const x=left[i],y=right[j];if(x==='~'||y==='~'){if(x!==y)return x==='~'?-1:1;i++;j++;continue}if(x==='^'||y==='^'){if(x!==y)return x==='^'?(y===undefined?1:-1):(x===undefined?-1:1);i++;j++;continue}if(x===undefined||y===undefined)return x===undefined?-1:1;const xn=/^\d+$/.test(x),yn=/^\d+$/.test(y),c=xn&&yn?integer(x,y):xn!==yn?xn?1:-1:lexical(x,y);if(c)return c;i++;j++}return 0;
}
type ApkTerm={type:number;value:string;weight?:number};
function apk(value:string):ApkTerm[]{
 bounded(value);const m=/^\d+(?:\.\d+)*/.exec(value);if(!m)throw Error('版本不符合 APK 格式');
 // Parse the numeric base separately from optional letter/suffix/hash/revision.
 const base=/^\d+(?:\.\d+)*/.exec(value)![0],terms:ApkTerm[]=base.split('.').map((v,i)=>({type:i===0?0:1,value:v}));let rest=value.slice(base.length);
 if(/^[a-z]/.test(rest)){terms.push({type:2,value:rest[0]});rest=rest.slice(1)}
 const weights:Record<string,number>={alpha:-4,beta:-3,pre:-2,rc:-1,cvs:1,svn:2,git:3,hg:4,p:5};
 while(rest.startsWith('_')){const suffix=/^_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)/.exec(rest);if(!suffix)throw Error('未知 APK 后缀');terms.push({type:3,value:suffix[1],weight:weights[suffix[1]]});if(suffix[2])terms.push({type:4,value:suffix[2]});rest=rest.slice(suffix[0].length)}
 if(rest.startsWith('~')){const hash=/^~([0-9a-fA-F]+)/.exec(rest);if(!hash)throw Error('无效 APK 提交标识');terms.push({type:5,value:hash[1]});rest=rest.slice(hash[0].length)}
 if(rest.startsWith('-r')){const revision=/^-r(\d+)/.exec(rest);if(!revision)throw Error('无效 APK 修订号');terms.push({type:6,value:revision[1]});rest=rest.slice(revision[0].length)}
 if(rest)throw Error('无效 APK 版本尾部');return terms;
}
function compareApk(a:string,b:string):Order{const left=apk(a),right=apk(b);for(let i=0;i<Math.max(left.length,right.length);i++){const x=left[i],y=right[i];if(x?.type!==y?.type){if(x?.type===3&&(x.weight??0)<0)return -1;if(y?.type===3&&(y.weight??0)<0)return 1;return (x?.type??7)<(y?.type??7)?1:-1}if(!x||!y)return 0;let c:Order;if(x.type===3)c=x.weight===y.weight?0:x.weight!<y.weight!?-1:1;else if(x.type===2||x.type===5||x.type===1&&(x.value.startsWith('0')||y.value.startsWith('0')))c=lexical(x.value,y.value);else c=integer(x.value,y.value);if(c)return c}return 0}
export function comparePackageVersions(scheme:PackageScheme,a:string,b:string):Order{
 if(scheme==='PEP440')return comparePythonVersions(a,b);if(scheme==='MAVEN')return compareMavenVersions(a,b);if(scheme==='DEBIAN')return compareDebianVersions(a,b);if(scheme==='SEMVER')return compareSemantic(a,b);if(scheme==='GO')return compareSemantic(a.replace(/^v/,''),b.replace(/^v/,''));if(scheme==='APK')return compareApk(a,b);if(scheme==='RPM'){const x=rpm(a),y=rpm(b);return integer(x.epoch,y.epoch)||compareRpmPart(x.version,y.version)||compareRpmPart(x.release,y.release)}throw Error('未识别的版本比较规则');
}
export function matchesVersionEvents(scheme:PackageScheme,version:string,events:readonly OsvRangeEvent[]):boolean{
 comparePackageVersions(scheme,version,version);if(!Array.isArray(events)||!events.length||events.length>1000)throw Error('无效 OSV 范围');
 const timeline:Array<{kind:string;version:string}>=[],limits:string[]=[];let introduced=false,fixed=false,last=false;
 for(const event of events){const keys=Object.keys(event||{});if(keys.length!==1||!['introduced','fixed','last_affected','limit'].includes(keys[0]))throw Error('无效 OSV 范围事件');const kind=keys[0],value=(event as any)[kind];if(typeof value!=='string')throw Error('版本边界缺失');if(!(kind==='introduced'&&value==='0')&&!(kind==='limit'&&value==='*'))comparePackageVersions(scheme,value,value);if(kind==='limit')limits.push(value);else{timeline.push({kind,version:value});introduced ||=kind==='introduced';fixed ||=kind==='fixed';last ||=kind==='last_affected'}}
 if(!introduced||fixed&&last)throw Error('OSV 引入/修复边界不完整或冲突');
 timeline.sort((a,b)=>a.kind==='introduced'&&a.version==='0'?-1:b.kind==='introduced'&&b.version==='0'?1:comparePackageVersions(scheme,a.version,b.version));
 for(let i=1;i<timeline.length;i++){const a=timeline[i-1],b=timeline[i];if(a.kind!==b.kind&&!(a.kind==='introduced'&&a.version==='0')&&comparePackageVersions(scheme,a.version,b.version)===0)throw Error('OSV 相等边界含义冲突')}
 if(limits.length&&!limits.some(value=>value==='*'||comparePackageVersions(scheme,version,value)<0))return false;
 let affected=false;for(const event of timeline){if(event.kind==='introduced'&&event.version==='0')affected=true;else{const order=comparePackageVersions(scheme,version,event.version);if(event.kind==='introduced'&&order>=0)affected=true;if(event.kind==='fixed'&&order>=0||event.kind==='last_affected'&&order>0)affected=false}}return affected;
}
