type Order=-1|0|1;
function lexical(a:string,b:string):Order{return a===b?0:a<b?-1:1}
function number(a:string,b:string):Order{a=a.replace(/^0+/,'')||'0';b=b.replace(/^0+/,'')||'0';return a.length===b.length?lexical(a,b):a.length<b.length?-1:1}
function python(value:string){
 if(typeof value!=='string'||value.length>4096)throw Error('无效 Python 版本');
 const m=/^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i.exec(value.trim());if(!m)throw Error('版本不符合 PEP 440');const pre=m[3]?.toLowerCase(),preRank=pre?['a','alpha'].includes(pre)?0:['b','beta'].includes(pre)?1:2:undefined;
 return {epoch:m[1]||'0',release:m[2].split('.'),pre:preRank,preNumber:m[4]||'0',post:m[5]??(m[6]?m[7]||'0':undefined),dev:m[8]?m[9]||'0':undefined,local:m[10]?.toLowerCase().split(/[-_.]/)||[]};
}
export function comparePythonVersions(a:string,b:string):Order{
 const x=python(a),y=python(b),epoch=number(x.epoch,y.epoch);if(epoch)return epoch;for(let i=0;i<Math.max(x.release.length,y.release.length);i++){const c=number(x.release[i]||'0',y.release[i]||'0');if(c)return c}
 const pre=(v:ReturnType<typeof python>)=>v.pre===undefined?v.dev!==undefined&&v.post===undefined?-1:3:v.pre,rankX=pre(x),rankY=pre(y);if(rankX!==rankY)return rankX<rankY?-1:1;if(x.pre!==undefined&&y.pre!==undefined){const c=number(x.preNumber,y.preNumber);if(c)return c}
 for(const key of ['post','dev'] as const){const left=x[key],right=y[key];if(left===undefined||right===undefined){if(left!==right)return left===undefined?(key==='post'?-1:1):(key==='post'?1:-1)}else{const c=number(left,right);if(c)return c}}
 for(let i=0;i<Math.max(x.local.length,y.local.length);i++){const left=x.local[i],right=y.local[i];if(left===undefined||right===undefined)return left===undefined?-1:1;const ln=/^\d+$/.test(left),rn=/^\d+$/.test(right),c=ln&&rn?number(left,right):ln!==rn?ln?1:-1:lexical(left,right);if(c)return c}return 0;
}
// Frozen compatibility profile: Maven Artifact 3.9.11 ComparableVersion.
// The upstream Maven 4 reference changes underscore semantics; do not mix profiles.
type MavenItem={value:string;numeric:boolean}|MavenItem[];
const qualifiers=['alpha','beta','milestone','rc','snapshot','','sp'];
function qualifier(value:string,directNumber=false){value=value.toLowerCase();if(directNumber)value=({a:'alpha',b:'beta',m:'milestone'} as Record<string,string>)[value]||value;return ({ga:'',final:'',release:'',cr:'rc'} as Record<string,string>)[value]??value}
function compareQualifier(a:string,b:string):Order{const x=qualifiers.indexOf(a),y=qualifiers.indexOf(b);if(x<0||y<0){if(x>=0)return -1;if(y>=0)return 1;return lexical(a,b)}return x===y?0:x<y?-1:1}
function maven(value:string):MavenItem[]{
 if(typeof value!=='string'||!value.length||value.length>4096||/[\s\x00-\x1f]/.test(value))throw Error('无效 Maven 版本');const root:MavenItem[]=[],lists=[root];let list=root,current='',digit=false;
 function child(){if(lists.length>=128)throw Error('Maven版本层级超过128');const next:MavenItem[]=[];list.push(next);lists.push(next);list=next}
 function emit(directNumber=false){const numeric=/^\d+$/.test(current||'0');list.push({value:numeric?current||'0':qualifier(current,directNumber),numeric});current=''}
 for(const char of value){if(char==='.'||char==='-'){emit();if(char==='-')child();continue}const numeric=/^[0-9]$/.test(char);if(current&&numeric!==digit){if(numeric){if(list.length)child();emit(true);child()}else{emit();child()}}current+=char;digit=numeric}
 if(current){if(!digit&&list.length)child();emit()}
 for(let i=lists.length-1;i>=0;i--){const items=lists[i];for(let j=items.length-1;j>=0;j--){const item=items[j],empty=Array.isArray(item)?item.length===0:item.numeric?number(item.value,'0')===0:item.value==='';if(empty)items.splice(j,1);else if(!Array.isArray(item))break}}return root;
}
function compareMavenItem(a:MavenItem|undefined,b:MavenItem|undefined):Order{
 if(a===undefined&&b===undefined)return 0;if(a===undefined){const result=compareMavenItem(b,undefined);return result===0?0:result===1?-1:1}
 if(b===undefined){if(Array.isArray(a)){for(const item of a){const result=compareMavenItem(item,undefined);if(result)return result}return 0}return a.numeric?number(a.value,'0'):compareQualifier(a.value,'')}
 if(Array.isArray(a)){if(!Array.isArray(b))return b.numeric?-1:1;for(let i=0;i<Math.max(a.length,b.length);i++){const result=compareMavenItem(a[i],b[i]);if(result)return result}return 0}
 if(Array.isArray(b))return a.numeric?1:-1;if(a.numeric!==b.numeric)return a.numeric?1:-1;return a.numeric?number(a.value,b.value):compareQualifier(a.value,b.value);
}
export function compareMavenVersions(a:string,b:string):Order{return compareMavenItem(maven(a),maven(b))}
