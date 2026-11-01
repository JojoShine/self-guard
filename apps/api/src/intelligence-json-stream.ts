// A bounded top-level object reader for the Debian tracker's package map.
// Only one package object is retained; JSON.parse validates each full value.
export async function* jsonObjectEntries(chunks:AsyncIterable<Uint8Array>,entryLimit=16*1024*1024):AsyncGenerator<[string,unknown]>{for await(const [path,value]of jsonObjectPairs(chunks,entryLimit,1))yield [path[0],value]}
export async function* jsonObjectPairs(chunks:AsyncIterable<Uint8Array>,entryLimit=2*1024*1024,splitDepth=2):AsyncGenerator<[string[],unknown]>{
 const decoder=new TextDecoder('utf-8',{fatal:true}),scope:string[]=[],keySets=[new Set<string>()];let buffer='',cursor=0,state='ROOT',start=0,key='',depth=0,quoted=false,escaped=false,afterComma=false,total=0;
 async function* decoded(){for await(const chunk of chunks){total+=chunk.length;if(total>512*1024*1024)throw Error('来源解压超过512MiB限制');yield decoder.decode(chunk,{stream:true})}yield decoder.decode()}
 for await(const text of decoded()){
  buffer+=text;
  while(cursor<buffer.length){const char=buffer[cursor];
   if(state==='ROOT'){if(/[ \t\r\n]/.test(char)){cursor++;continue}if(char!=='{')throw Error('来源顶层必须为软件包对象');state='KEY';cursor++;continue}
   if(state==='KEY'){if(/[ \t\r\n]/.test(char)){cursor++;continue}if(char==='}'&&!afterComma){if(scope.length){scope.pop();keySets.pop();state='AFTER'}else state='END';cursor++;continue}if(char!=='"')throw Error('来源软件包键无效');start=cursor;quoted=true;escaped=false;state='KEY_TEXT';cursor++;continue}
   if(state==='KEY_TEXT'){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"'){key=JSON.parse(buffer.slice(start,cursor+1));const keys=keySets[keySets.length-1];if(keys.has(key)||keys.size>=100000)throw Error('来源重复标识或超过十万条限制');keys.add(key);state='COLON'}cursor++;if(cursor-start>entryLimit)throw Error('单个来源条目过大');continue}
   if(state==='COLON'){if(/[ \t\r\n]/.test(char)){cursor++;continue}if(char!==':')throw Error('来源软件包分隔符无效');state='VALUE';cursor++;continue}
   if(state==='VALUE'){if(/[ \t\r\n]/.test(char)){cursor++;continue}if(char!=='{')throw Error('来源软件包内容必须为对象');if(scope.length<splitDepth-1){scope.push(key);keySets.push(new Set());state='KEY';afterComma=false;cursor++;continue}start=cursor;depth=1;quoted=false;escaped=false;state='VALUE_TEXT';cursor++;continue}
   if(state==='VALUE_TEXT'){
    if(quoted){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"')quoted=false}else if(char==='"')quoted=true;else if(char==='{'||char==='[')depth++;else if(char==='}'||char===']')depth--;
    cursor++;if(cursor-start>entryLimit)throw Error('单个来源条目过大');
    if(depth===0){const raw=buffer.slice(start,cursor);if(Buffer.byteLength(raw)>entryLimit)throw Error('单个来源条目过大');const value=JSON.parse(raw);buffer=buffer.slice(cursor);cursor=0;state='AFTER';yield [[...scope,key],value]}
    continue;
   }
   if(state==='AFTER'){if(/[ \t\r\n]/.test(char)){cursor++;continue}if(char===','){afterComma=true;state='KEY';cursor++;continue}if(char==='}'){if(scope.length){scope.pop();keySets.pop();state='AFTER';afterComma=false}else state='END';cursor++;continue}throw Error('来源条目后存在无效内容')}
   if(state==='END'){if(!/[ \t\r\n]/.test(char))throw Error('来源对象后存在多余内容');cursor++}
  }
  // Outside tokens the consumed prefix carries no business data.
  if(!['KEY_TEXT','VALUE_TEXT'].includes(state)){buffer='';cursor=0}
 }
 if(state!=='END')throw Error('来源响应未完整结束，不发布快照');
}
