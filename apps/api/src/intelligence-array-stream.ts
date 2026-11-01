type FeedEntry={key:string;value:unknown}|{record:unknown};
// Split one named root array while retaining bounded metadata values. This
// avoids buffering a whole NVD annual file or silently ignoring its tail.
export async function* jsonArrayFeed(chunks:AsyncIterable<Uint8Array>,arrayKey:string,entryLimit=2*1024*1024,totalLimit=1024*1024*1024):AsyncGenerator<FeedEntry>{
 const decoder=new TextDecoder('utf-8',{fatal:true}),keys=new Set<string>();let buffer='',cursor=0,state='ROOT',key='',start=0,quoted=false,escaped=false,depth=0,mode='',inArray=false,afterComma=false,arraySeen=false,total=0;
 const space=(char:string)=>/[ \t\r\n]/.test(char);
 async function* decoded(){for await(const chunk of chunks){total+=chunk.length;if(total>totalLimit)throw Error('年度来源超过解压预算');yield decoder.decode(chunk,{stream:true})}yield decoder.decode()}
 for await(const text of decoded()){
  buffer+=text;
  while(cursor<buffer.length){const char=buffer[cursor];
   if(state==='ROOT'){if(space(char)){cursor++;continue}if(char!=='{')throw Error('年度来源必须为JSON对象');state='KEY';cursor++;continue}
   if(state==='KEY'){if(space(char)){cursor++;continue}if(char==='}'&&!afterComma){state='END';cursor++;continue}if(char!=='"')throw Error('年度来源元数据键无效');start=cursor;escaped=false;state='KEY_TEXT';cursor++;continue}
   if(state==='KEY_TEXT'){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"'){key=JSON.parse(buffer.slice(start,cursor+1));if(keys.has(key)||keys.size>=32)throw Error('年度来源元数据重复或过多');keys.add(key);state='COLON'}cursor++;if(cursor-start>4096)throw Error('年度来源键过长');continue}
   if(state==='COLON'){if(space(char)){cursor++;continue}if(char!==':')throw Error('年度来源元数据分隔无效');state='VALUE';cursor++;continue}
   if(state==='VALUE'||state==='ARRAY_ITEM'){
    if(space(char)){cursor++;continue}
    if(state==='VALUE'&&key===arrayKey){if(char!=='[')throw Error('年度来源通告必须为数组');arraySeen=true;inArray=true;afterComma=false;state='ARRAY_ITEM';cursor++;continue}
    if(state==='ARRAY_ITEM'&&char===']'&&!afterComma){inArray=false;state='AFTER';cursor++;continue}
    if(state==='ARRAY_ITEM'&&char!=='{')throw Error('年度来源通告必须为对象');
    start=cursor;depth=0;quoted=false;escaped=false;afterComma=false;mode=char==='{'||char==='['?'complex':char==='"'?'string':'primitive';state='TOKEN';continue;
   }
   if(state==='TOKEN'){
    let complete=false,consume=true;
    if(mode==='primitive'&&(space(char)||char===','||char==='}')){complete=true;consume=false}
    else if(quoted){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"'){quoted=false;if(mode==='string')complete=true}}
    else if(char==='"')quoted=true;
    else if(char==='{'||char==='[')depth++;
    else if(char==='}'||char===']'){depth--;if(mode==='complex'&&depth===0)complete=true}
    if(consume)cursor++;if(cursor-start>entryLimit)throw Error('年度来源单条通告或元数据超过预算');
    if(complete){const raw=buffer.slice(start,cursor);if(Buffer.byteLength(raw)>entryLimit)throw Error('年度来源单条超过预算');const value=JSON.parse(raw),entry:FeedEntry=inArray?{record:value}:{key,value};buffer=buffer.slice(cursor);cursor=0;state=inArray?'ARRAY_AFTER':'AFTER';yield entry}
    continue;
   }
   if(state==='ARRAY_AFTER'){if(space(char)){cursor++;continue}if(char===','){afterComma=true;state='ARRAY_ITEM';cursor++;continue}if(char===']'){inArray=false;state='AFTER';cursor++;continue}throw Error('年度来源通告分隔无效')}
   if(state==='AFTER'){if(space(char)){cursor++;continue}if(char===','){afterComma=true;state='KEY';cursor++;continue}if(char==='}'){state='END';cursor++;continue}throw Error('年度来源元数据尾部无效')}
   if(state==='END'){if(!space(char))throw Error('年度来源JSON后存在额外内容');cursor++}
  }
  if(!['KEY_TEXT','TOKEN'].includes(state)){buffer='';cursor=0}
 }
 if(state!=='END'||!arraySeen)throw Error('年度来源未完整结束或缺少通告数组');
}
