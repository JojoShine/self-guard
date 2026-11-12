export type TrafficSqlParse = {
  state:'EXTRACTED'|'PARTIAL'|'UNAVAILABLE'|'UNSUPPORTED';
  statements:{sql:string;stage:'QUERY'|'PREPARE'|'EXECUTE'}[];
  reasons:string[];
};
const MAX_REQUEST=1024*1024,MAX_SQL=32768,MAX_STATEMENTS=100,MAX_FRAMES=4096;
class FrameError extends Error { constructor(readonly reason:string){super(reason);} }
const fail=(reason:string):never=>{throw new FrameError(reason);};
const unavailable=(reason:string):TrafficSqlParse=>({state:'UNAVAILABLE',statements:[],reasons:[reason]});
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
function text(bytes:Buffer):string {
  try{return decoder.decode(bytes);}catch(error){if(error instanceof TypeError)return fail('INVALID_ENCODING');throw error;}
}
function sqlText(bytes:Buffer):string {
  if(bytes.length>MAX_SQL)fail('SQL_TOO_LARGE');
  if(bytes.includes(0))fail('INVALID_FRAME');
  return text(bytes);
}
class Fields {
  offset=0;
  constructor(readonly body:Buffer){}
  bytes(count:number):Buffer {if(count<0||count>this.body.length-this.offset)fail('INVALID_FRAME');const out=this.body.subarray(this.offset,this.offset+count);this.offset+=count;return out;}
  u16():number{return this.bytes(2).readUInt16BE(0);}
  u32():number{return this.bytes(4).readUInt32BE(0);}
  i32():number{return this.bytes(4).readInt32BE(0);}
  cstring():Buffer {const end=this.body.indexOf(0,this.offset);if(end<0)return fail('INVALID_FRAME');const out=this.bytes(end-this.offset);this.bytes(1);return out;}
  end():void {if(this.offset!==this.body.length)fail('INVALID_FRAME');}
}

/** Decode only framed request messages; never search arbitrary payloads for SQL keywords. */
export function parseCapturedSql(protocol:string,request:Buffer):TrafficSqlParse {
  if(protocol!=='POSTGRESQL'&&protocol!=='MYSQL')return{state:'UNSUPPORTED',statements:[],reasons:['PROTOCOL_UNSUPPORTED']};
  if(request.length>MAX_REQUEST)return unavailable('REQUEST_TOO_LARGE');
  if(!request.length)return unavailable('BODY_NOT_CAPTURED');
  if(request.length>=3&&(request[0]===0x16||request[0]===0x17)&&request[1]===3&&request[2]<=4)return unavailable('TLS_NO_PLAINTEXT');
  if(protocol==='POSTGRESQL'&&request[0]===0){
    if(request.length===8&&request.readUInt32BE(0)===8&&request.readUInt32BE(4)===80877103)return unavailable('TLS_NO_PLAINTEXT');
    return unavailable('AUTHENTICATION_MESSAGE');
  }
  type Candidate={sql:string;used:boolean};
  const events:{statement:TrafficSqlParse['statements'][number];prepare?:Candidate}[]=[],reasons=new Set<string>();
  const statements=new Map<string,Candidate>(),portals=new Map<string,Candidate>();
  const add=(sql:string,stage:TrafficSqlParse['statements'][number]['stage'],prepare?:Candidate)=>{
    if(events.length>=MAX_STATEMENTS)fail('STATEMENT_LIMIT');events.push({statement:{sql,stage},prepare});
  };
  try {
    let offset=0,frames=0;
    while(offset<request.length){
      if(++frames>MAX_FRAMES)fail('STATEMENT_LIMIT');
      if(protocol==='MYSQL'){
        if(request.length-offset<4)fail('INVALID_FRAME');
        const length=request.readUIntLE(offset,3),sequence=request[offset+3];
        if(sequence!==0)fail('AUTHENTICATION_MESSAGE');
        if(length>MAX_REQUEST)fail('REQUEST_TOO_LARGE');
        if(length<1||length>request.length-offset-4)fail('INVALID_FRAME');
        const command=request[offset+4],body=request.subarray(offset+5,offset+4+length);offset+=4+length;
        if(command===3)add(sqlText(body),'QUERY');
        else if(command===0x16)add(sqlText(body),'PREPARE');
        else if(command===0x17)reasons.add('PREPARED_CONTEXT_MISSING');
        continue;
      }
      if(request.length-offset<5)fail('INVALID_FRAME');
      const kind=String.fromCharCode(request[offset]),length=request.readUInt32BE(offset+1);
      if(length<4||length>request.length-offset-1)fail('INVALID_FRAME');
      const fields=new Fields(request.subarray(offset+5,offset+1+length));offset+=1+length;
      if(kind==='p')fail('AUTHENTICATION_MESSAGE');
      if(kind==='Q')add(sqlText(fields.cstring()),'QUERY');
      else if(kind==='P'){
        const name=fields.cstring().toString('hex'),sql=sqlText(fields.cstring());
        fields.bytes(fields.u16()*4);const candidate={sql,used:false};statements.set(name,candidate);add(sql,'PREPARE',candidate);
      } else if(kind==='B'){
        const portal=fields.cstring().toString('hex'),statement=fields.cstring().toString('hex');
        const formats=fields.u16();for(let i=0;i<formats;i++){if(fields.u16()>1)fail('INVALID_FRAME');}
        const count=fields.u16();if(formats!==0&&formats!==1&&formats!==count)fail('INVALID_FRAME');
        for(let i=0;i<count;i++){const size=fields.i32();if(size< -1)fail('INVALID_FRAME');if(size>=0)fields.bytes(size);}
        const results=fields.u16();for(let i=0;i<results;i++){if(fields.u16()>1)fail('INVALID_FRAME');}
        const candidate=statements.get(statement);if(candidate)portals.set(portal,candidate);else{portals.delete(portal);reasons.add('PREPARED_CONTEXT_MISSING');}
      } else if(kind==='E'){
        const portal=fields.cstring().toString('hex');fields.u32();const candidate=portals.get(portal);
        if(candidate){candidate.used=true;add(candidate.sql,'EXECUTE');}else reasons.add('PREPARED_CONTEXT_MISSING');
      } else if(kind==='C'||kind==='D'){
        const target=fields.bytes(1)[0],name=fields.cstring().toString('hex');if(target!==83&&target!==80)fail('INVALID_FRAME');
        if(kind==='C')(target===83?statements:portals).delete(name);
      } else if(kind==='d'||kind==='f')fields.bytes(fields.body.length);
      else if(!['S','H','X','c'].includes(kind))fail('INVALID_FRAME');
      fields.end();
    }
    const output=events.filter(event=>!event.prepare?.used).map(event=>event.statement);
    if(reasons.size)return{state:'PARTIAL',statements:output,reasons:[...reasons]};
    return output.length?{state:'EXTRACTED',statements:output,reasons:[]}:unavailable('NO_SQL_MESSAGE');
  }catch(error){if(error instanceof FrameError)return unavailable(error.reason);throw error;}
}
