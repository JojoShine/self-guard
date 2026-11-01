function bytes(value){if(value===undefined||value===null)return Buffer.alloc(0);if(typeof value==='string')return Buffer.from(value);if(value&&typeof value==='object'&&Object.keys(value).length===1&&typeof value.selfguardBytesBase64==='string')return Buffer.from(value.selfguardBytesBase64,'base64');throw Error('unsupported original fixture byte format')}
function request(input){
 if(input.encoded_request!==undefined)return Buffer.from(bytes(input.encoded_request).toString().replace(/\s/g,''),'base64');
 const headers={...(input.headers||{})},auto=input.autocomplete_headers!==false,method=input.method||'GET';let body=bytes(input.data);
 const has=name=>Object.keys(headers).some(k=>k.toLowerCase()===name.toLowerCase());
 // Reproduce go-ftw BuildRequest, not browser/fetch defaults. In particular,
 // missing Host/User-Agent can be the very condition a protocol fixture tests.
 // Reference: coreruleset/go-ftw/ftwhttp/request.go (BuildRequest).
 if(auto&&body.length){
  if(!has('Content-Type'))headers['Content-Type']='application/x-www-form-urlencoded';
  const media=Object.entries(headers).find(([k])=>k.toLowerCase()==='content-type')?.[1];
  if(media==='application/x-www-form-urlencoded'&&!body.includes(37)&&!body.includes(43)){
   const escape=value=>Array.from(value,b=>b===32?'+':b>=65&&b<=90||b>=97&&b<=122||b>=48&&b<=57||[45,95,46,126].includes(b)?String.fromCharCode(b):'%'+b.toString(16).toUpperCase().padStart(2,'0')).join('');
   body=Buffer.from(body.toString('latin1').split('&').map(field=>{const i=field.indexOf('=');return i<0?escape(Buffer.from(field,'latin1')):escape(Buffer.from(field.slice(0,i),'latin1'))+'='+escape(Buffer.from(field.slice(i+1),'latin1'))}).join('&'));
  }
 }
 const media=Object.entries(headers).find(([k])=>k.toLowerCase()==='content-type')?.[1];
 if(typeof media==='string'&&media.includes('multipart/form-data;'))body=Buffer.from(body.toString('latin1').replace(/\n/g,'\r\n'),'latin1');
 if(auto){if(!has('Connection'))headers.Connection='close';if(!has('Content-Length')&&(body.length||/^(POST|PUT|PATCH|DELETE)$/.test(method)))headers['Content-Length']=String(body.length)}
 const lines=[method+' '+(input.uri||'/')+' '+(input.version??'HTTP/1.1')];for(const [key,value]of Object.entries(headers)){if(typeof value!=='string'&&typeof value!=='number')throw Error('unsupported fixture header value');lines.push(key+': '+value)}return Buffer.concat([Buffer.from(lines.join('\r\n')+'\r\n\r\n'),body]);
}
module.exports = { request };
