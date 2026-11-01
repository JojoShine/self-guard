// Restricted CONNECT fixture: only the isolated native API is reachable.
const http=require('node:http'),net=require('node:net');let connections=0;
const server=http.createServer((req,res)=>{if(req.url==='/stats'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({connections}));}else{res.writeHead(405);res.end();}});
server.on('connect',(req,client,head)=>{if(!['host.lima.internal:14410','native-api:4001'].includes(req.url)||req.headers['proxy-authorization']){client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
 const upstream=net.connect(4001,'native-api',()=>{connections++;client.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);upstream.pipe(client);client.pipe(upstream);});upstream.on('error',()=>client.destroy());client.on('error',()=>upstream.destroy());client.on('close',()=>upstream.destroy());});
server.listen(4002,'0.0.0.0',()=>console.log('Restricted native fixture proxy ready'));
