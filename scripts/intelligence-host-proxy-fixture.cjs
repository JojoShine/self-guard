// Local acceptance infrastructure only. These four public Debian CDN addresses
// were independently resolved on 2026-10-31; no arbitrary CONNECT is accepted.
// TLS remains end-to-end between the product fetcher and the official hostname.
const http=require('node:http'),net=require('node:net');
const allowed=new Set(['151.101.2.132:443','151.101.66.132:443','151.101.130.132:443','151.101.194.132:443']),sockets=new Set();
const server=http.createServer((_,res)=>{res.writeHead(405);res.end()});
server.on('connect',(request,client,head)=>{
 if(!allowed.has(request.url)||head.length||sockets.size>=8){client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return}
 const [host,port]=request.url.split(':'),remote=net.connect(Number(port),host,()=>{client.write('HTTP/1.1 200 Connection Established\r\n\r\n');client.pipe(remote);remote.pipe(client)});
 for(const socket of [client,remote]){sockets.add(socket);socket.setTimeout(30000,()=>socket.destroy());socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{client.destroy();remote.destroy()})}
});
server.listen(14412,'127.0.0.1',()=>console.log('Restricted Debian official-source acceptance proxy ready on 14412'));
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{for(const socket of sockets)socket.destroy();server.close(()=>process.exit(0))});
