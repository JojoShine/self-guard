const http=require('node:http'),https=require('node:https'),fs=require('node:fs'),path=require('node:path');
const upstreams=(process.env.API_UPSTREAMS||'http://api:4000').split(',').map(x=>new URL(x));let cursor=0;const healthy=new Set(upstreams.map(u=>u.href));
const webRoot=process.env.WEB_ROOT||'/web';
async function probe(){await Promise.all(upstreams.map(async u=>{try{const r=await fetch(new URL('/api/health/ready',u),{signal:AbortSignal.timeout(2000)});if(r.ok)healthy.add(u.href);else healthy.delete(u.href)}catch{healthy.delete(u.href)}}));}
setInterval(probe,2000).unref();void probe();
function handler(req,res){
 res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; base-uri 'self'; frame-ancestors 'none'");
 res.setHeader('Referrer-Policy','same-origin');
 if(req.url==='/health'){res.writeHead(healthy.size?200:503,{'content-type':'application/json'});res.end(JSON.stringify({ready:healthy.size>0,healthy:healthy.size,total:upstreams.length}));return;}
 if(req.url.startsWith('/api/')){const targets=upstreams.filter(u=>healthy.has(u.href));if(!targets.length){res.writeHead(503);res.end('API unavailable');return;}const target=targets[cursor++%targets.length];const headers={...req.headers,host:target.host,'x-forwarded-for':req.socket.remoteAddress};for(const name of ['connection','proxy-authorization','proxy-authenticate','keep-alive','upgrade','transfer-encoding','te','trailer'])delete headers[name];
 const proxy=(target.protocol==='https:'?https:http).request(new URL(req.url,target),{method:req.method,headers,timeout:30000},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res)});proxy.on('error',()=>{healthy.delete(target.href);if(!res.headersSent)res.writeHead(502);res.end('API connection failed')});proxy.on('timeout',()=>proxy.destroy());req.on('aborted',()=>proxy.destroy());req.pipe(proxy);return;}
 let pathname;try{pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname)}catch{res.writeHead(400);res.end();return;}
 let file=path.resolve(webRoot,'.'+pathname);if(!file.startsWith(path.resolve(webRoot)+path.sep)){file=path.join(webRoot,'index.html');}if(!fs.existsSync(file)||fs.statSync(file).isDirectory())file=path.join(webRoot,'index.html');
 const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png'};res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');res.setHeader('Cache-Control',file.endsWith('index.html')?'no-store':'public,max-age=3600');fs.createReadStream(file).on('error',()=>{res.statusCode=404;res.end('not found')}).pipe(res);
}
const server=process.env.TLS_CERT&&process.env.TLS_KEY?https.createServer({cert:fs.readFileSync(process.env.TLS_CERT),key:fs.readFileSync(process.env.TLS_KEY)},handler):http.createServer(handler);server.requestTimeout=30000;server.headersTimeout=5000;server.listen(Number(process.env.PORT||8080),'0.0.0.0');
