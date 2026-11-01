const {test}=require('node:test'),assert=require('node:assert/strict');
const {request}=require('./crs-ftw-request.cjs');

test('FTW preserves explicit empty protocol version for HTTP/0.9 fixtures',()=>{
 assert.equal(request({version:'',autocomplete_headers:false}).toString(),'GET / \r\n\r\n');
 assert.match(request({}).toString(),/^GET \/ HTTP\/1\.1\r\n/);
});

test('FTW preserves intentional missing headers and adds body headers for any method',()=>{
 const raw=request({version:'HTTP/1.0',data:'q=attack'}).toString();
 assert.doesNotMatch(raw,/Host:|User-Agent:/);
 assert.match(raw,/Content-Type: application\/x-www-form-urlencoded/);
 assert.match(raw,/Connection: close/);
 assert.match(raw,/Content-Length: 8/);
});
test('FTW form escaping and multipart line endings occur before content-length calculation',()=>{
 const form=request({method:'POST',data:'q=<script>'}).toString();
 assert.match(form,/q=%3Cscript%3E$/);
 assert.match(form,/Content-Length: 14/);
 const body='--x\nContent-Disposition: form-data; name="q"\n\nsafe\n--x--\n';
 const multipart=request({method:'POST',headers:{'Content-Type':'multipart/form-data; boundary=x'},data:body}).toString();
 assert.match(multipart,/\r\n\r\nsafe\r\n--x--\r\n$/);
 assert.match(multipart,new RegExp('Content-Length: '+(body.length+5)));
});
test('FTW explicit raw and no-autocomplete requests remain byte-preserving',()=>{
 const raw=Buffer.from('GET / HTTP/1.0\r\nHost:\r\n\r\n');
 assert.deepEqual(request({encoded_request:raw.toString('base64')}),raw);
 assert.equal(request({autocomplete_headers:false,data:'q=<script>'}).toString(),'GET / HTTP/1.1\r\n\r\nq=<script>');
});
