import {expect,it} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {formatTrafficPayload,TrafficPayloadView} from './TrafficPayloadView';

it('formats JSON without changing large numbers, duplicate keys or string escapes',()=>{
 const raw='{"id":9007199254740993,"id":1e+200,"items":[true,null,{"text":"a\\n\\\"b"}],"empty":{}}';
 const result=formatTrafficPayload(raw,'TEXT');
 expect(result.language).toBe('JSON');expect(result.text).toContain('\n  "id": 9007199254740993,');expect(result.text).toContain('"id": 1e+200');expect(result.text).toContain('"empty": {}');expect(result.text).toContain('"text": "a\\n\\\"b"');expect(JSON.parse(result.text)).toEqual(JSON.parse(raw));
});
it('separates HTTP headers from a formatted JSON body',()=>{
 const result=formatTrafficPayload('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Test: keep\r\n\r\n{"rows":[{"id":1}]}','TEXT');
 expect(result.language).toBe('HTTP');expect(result.text).toContain('X-Test: keep\n\n{\n  "rows": [');
});
it('keeps partial JSON, SQL and non-JSON HTTP bodies intact',()=>{
 for(const raw of ['{"partial":','SELECT id FROM users;','<script>alert("x")</script>'])expect(formatTrafficPayload(raw,'TEXT').text).toBe(raw);
 const raw='POST /upload HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n{incomplete';expect(formatTrafficPayload(raw,'TEXT').text).toContain('\n\n{incomplete');
});
it('formats binary previews with byte offsets, hex and printable ASCII',()=>{
 const result=formatTrafficPayload('00 41 42 ff 0a','HEX');expect(result.language).toBe('HEX');expect(result.text).toMatch(/^00000000\s+00 41 42 ff 0a/);expect(result.text).toContain('|.AB..|');
});
it('bounds deeply nested JSON formatting and preserves the original preview',()=>{
 const raw='['.repeat(1000)+'0'+']'.repeat(1000);expect(formatTrafficPayload(raw,'TEXT').text).toBe(raw);
});
it('renders escaped code with line numbers and format/raw controls',()=>{
 const html=renderToStaticMarkup(<TrafficPayloadView text={'{"html":"<img src=x onerror=alert(1)>"}'} mode="TEXT"/>);
 expect(html).toContain('<pre');expect(html).toContain('<code');expect(html).toContain('payload-line-number');expect(html).toContain('payload-token-key');expect(html).toContain('格式化');expect(html).toContain('原文');expect(html).toContain('自动换行');expect(html).toContain('&lt;img');expect(html).not.toContain('<img');expect(html).not.toContain('<textarea');
});
