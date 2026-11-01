import {it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {recordFieldRows,RecordFieldsTable} from './RecordFieldsTable';

it('retains all nested fields, arrays, empty values and structured JSON text without colliding paths',()=>{
 const value=JSON.parse('{"a.b":1,"a":{"b":2},"zero":0,"enabled":false,"missing":null,"items":[],"empty":{},"__proto__":"literal"}');
 value.evidence=JSON.stringify({events:Array.from({length:151},(_,index)=>({index,content:'item-'+index}))});
 const rows=recordFieldRows(value);
 expect(new Set(rows.map(row=>row.id)).size).toBe(rows.length);
 expect(rows.some(row=>row.value===0)).toBe(true);expect(rows.some(row=>row.value===false)).toBe(true);expect(rows.some(row=>row.value===null)).toBe(true);
 expect(rows.some(row=>row.value==='item-150')).toBe(true);expect(rows.some(row=>row.field==='__proto__'&&row.value==='literal')).toBe(true);
 expect(rows.filter(row=>row.value===1||row.value===2).map(row=>row.path)).toContain('["a.b"]');
 expect(rows.filter(row=>row.value===2).map(row=>row.path)).toContain('a.b');
});
it('handles deep records iteratively and presents raw fields as a visible table, not collapsed JSON',()=>{
 let value:any={actual:'<script>unsafe()</script>'};for(let i=0;i<2000;i++)value={child:value};
 expect(recordFieldRows(value)).toHaveLength(1);
 const html=renderToStaticMarkup(<RecordFieldsTable value={{actual:'<script>unsafe()</script>',enabled:false,count:0}}/>);
 expect(html).toContain('完整留存字段');expect(html).toContain('<table');expect(html).toContain('&lt;script&gt;');expect(html).not.toContain('<script>');expect(html).not.toContain('<details');expect(html).not.toContain('<pre');
});
