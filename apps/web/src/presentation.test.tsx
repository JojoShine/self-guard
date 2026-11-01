import {describe,it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {displaySource,displayStatus,statusTone,formatTime} from './presentation';
import {StatusTag,SeverityTag,DetectionMatchTag} from './ModuleSection';

describe('shared module status presentation',()=>{
 it('distinguishes uncertain outcomes, active work and confirmed completion',()=>{
  expect(statusTone('UNKNOWN')).toBe('warning');
  expect(statusTone('SENDING')).toBe('processing');
  expect(statusTone('DELIVERED')).toBe('success');
  expect(statusTone('PARTIAL')).toBe('warning');
  expect(statusTone('FAILED')).toBe('error');
  expect(statusTone('ONLINE')).toBe('success');expect(statusTone('STALE')).toBe('warning');
 });
 it('uses the module meaning for a shared code and keeps unknown labels literal',()=>{
  const html=renderToStaticMarkup(<StatusTag value="PENDING" labels={{PENDING:'等待投递'}}/>);
  expect(html).toContain('等待投递');
  expect(html).not.toContain('待审批');
  expect(displayStatus('constructor')).toBe('constructor');
  expect(displaySource('__proto__')).toBe('__proto__');
 });
 it('keeps risk severity separate from workflow state and avoids a clean label for unknown detections',()=>{
  const high=renderToStaticMarkup(<SeverityTag value="HIGH"/>);
  expect(high).toContain('ant-tag-error');expect(high).toContain('高');
  const medium=renderToStaticMarkup(<SeverityTag value="MEDIUM"/>);
  expect(medium).toContain('ant-tag-warning');
  expect(renderToStaticMarkup(<DetectionMatchTag matched={false} status="UNKNOWN"/>)).toBe('');
  expect(renderToStaticMarkup(<DetectionMatchTag matched={false} status="COMPLETED"/>)).toContain('未命中');
  expect(renderToStaticMarkup(<DetectionMatchTag matched={true} status="COMPLETED"/>)).toContain('命中规则');
 });
 it('does not fabricate timestamps for absent or invalid values',()=>{
  expect(formatTime(undefined)).toBe('—');
  expect(formatTime('invalid-date')).toBe('—');
 });
 it('uses meaningful labels and tones for WAF and detection outcomes',()=>{
  expect(displayStatus('BLOCK')).toBe('阻断');
  expect(statusTone('BLOCK')).toBe('error');
  expect(displayStatus('ALLOW')).toBe('放行');
  expect(statusTone('ALLOW')).toBe('success');
  expect(displayStatus('OBSERVE')).toBe('观察');
  expect(statusTone('OBSERVE')).toBe('processing');
  expect(statusTone('MATCHED')).toBe('warning');
  expect(statusTone('NO_MATCH')).toBe('success');
 });
});
