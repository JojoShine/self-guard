import {describe,it,expect} from 'vitest';
import {theme} from 'antd';
import {designTokens,themeConfig} from './theme';

describe('semantic status backgrounds',()=>{
 it('keeps Ant Design status backgrounds consistent with the shared soft colors',()=>{
  const resolved=theme.getDesignToken(themeConfig);
  expect(resolved.colorSuccessBg).toBe(designTokens['--sg-success-soft']);
  expect(resolved.colorWarningBg).toBe(designTokens['--sg-warning-soft']);
  expect(resolved.colorErrorBg).toBe(designTokens['--sg-danger-soft']);
  expect(resolved.colorInfoBg).toBe(designTokens['--sg-primary-soft']);
 });
});
