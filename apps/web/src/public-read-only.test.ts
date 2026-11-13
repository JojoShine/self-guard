import {expect,it} from 'vitest';
import {canViewConfiguration,isPublicReadOnly} from './public-read-only';
it('allows public viewers to inspect settings without changing their role',()=>{
 const viewer={role:'VIEWER',publicReadOnly:true};
 expect(canViewConfiguration(viewer)).toBe(true);
 expect(viewer.role).toBe('VIEWER');
 expect(isPublicReadOnly(viewer)).toBe(true);
});
it('preserves configuration access for ordinary accounts',()=>{
 expect(canViewConfiguration({role:'ADMIN'})).toBe(true);
 expect(canViewConfiguration({role:'VIEWER'})).toBe(false);
 expect(canViewConfiguration(undefined)).toBe(false);
 expect(isPublicReadOnly({role:'VIEWER'})).toBe(false);
});
