import {describe,it,expect} from 'vitest';
import {pageWithinTotal} from './pagination';

describe('server pagination after result changes',()=>{
 it('returns the last valid page after the result count shrinks',()=>{
  expect(pageWithinTotal(9,7,15)).toBe(1);
  expect(pageWithinTotal(3,30,15)).toBe(2);
  expect(pageWithinTotal(2,31,15)).toBe(2);
 });
 it('keeps the first page for an empty result and accounts for the selected size',()=>{
  expect(pageWithinTotal(4,0,50)).toBe(1);
  expect(pageWithinTotal(4,65,30)).toBe(3);
 });
});
