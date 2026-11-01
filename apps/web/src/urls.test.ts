import {it,expect} from 'vitest';
import {apiURL,assetURL,platformURL} from './urls';
it('prefixes API and static resources from the same deployment base',()=>{expect(apiURL('/assets')).toBe((import.meta.env.BASE_URL||'/')+'api/assets');expect(assetURL('brand/selfguard-mark.png')).toContain('brand/selfguard-mark.png')});
it('preserves the approved platform subpath',()=>{expect(platformURL('https://tbtparent.me/self-guard/')).toBe('https://tbtparent.me/self-guard');for(const value of ['https://x/a/../b','https://x/a//b','https://x/a?b','https://x/api'])expect(()=>platformURL(value)).toThrow()});
