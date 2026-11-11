import {describe,it,expect} from 'vitest';
import {parseProcessProfile} from './ProcessProfileField';
describe('approved process profiles',()=>{
 const profile={kind:'OPENSSL_DYNAMIC',libraryPath:'/usr/lib64/libssl.so.3',pid:1234,uid:1001,startTicks:'123456',executableSha256:'a'.repeat(64),librarySha256:'b'.repeat(64),executableIdentity:'1:2:3:4:5',libraryIdentity:'1:2:3:4:5'};
 it('accepts the inspector output and requires its mapped library path',()=>{expect(parseProcessProfile(profile)).toEqual(profile);expect(()=>parseProcessProfile({...profile,libraryPath:undefined})).toThrow();});
 it('rejects injected paths, unrecognized keys and unsupported integer identities',()=>{for(const changes of [{libraryPath:'/tmp/x; exit()'},{token:'forged'},{librarySha256:''},{pid:0},{pid:4194305},{uid:2147483648},{startTicks:'0'}])expect(()=>parseProcessProfile({...profile,...changes})).toThrow();});
});
