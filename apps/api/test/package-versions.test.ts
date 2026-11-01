import {test} from 'node:test';import assert from 'node:assert/strict';
import {comparePackageVersions,matchesVersionEvents} from '../src/package-versions';
test('semantic precedence handles prereleases, ignored build metadata and numeric size without coercion',()=>{
 const values=['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta','1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0'];for(let i=1;i<values.length;i++)assert.equal(comparePackageVersions('SEMVER',values[i-1],values[i]),-1);
 assert.equal(comparePackageVersions('SEMVER','1.0.0+a','1.0.0+b'),0);assert.equal(comparePackageVersions('SEMVER','99999999999999999999.0.0','99999999999999999998.0.0'),1);assert.throws(()=>comparePackageVersions('SEMVER','1.02.0','1.2.0'));assert.equal(comparePackageVersions('GO','v1.2.3','v1.2.4'),-1);
});
test('RPM epochs, separators, tilde, caret and release segments follow native ordering',()=>{
 for(const [left,right]of [['1.0~rc1','1.0'],['2.0','2.0^150825'],['2.0^150825','2.0.1'],['1.0','1.0-1'],['1.0-2','1.0-10'],['1.xyz','1.0'],['1.999','1:1.0']])assert.equal(comparePackageVersions('RPM',left,right),-1,left+' < '+right);
 for(const [left,right]of [['1.0','1+0'],['1.0','1+.+0'],['abc123','abc0123'],['0:1.0','1.0']])assert.equal(comparePackageVersions('RPM',left,right),0);assert.throws(()=>comparePackageVersions('RPM','1.α','1.0'));
});
test('APK revisions, ordered suffixes, leading zero segments and hashes follow native ordering',()=>{
 for(const [left,right]of [['1.0_alpha','1.0_beta'],['1.0_beta','1.0_pre'],['1.0_pre','1.0_rc'],['1.0_rc1','1.0'],['1.0','1.0_p1'],['1.0-r1','1.0-r2'],['1.01','1.1'],['1.0~abc','1.0~abd'],['1.0','1.0a']])assert.equal(comparePackageVersions('APK',left,right),-1,left+' < '+right);
 assert.equal(comparePackageVersions('APK','01.0','1.0'),0);assert.throws(()=>comparePackageVersions('APK','1.0_invalid','1.0'));assert.throws(()=>comparePackageVersions('APK','1.0-rx','1.0'));
});
test('OSV transitions distinguish introduced, fixed and inclusive last affected across ordered schemes',()=>{
 const events=[{introduced:'0'},{fixed:'1.2.3'},{introduced:'2.0.0'},{fixed:'2.0.1'}];assert.equal(matchesVersionEvents('SEMVER','1.2.2',events),true);assert.equal(matchesVersionEvents('SEMVER','1.2.3',events),false);assert.equal(matchesVersionEvents('SEMVER','2.0.0',events),true);assert.equal(matchesVersionEvents('SEMVER','2.0.1',events),false);
 assert.equal(matchesVersionEvents('APK','1.0-r1',[{introduced:'0'},{last_affected:'1.0-r1'}]),true);assert.equal(matchesVersionEvents('APK','1.0-r2',[{introduced:'0'},{last_affected:'1.0-r1'}]),false);assert.throws(()=>matchesVersionEvents('SEMVER','1.0.0',[{fixed:'2.0.0'}]));
});
test('Python PEP 440 orders epoch, zero-padded releases, prerelease, dev, post and local identifiers',()=>{
 const values=['1.0.dev1','1.0a1.dev1','1.0a1','1.0b1','1.0rc1','1.0','1.0+abc','1.0+1','1.0.post1.dev1','1.0.post1','1!0.1'];for(let i=1;i<values.length;i++)assert.equal(comparePackageVersions('PEP440',values[i-1],values[i]),-1);
 for(const [a,b]of [['1.0','1.0.0'],['v01.0a01','1.0alpha1'],['1.0-1','1.0post1'],['1.0preview1','1.0rc1'],['1.0+ABC_01','1.0+abc.1']])assert.equal(comparePackageVersions('PEP440',a,b),0);assert.throws(()=>comparePackageVersions('PEP440','1.0invalid!','1'));
});
test('Maven qualifiers, separators and null trimming follow the documented version order',()=>{
 for(const [a,b]of [['1-snapshot','1'],['1','1-sp'],['1-foo2','1-foo10'],['1-foo','1-1'],['1-1','1.1'],['1-sp-1','1-ga-1'],['1.7','1.K'],['5.zebra','5.aardvark']])assert.equal(comparePackageVersions('MAVEN',a,b),['1.7','5.zebra'].includes(a)?1:-1,a+' vs '+b);
 for(const [a,b]of [['1.foo','1-foo'],['1.ga','1'],['1-ga','1'],['1-0','1'],['1.0','1'],['1-a1','1-alpha-1'],['1.0-alpha1','1.0-ALPHA1'],['1.0.0-foo.0.0','1-foo'],['1.0.0-0.0.0','1']])assert.equal(comparePackageVersions('MAVEN',a,b),0,a+' = '+b);
 assert.equal(comparePackageVersions('MAVEN','1_0','1'),1);assert.equal(comparePackageVersions('MAVEN','1-1','1-ga-1'),1);
 const order=['1-alpha','1-a1','1-beta','1-b1','1-milestone','1-m1','1-rc','1-snapshot','1','1-sp'];for(let i=1;i<order.length;i++)assert.equal(comparePackageVersions('MAVEN',order[i-1],order[i]),-1);
});
