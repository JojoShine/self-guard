import {test} from 'node:test';
import assert from 'node:assert/strict';
import {findingSecurityDomain,securityDomainInput} from '../src/security-domain';
test('only explicit sources determine a primary domain, never a generic log or free text',()=>{
 for(const source of ['vulnerability','active-scan','agent-fim'])assert.equal(findingSecurityDomain(source),'NETWORK');
 assert.equal(findingSecurityDomain('database-security'),'DATA');
 assert.equal(findingSecurityDomain('access-observation'),'DATA');
 for(const source of ['agent-log','agent','correlation','custom','mysql'])assert.equal(findingSecurityDomain(source),'UNCLASSIFIED');
 assert.equal(findingSecurityDomain('custom',{message:'database-security',instanceId:'known'}),'UNCLASSIFIED');
});
test('trusted database rule configuration can classify agent alerts without misclassifying database CVEs',()=>{
 for(const type of ['DATABASE_SECURITY','DATABASE_AUTH','DATABASE_CLEARTEXT','DATABASE_ACTIVITY','DATABASE_ACCESS'])assert.equal(findingSecurityDomain('agent-log',{type}),'DATA');
 assert.equal(findingSecurityDomain('vulnerability',{type:'DATABASE_ACTIVITY'}),'NETWORK');
 for(const config of [null,[],{type:'OTHER'},'DATABASE_AUTH'])assert.equal(findingSecurityDomain('agent-log',config),'UNCLASSIFIED');
});
test('domain filter rejects unknown names instead of silently falling back to another domain',()=>{
 for(const value of ['NETWORK','DATA','UNCLASSIFIED'])assert.equal(securityDomainInput.parse(value),value);
 for(const value of ['ALL','network','',null])assert.equal(securityDomainInput.safeParse(value).success,false);
});
