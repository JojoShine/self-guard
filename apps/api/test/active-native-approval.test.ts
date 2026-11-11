import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {isApprovedProbeTemplate,isProbeValidationCurrent,activeSourcePins} from '../src/active-scan-pins';
import {activeScanChoices} from '../src/active-scans';

const raw='{"id":"owned-response-rule"}',sha256=createHash('sha256').update(raw).digest('hex');
const native={sourceKind:'NUCLEI_LIBRARY',status:'APPROVED',configHash:'a'.repeat(64),approvalHash:'a'.repeat(64),validatedHash:'a'.repeat(64),definition:{rule:{nativeTemplate:{raw,sha256,engineVersion:'3.11.1'}}},validationReport:{passed:true,validationKind:'NATIVE_TEMPLATE_COMPILE',templateSha256:sha256,engineVersion:'3.11.1',samples:[]}};
test('library approval binds original execution bytes and exact engine compile proof without calling it sample validation',()=>{
 assert.equal(isApprovedProbeTemplate(native),true);
 assert.equal(isProbeValidationCurrent({...native,status:'DRAFT',approvalHash:null}),true);
 assert.equal(isApprovedProbeTemplate({...native,status:'DRAFT',approvalHash:null}),false);
 for(const row of [{...native,sourceKind:'LOCAL'},{...native,status:'DISABLED'},{...native,validatedHash:'b'.repeat(64)},{...native,validationReport:{...native.validationReport,validationKind:'SAMPLES'}},{...native,validationReport:{...native.validationReport,engineVersion:'3.11.0'}},{...native,validationReport:{...native.validationReport,templateSha256:'b'.repeat(64)}},{...native,definition:{rule:{nativeTemplate:{...native.definition.rule.nativeTemplate,raw:raw+' '}}}}])assert.equal(isApprovedProbeTemplate(row),false);
 assert.equal(isApprovedProbeTemplate({...native,sourceKind:'LOCAL',definition:{rule:{conditions:[]}},validationReport:{passed:true,samples:[{passed:true}]}}),true);
});
test('generic approved rule selections are bounded at 5000 while endpoints retain their existing limit',()=>{
 const id=(n:number)=>'00000000-0000-4000-8000-'+n.toString(16).padStart(12,'0'),templateIds=Array.from({length:5000},(_,i)=>id(i+1)),endpointIds=[id(900)];
 assert.ok(activeScanChoices.safeParse({templateIds,endpointIds,scope:{include:[{assetIds:[id(901)]}]}}).success);
 assert.ok(activeSourcePins.safeParse({endpoints:[{id:id(900),version:1,approvalHash:'a'.repeat(64)}],templates:templateIds.map(id=>({id,version:1,approvalHash:'a'.repeat(64)}))}).success);
 assert.equal(activeScanChoices.safeParse({templateIds:[...templateIds,id(5001)],endpointIds,scope:{include:[{assetIds:[id(901)]}]}}).success,false);
 assert.equal(activeScanChoices.safeParse({templateIds:[id(1)],endpointIds:Array.from({length:51},(_,i)=>id(i+600)),scope:{include:[{assetIds:[id(901)]}]}}).success,false);
});
