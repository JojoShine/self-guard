type Choice={value:string;label:string;family:string;group:string;versions:string[]};
const linux=(value:string,label:string,versions:string[],domestic=false):Choice=>({value,label,versions,family:'linux',group:domestic?'国产主流 Linux':'常见 Linux 发行版'});
// Registration choices describe the asset; they are independent of feed/Agent compatibility.
export const assetOSChoices:Choice[]=[
 linux('uos','统信 UOS',['20','25'],true),linux('kylin','银河麒麟',['V10','V11'],true),linux('openeuler','openEuler',['20.03','22.03','24.03'],true),linux('anolis','龙蜥 Anolis OS',['7','8','23'],true),linux('opencloudos','OpenCloudOS',['8','9'],true),linux('alinux','阿里云 Linux',['2','3'],true),
 linux('centos','CentOS / CentOS Stream',['7','8','9','10']),linux('ubuntu','Ubuntu',['20.04','22.04','24.04']),linux('debian','Debian',['11','12','13']),linux('rocky','Rocky Linux',['8','9','10']),linux('almalinux','AlmaLinux',['8','9','10']),linux('rhel','Red Hat Enterprise Linux',['7','8','9','10']),linux('alpine','Alpine Linux',['3.19','3.20','3.21','3.22']),
 {value:'windows',label:'Windows',family:'windows',group:'其他系统',versions:['10','11']},{value:'windows-server',label:'Windows Server',family:'windows',group:'其他系统',versions:['2016','2019','2022','2025']},{value:'darwin',label:'macOS',family:'darwin',group:'其他系统',versions:['13','14','15','26']},{value:'linux',label:'Linux（发行版待识别）',family:'linux',group:'其他系统',versions:[]},{value:'other',label:'其他 / 待识别',family:'other',group:'其他系统',versions:[]}
];
function labelFor(id:string,version?:string|null){const choice=assetOSChoices.find(c=>c.value===id);const v=version?.trim();return (choice?.label||id)+(v?' '+(id==='uos'&&!/^v/i.test(v)?'V'+v:v):'');}
export function assetOSDisplay(record:Record<string,any>):{label:string;source:'agent'|'declared'|'family'}{
 const inventory=record.inventory||{},distribution=inventory.distribution;
 if(inventory.distributionCollection?.complete===true&&typeof distribution?.id==='string'&&distribution.id&&typeof distribution?.versionId==='string'&&distribution.versionId)return {label:labelFor(distribution.id,distribution.versionId),source:'agent'};
 if(record.osDistribution)return {label:labelFor(record.osDistribution,record.osVersion),source:'declared'};
 return {label:labelFor(record.os||'other',record.osVersion),source:record.osVersion?'declared':'family'};
}
export function assetOSFormValues(record:Record<string,any>){const choice=record.osDistribution||record.os||'other';return {os:record.os,osChoice:assetOSChoices.some(c=>c.value===choice)?choice:'legacy:'+choice,osDistribution:record.osDistribution??null,osVersion:record.osVersion??null};}
export function assetOSPayload(values:Record<string,any>){const id=values.osChoice||values.os||'other',choice=assetOSChoices.find(c=>c.value===id);return {os:choice?.family||(id.startsWith('legacy:')?id.slice(7):id),osDistribution:choice&&choice.value!==choice.family?choice.value:null,osVersion:values.osVersion||null};}
