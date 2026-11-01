import {BadRequestException} from '@nestjs/common';
const linuxDistributions=new Set(['uos','kylin','openeuler','anolis','opencloudos','alinux','centos','ubuntu','debian','rocky','almalinux','rhel','alpine']);
type OSFields={os?:string;osDistribution?:string|null;osVersion?:string|null};
export function assetOperatingSystemData<T extends OSFields>(data:T,previous?:OSFields):T{
 const result={...data};
 if(data.os!==undefined&&previous&&data.os!==previous.os){if(data.osDistribution===undefined)result.osDistribution=null;if(data.osVersion===undefined)result.osVersion=null;}
 if(data.osDistribution!==undefined&&data.osDistribution!==previous?.osDistribution&&data.osVersion===undefined)result.osVersion=null;
 const distribution=result.osDistribution===undefined?previous?.osDistribution:result.osDistribution;
 const family=result.os??previous?.os;
 if(distribution){const expected=linuxDistributions.has(distribution)?'linux':distribution==='windows-server'?'windows':undefined;if(!expected||expected!==family)throw new BadRequestException('发行版与操作系统类型不一致，请重新选择操作系统');}
 return result;
}
