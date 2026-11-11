import {BadRequestException} from '@nestjs/common';
const linuxDistributions=new Set(['uos','kylin','openeuler','anolis','opencloudos','alinux','centos','ubuntu','debian','rocky','almalinux','rhel','alpine']);
type OSFields={os?:string;osDistribution?:string|null;osVersion?:string|null};
export function isLinuxAsset(asset:{os?:unknown;inventory?:unknown}):boolean{
 const inventory=asset.inventory;
 const observed=inventory&&typeof inventory==='object'&&'os' in inventory?inventory.os:undefined;
 // Agent platform evidence takes precedence; display names remain untouched.
 if(typeof observed==='string'&&observed.trim())return observed.trim().toLowerCase()==='linux';
 return typeof asset.os==='string'&&/^(?:linux\b|ubuntu\b|debian\b|centos\b|rocky\b|almalinux\b|red hat\b|rhel\b|alpine\b|fedora\b|opensuse\b|suse\b|kylin\b|uos\b|openeuler\b|anolis\b|opencloudos\b|alinux\b|阿里云\s*linux|银河麒麟|中标麒麟|统信)/i.test(asset.os.trim());
}
export function assetOperatingSystemData<T extends OSFields>(data:T,previous?:OSFields):T{
 const result={...data};
 if(data.os!==undefined&&previous&&data.os!==previous.os){if(data.osDistribution===undefined)result.osDistribution=null;if(data.osVersion===undefined)result.osVersion=null;}
 if(data.osDistribution!==undefined&&data.osDistribution!==previous?.osDistribution&&data.osVersion===undefined)result.osVersion=null;
 const distribution=result.osDistribution===undefined?previous?.osDistribution:result.osDistribution;
 const family=result.os??previous?.os;
 if(distribution){const expected=linuxDistributions.has(distribution)?'linux':distribution==='windows-server'?'windows':undefined;if(!expected||expected!==family)throw new BadRequestException('发行版与操作系统类型不一致，请重新选择操作系统');}
 return result;
}
