import {BlockList,isIP} from 'node:net';
const excluded=new BlockList();
const privatePeers=new BlockList();
for(const [network,prefix] of [['10.0.0.0',8],['172.16.0.0',12],['192.168.0.0',16]] as const)privatePeers.addSubnet(network,prefix,'ipv4');
privatePeers.addSubnet('fc00::',7,'ipv6');
for(const [network,prefix] of [['0.0.0.0',8],['127.0.0.0',8],['169.254.0.0',16],['224.0.0.0',4],['240.0.0.0',4]] as const)excluded.addSubnet(network,prefix,'ipv4');
for(const [network,prefix] of [['::',128],['::1',128],['fe80::',10],['ff00::',8]] as const)excluded.addSubnet(network,prefix,'ipv6');
export function canonicalDiscoveryAddress(value:string):string|undefined{
 const family=isIP(value);if(!family||value.includes('%'))return;
 if(family===4)return value;
 const canonical=new URL('http://['+value+']/').hostname.slice(1,-1);
 const mapped=/^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(canonical);
 if(!mapped)return canonical;
 const high=parseInt(mapped[1],16),low=parseInt(mapped[2],16);return [high>>8,high&255,low>>8,low&255].join('.');
}
export function usableDiscoveryAddress(value:string){const address=canonicalDiscoveryAddress(value);if(!address)return false;const family=isIP(address)===4?'ipv4':'ipv6';return privatePeers.check(address,family)&&!excluded.check(address,family);}
export function localDiscoveryAddresses(inventory:unknown,hostIp:string|null){
 const addresses=new Set<string>();const add=(value:unknown)=>{if(typeof value==='string'){const address=canonicalDiscoveryAddress(value);if(address)addresses.add(address)}};add(hostIp);
 // Listening addresses describe the reporting host, never a newly discovered host.
 if(inventory&&typeof inventory==='object'&&'ports' in inventory&&Array.isArray(inventory.ports))for(const row of inventory.ports)if(row&&typeof row==='object'&&'address' in row)add(row.address);
 return addresses;
}
