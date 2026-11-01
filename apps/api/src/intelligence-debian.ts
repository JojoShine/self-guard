import {createHash} from 'node:crypto';import {z} from 'zod';import type {IntelligenceRecord} from './intelligence-normalize';
export const debianReleases={bookworm:'12',trixie:'13'} as const;
export type DebianRelease=keyof typeof debianReleases;
export function normalizeDebianPackage(name:string,raw:unknown,release:DebianRelease):IntelligenceRecord[]{
 z.string().regex(/^[a-z0-9][a-z0-9+.-]{0,199}$/).parse(name);const advisories=z.record(z.string(),z.unknown()).parse(raw),records:IntelligenceRecord[]=[];
 for(const [identity,value]of Object.entries(advisories)){
  const entry=z.record(z.string(),z.any()).parse(value),details=entry.releases?.[release];if(!details)continue;
  z.string().min(1).max(200).parse(identity);const vendor=z.record(z.string(),z.any()).parse(details),fixed=typeof vendor.fixed_version==='string'?vendor.fixed_version:null;
  const status=vendor.status==='resolved'&&fixed==='0'?'NOT_AFFECTED':vendor.status==='resolved'&&fixed?'FIXED':vendor.status==='open'?'AFFECTED':'UNKNOWN';
  if(fixed!==null)z.string().max(4096).parse(fixed);const ecosystem='Debian:'+debianReleases[release],description=z.string().max(100000).parse(entry.description||identity),source={...entry,releases:{[release]:vendor}},serialized=JSON.stringify(source);if(Buffer.byteLength(serialized)>2*1024*1024)throw Error('单条Debian情报超过2MiB限制');
  records.push({externalId:'DEBIAN:'+release+':'+name+':'+identity,aliases:[identity],summary:identity+' · '+name+' · Debian '+debianReleases[release],details:description,severity:null,scores:[],purpose:'PACKAGE',affected:[{kind:'DEBIAN_STATUS',ecosystem,distribution:'debian',release:debianReleases[release],codename:release,package:name,scheme:'DEBIAN',status,fixed:status==='FIXED'?fixed:null,repositories:vendor.repositories||{},vendorStatus:vendor.status,urgency:vendor.urgency||null}],packages:[ecosystem+':'+name],references:[{type:'ADVISORY',url:'https://security-tracker.debian.org/tracker/'+encodeURIComponent(identity)}],modifiedAt:null,withdrawnAt:null,metadata:{scope:entry.scope||'unknown',urgency:vendor.urgency||null,vendorStatus:vendor.status,nodsa:vendor.nodsa||null,nodsaReason:vendor.nodsa_reason||null},rawSha256:createHash('sha256').update(serialized).digest('hex')});
 }
 return records;
}
