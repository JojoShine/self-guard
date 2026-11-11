import {z} from 'zod';

export const securityDomainInput=z.enum(['NETWORK','DATA','UNCLASSIFIED']);
export type SecurityDomain=z.infer<typeof securityDomainInput>;
const networkSources=new Set(['suricata','vulnerability','active-scan','agent-fim','host-resource-monitor']);
const databaseRule=z.object({type:z.enum(['DATABASE_SECURITY','DATABASE_AUTH','DATABASE_CLEARTEXT','DATABASE_ACTIVITY','DATABASE_ACCESS'])}).passthrough();

// Rule configuration must come from the server's rule record, never finding evidence.
export function findingSecurityDomain(source:string,trustedRuleConfig?:unknown):SecurityDomain {
 if(networkSources.has(source))return 'NETWORK';
 if(source==='database-security'||source==='database-monitor'||source==='access-observation'||databaseRule.safeParse(trustedRuleConfig).success)return 'DATA';
 return 'UNCLASSIFIED';
}
