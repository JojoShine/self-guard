const destinations:Record<string,string>={
 overviewAssets:'assets',overviewRisks:'risks',overviewAlerts:'alerts',overviewTasks:'tasks',overviewCritical:'risks',overviewIncidents:'incidents',
 wafEvents:'waf-events',wafBlocked:'waf-events',wafNodes:'nodes',
 online:'assets',stale:'assets',neverSeen:'assets',archived:'assets',
 approvals:'approvals',myTasks:'tasks',assigned:'findings',overdue:'findings',verifyFindings:'findings',verifyTasks:'tasks',
 succeeded:'tasks',failed:'tasks',rolledBack:'tasks',businessAssets:'assets',businessRisks:'risks',
};
export function dashboardDestination(group:string){return Object.hasOwn(destinations,group)?destinations[group]:'overview';}
