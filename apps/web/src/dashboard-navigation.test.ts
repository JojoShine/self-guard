import {describe,it,expect} from 'vitest';
import {dashboardDestination} from './dashboard-navigation';

describe('dashboard module destinations',()=>{
 it('opens matching menu pages for metric, health and work groups',()=>{
  for(const [group,page] of Object.entries({overviewAssets:'assets',overviewRisks:'risks',overviewAlerts:'alerts',overviewTasks:'tasks',overviewCritical:'risks',overviewIncidents:'incidents',wafEvents:'waf-events',wafBlocked:'waf-events',wafNodes:'nodes',online:'assets',stale:'assets',neverSeen:'assets',archived:'assets',approvals:'approvals',myTasks:'tasks',assigned:'findings',overdue:'findings',verifyFindings:'findings',verifyTasks:'tasks',succeeded:'tasks',failed:'tasks',rolledBack:'tasks',businessAssets:'assets',businessRisks:'risks'}))expect(dashboardDestination(group)).toBe(page);
 });
 it('uses the workbench for an unrecognised group',()=>{
  expect(dashboardDestination('constructor')).toBe('overview');
 });
});
