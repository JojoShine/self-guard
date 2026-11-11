import {it,expect} from 'vitest';
import {dashboardDestination} from './dashboard-navigation';
it('core metrics open corresponding scoped modules',()=>{for(const [group,page] of Object.entries({overviewAssets:'assets',overviewInstances:'database-instances',overviewNetworkRisks:'network-risks?status=OPEN',overviewNetworkAlerts:'network-alerts?status=OPEN',overviewDataAlerts:'data-alerts?status=OPEN',overviewAccess:'data-access'}))expect(dashboardDestination(group)).toBe(page);});
it('obsolete or unknown dashboard actions do not navigate to retired capabilities',()=>{for(const group of ['constructor','wafNodes','overviewTasks','approvals'])expect(dashboardDestination(group)).toBe('overview')});

it('pending issue metrics preserve the OPEN filter on their destination',()=>{
 expect(dashboardDestination('overviewNetworkRisks')).toBe('network-risks?status=OPEN');
 expect(dashboardDestination('overviewNetworkAlerts')).toBe('network-alerts?status=OPEN');
 expect(dashboardDestination('overviewDataAlerts')).toBe('data-alerts?status=OPEN');
});
