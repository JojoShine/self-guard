export type SensorFilters={assetId?:string;sensorId?:string;eventType?:string;flowId?:string;from?:string;to?:string};
export type SensorLocation={filters:SensorFilters;recordId?:string;view?:'configuration';page:number;size:number};
const filterKeys=['assetId','sensorId','eventType','flowId','from','to'] as const;
export function readSensorLocation(hash:string):SensorLocation{
 const query=new URLSearchParams(hash.split('?')[1]||'');
 const page=Number(query.get('page')),size=Number(query.get('pageSize'));
 return {filters:Object.fromEntries(filterKeys.flatMap(key=>query.get(key)?[[key,query.get(key)!]]:[])),recordId:query.get('recordId')||undefined,...(query.get('view')==='configuration'?{view:'configuration' as const}:{}),page:Number.isSafeInteger(page)&&page>0?page:1,size:Number.isInteger(size)&&size>=1&&size<=100?size:20};
}
export function sensorHref(state:SensorLocation){const params=sensorEventQuery(state);if(!state.filters.eventType)params.delete('eventType');if(state.recordId)params.set('recordId',state.recordId);if(state.view)params.set('view',state.view);return '#network-sensors?'+params;}
export function sensorEventQuery(state:SensorLocation){return new URLSearchParams({...Object.fromEntries(Object.entries(state.filters).filter((entry):entry is [string,string]=>typeof entry[1]==='string'&&entry[1]!=='')),...(!state.filters.eventType&&!state.filters.flowId?{eventType:'flow'}:{}),page:String(state.page),pageSize:String(state.size)});}
export function sensorFilterTime(value:string|undefined){if(!value)return undefined;const date=new Date(/(?:Z|[+-]\d{2}:\d{2})$/.test(value)?value:value+'Z');return Number.isNaN(date.getTime())?undefined:date.toISOString();}
export function sensorDateValue(value:string|undefined){if(!value)return undefined;const date=new Date(value);return Number.isNaN(date.getTime())?undefined:date.toISOString().slice(0,19);}
