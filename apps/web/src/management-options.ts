import {api} from './api';
// These editors are global management actions. The server checks global scope
// before returning real asset and business identities.
export async function managementOptions(){
 const data=await api('/scan-plans/options');
 return {assets:data.assets.map((a:any)=>({value:a.id,label:a.hostname+(a.business?' · '+a.business:'')})),businesses:data.businesses.map((b:any)=>({value:b.name,label:b.name}))};
}
