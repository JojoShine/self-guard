// A changed file cannot prove that an unrelated package or imported risk is safe.
export function canAutoVerifyRisk(finding:any,task:any){
 if(finding.kind!=='RISK'||finding.source!=='agent'||finding.assetId!==task.assetId)return false;
 let evidence:any;try{evidence=JSON.parse(finding.evidence)}catch{return false;}
 const p=task.parameters;
 if(task.template==='FILE_PERMISSION')return finding.externalId==='baseline:FILE_PERMISSION:'+p.path+'::'&&evidence.type==='FILE_PERMISSION'&&evidence.path===p.path&&evidence.expected===p.mode;
 if(task.template==='SERVICE_STATE')return finding.externalId==='baseline:SERVICE_STATE::'+p.service+':'&&evidence.type==='SERVICE_STATE'&&evidence.service===p.service&&evidence.expected===p.state;
 // Configuration findings deliberately do not expose expected secret values.
 // Their original security check must be independently confirmed by an analyst.
 return false;
}
