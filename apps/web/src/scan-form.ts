export function scanScopeFromForm(value:any){
 const keys:Record<string,string>={assets:'assetIds',businesses:'businessIds',tags:'tags'},key=keys[value.scopeMode];
 if(value.scopeMode!=='all'&&(!key||!value.targets?.length))throw Error('请选择需要检查的明确目标');
 const expiresAt=value.excludeUntil?value.excludeUntil+'T23:59:59.999Z':undefined;
 return {allAuthorized:value.scopeMode==='all',include:value.scopeMode==='all'?[]:[{[key]:value.targets}],exclude:[...(value.excludeAssets?.length?[{assetIds:value.excludeAssets,...(expiresAt?{expiresAt}:{})}]:[]),...(value.excludeTags?.length?[{tags:value.excludeTags,...(expiresAt?{expiresAt}:{})}]:[])],inventoryMaxAgeHours:value.inventoryMaxAgeHours||24};
}
export const scanReasonNames:Record<string,string>={EXECUTION_IDENTITY_SCOPE:'不在执行身份授权范围',ARCHIVED:'资产已归档',EXCLUDED:'符合排除条件',MISSING_INVENTORY:'尚无采集清单',INVALID_INVENTORY_TIME:'采集时间无效',STALE_INVENTORY:'采集清单已过期'};
