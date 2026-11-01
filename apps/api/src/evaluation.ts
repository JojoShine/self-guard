import {matchesOsvRange} from "./versions";
export function evaluateVulnerability(
  config: any,
  asset: { os: string; inventory: any },
) {
  if (asset.os !== config.os)
    return {
      status: "NOT_APPLICABLE",
      matched: false,
      evidence: "资产操作系统与规则不一致",
    };
  if(config.ecosystem){const parts=String(config.ecosystem).split(':');const distro=asset.inventory?.distribution;
    const expected=parts[0].toLowerCase(),version=parts[1]?.replace(/^v/,'');
    if(!distro?.id||!distro?.versionId)return {status:'UNKNOWN',matched:false,evidence:'缺少发行版版本，无法匹配公告生态'};
    if(distro.id.toLowerCase()!==expected||version&&distro.versionId.replace(/^v/,'')!==version)return {status:'NOT_APPLICABLE',matched:false,evidence:'公告发行版或版本不适用'};
  }
  if (!Array.isArray(asset.inventory?.packages))
    return {
      status: "UNKNOWN",
      matched: false,
      evidence: "缺少软件包清单，不能判断是否存在漏洞",
    };
  const sourceBased=/^(Debian|Ubuntu)(:|$)/.test(config.ecosystem||'');
  let missingSource=false;
  const matches = asset.inventory.packages.filter((p:any)=>{
    if(sourceBased&&(!p.origin||!p.sourceVersion)){missingSource=true;return false;}
    const name=sourceBased?p.origin:p.name,version=sourceBased?p.sourceVersion:p.version;
    return name===config.package&&(version===config.affectedVersion||config.ranges?.some((r:any)=>matchesOsvRange(version,r.events)));
  });
  return {
    status: matches.length===0&&(asset.inventory.packageCollection?.complete===false||missingSource)?"UNKNOWN":"COMPLETED",
    matched: matches.length > 0,
    evidence: JSON.stringify({
      package: config.package,
      affectedVersion: config.affectedVersion,
      advisory: config.advisory,
      fixedVersion: config.fixedVersion || null,
      ranges:config.ranges||null,
      matches: matches.length,
      observations:matches.slice(0,50).map((p:any)=>({name:p.name,version:p.version,origin:p.origin||null,sourceVersion:p.sourceVersion||null,architecture:p.architecture||null})),
      omittedObservations:Math.max(0,matches.length-50),
      missingSourceMetadata:missingSource,
      collection: asset.inventory.packageCollection||null,
    }),
  };
}
