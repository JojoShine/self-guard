import {it,expect} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';import {EvidenceView} from './EvidenceView';
it('explains actual package versions, range boundaries and Git source conditions',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={[{kind:'OSV_PACKAGE',ecosystem:'npm',package:'example',scheme:'SEMVER',versions:['1.0.1'],ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0.0'}]},{type:'GIT',repo:'https://github.com/example/code',events:[{fixed:'a'.repeat(40)}]}]}]} title="软件与版本适用条件"/>);
 for(const text of ['明确受影响版本','受影响版本范围','来源组件条件','初始版本起','来源代码仓库','语义版本规则','Git代码提交范围'])expect(html).toContain(text);
});

it('explains upstream advisory relationships without displaying them as equivalent vulnerability aliases',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{upstream:['CVE-2026-111497','CVE-2026-114148'],reportedEcosystem:'Ubuntu:24.04:LTS'}} title="厂商判断依据"/>);
 expect(html).toContain('厂商通告涉及的上游漏洞');expect(html).toContain('来源原始发行范围');expect(html).toContain('Ubuntu:24.04:LTS');
});

it('score version and vendor rating remain readable and cannot be mislabeled as software versions',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{scores:[{version:'3.1',source:'vendor',vector:'CVSS:3.1/AV:N',score:null}]}}/>);
 expect(html).toContain('评分规范与版本');expect(html).toContain('来源原始向量或评级');expect(html).toContain('CVSS:3.1/AV:N');expect(html).not.toContain('软件版本');
});

it('distinguishes referenced CVEs from the advisory and labels source data versions accurately',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{description:'厂商更新范围',component:{name:'kernel',version:'0:5.14.0-1.el9'},sources:[{provider:'OSV',version:'OSV/Rocky Linux@frozen',externalId:'RLSA-2026:1234',stale:false}],upstreamContext:[{externalId:'CVE-2026-12345',relationship:'UPSTREAM_REFERENCE',description:'独立CVE说明',knownExploited:true,scores:[{version:'3.1',score:9.8}],sources:[{provider:'CISA_KEV',version:'2026.10.31',externalId:'CVE-2026-12345'}]}]}}/>);
 for(const text of ['查看关联CVE的独立来源信息','情报数据版本','厂商更新通告引用','CISA在野利用目录','不证明本机已经被利用'])expect(html).toContain(text);
});

it('keeps provider names separate from version comparison algorithm names',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{sources:[{provider:'DEBIAN',version:'bookworm-frozen',externalId:'CVE-2026-12345'}]}}/>);expect(html).toContain('Debian厂商漏洞状态');expect(html).not.toContain('Debian/Ubuntu版本规则');expect(html).not.toContain('软件版本');
});
it('attributes supplemental vulnerability content to its exact source snapshot',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{description:'实际来源中的漏洞解释',descriptionSource:{provider:'NVD',externalId:'CVE-2026-12345',version:'NVD2026@fixed',snapshotId:'description-snapshot',sourceSha256:'a'.repeat(64),stale:false}}}/>);
 for(const text of ['漏洞内容','实际来源中的漏洞解释','漏洞内容来源','NVD漏洞资料','情报数据版本','来源快照编号','description-snapshot','CVE-2026-12345'])expect(html).toContain(text);
 expect(html).not.toContain('软件版本');
});

it('shows original advisory version precision with business labels',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{osvOriginalVersion:{modified:'2026-10-31T00:00:00.123456789Z',withdrawn:null}}}/>);
 for(const text of ['通告原始版本时间','来源修改时间','来源撤回时间','2026-10-31T00:00:00.123456789Z'])expect(html).toContain(text);
});
it('explains both the complete root and incremental original behind a composite finding',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{sources:[{provider:'OSV',snapshotId:'combined-snapshot',contentSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),sourceParts:[{role:'COMPLETE_BASE',snapshotId:'full-root',sourceSha256:'c'.repeat(64),artifactSha256:'d'.repeat(64),contentSha256:'e'.repeat(64)},{role:'VERIFIED_DELTA',snapshotId:'delta-original',sourceSha256:'f'.repeat(64),artifactSha256:'a'.repeat(64),contentSha256:'b'.repeat(64)}]}]}}/>);
 for(const text of ['本次完整来源的组成','完整基线原包','已校验的增量原件','来源快照编号','下载文件摘要','合并后完整内容摘要','full-root','delta-original'])expect(html).toContain(text);
});
it('explains the distinct annual and modification originals behind NVD candidate evidence',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{sources:[{provider:'NVD',sourceParts:[{role:'ANNUAL_SOURCE',snapshotId:'annual-original'},{role:'BASELINE_UPDATES',snapshotId:'baseline-update'},{role:'VERIFIED_DELTA',snapshotId:'current-update'}]}]}}/>);
 for(const text of ['官方年度原包','建立完整基线的官方修改源','已校验的增量原件','annual-original','baseline-update','current-update'])expect(html).toContain(text);
});
