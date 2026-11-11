import {it,expect} from 'vitest';
import {assetOSChoices,assetOSDisplay,assetOSFormValues,assetOSPayload,isLinuxAsset} from './asset-os';
it('enables Linux actions for real distribution labels while respecting the observed platform',()=>{
 for(const os of ['Ubuntu 22.04','CentOS Linux 7','银河麒麟高级服务器 V10','Kylin V10','统信 UOS V20','linux'])expect(isLinuxAsset({os})).toBe(true);
 expect(isLinuxAsset({os:'Custom OS',inventory:{os:'linux'}})).toBe(true);
 for(const os of ['windows','darwin','freebsd'])expect(isLinuxAsset({os:'Ubuntu 22.04',inventory:{os}})).toBe(false);
 expect(isLinuxAsset({os:'Windows Subsystem for Linux'})).toBe(false);
 expect(assetOSDisplay({os:'Ubuntu 22.04'}).label).toBe('Ubuntu 22.04');
});
it('provides domestic and mainstream distributions without using them as OS family values',()=>{for(const id of ['uos','kylin','openeuler','anolis','opencloudos','alinux','centos','ubuntu','debian'])expect(assetOSChoices.find(row=>row.value===id)?.family).toBe('linux');});
it('uses actual collected OS over registration without filling missing actual versions from manual data',()=>{const row={os:'linux',osDistribution:'uos',osVersion:'20',inventory:{distribution:{id:'ubuntu',versionId:'24.04'},distributionCollection:{complete:true}}};expect(assetOSDisplay(row)).toMatchObject({label:'Ubuntu 24.04',source:'agent'});expect(assetOSDisplay({...row,inventory:{distribution:{id:'ubuntu'},distributionCollection:{complete:false}}})).toMatchObject({label:'统信 UOS V20',source:'declared'});});
it('preserves unknown actual distributions and legacy registered values honestly',()=>{expect(assetOSDisplay({os:'linux',inventory:{distribution:{id:'vendor-linux',versionId:'1.2'},distributionCollection:{complete:true}}}).label).toBe('vendor-linux 1.2');const values=assetOSFormValues({os:'Legacy Linux 6',osDistribution:null,osVersion:null});expect(assetOSPayload(values)).toEqual({os:'Legacy Linux 6',osDistribution:null,osVersion:null});});
it('submits Linux family separately and clears previous versions when switching OS',()=>{expect(assetOSPayload({osChoice:'ubuntu',osVersion:'24.04'})).toEqual({os:'linux',osDistribution:'ubuntu',osVersion:'24.04'});expect(assetOSPayload({osChoice:'windows-server',osVersion:'2022'})).toEqual({os:'windows',osDistribution:'windows-server',osVersion:'2022'});});
it('does not combine incomplete Agent versions with registered versions or copy Agent facts into edits',()=>{const row={os:'linux',inventory:{distribution:{id:'ubuntu'},distributionCollection:{complete:true}}};expect(assetOSDisplay(row).source).toBe('family');expect(assetOSFormValues({...row,inventory:{distribution:{id:'ubuntu',versionId:'24.04'},distributionCollection:{complete:true}}})).toMatchObject({osChoice:'linux',osDistribution:null,osVersion:null});});
