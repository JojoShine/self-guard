import {describe,it,expect} from 'vitest';
import {installationCommand,offlineInstallationProfile} from './agent-installation';
describe('installation command',()=>{
 it('pins executable digest and trust root without exposing the enrollment ticket',()=>{
  const command=installationCommand({id:'12345678-1234-1234-1234-123456789abc',profile:{server:'https://guard.example'},release:{sha256:'a'.repeat(64)},trustRoot:'test-public-root'});
  expect(command).toContain('sha256sum -c');expect(command).toContain('read -r -s');expect(command).toContain('curl --config -');expect(command).toContain('--proto');expect(command).toContain('--install');expect(command).not.toContain('ENROLLMENT_TOKEN');expect(command).not.toContain('curl -k');
 });
 it('rejects untrusted values before producing shell code',()=>{
  expect(()=>installationCommand({id:'x; touch /tmp/oops',profile:{server:'https://guard.example'},release:{sha256:'a'.repeat(64)},trustRoot:'test-public-root'})).toThrow();
 });
 it('uses an explicit private CA for both download and installation',()=>{
  const ca='-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----';
  const command=installationCommand({id:'12345678-1234-1234-1234-123456789abc',profile:{server:'https://guard.example',caCertificate:ca},release:{sha256:'a'.repeat(64)},trustRoot:'test-public-root'});
  expect(command).toContain('--cacert');expect(command).toContain('AGENT_CA_FILE=');expect(command).toContain('--max-time 300');
 });
 it('uses explicit proxy for download and runtime even if the host has a bypass list',()=>{const command=installationCommand({id:'12345678-1234-1234-1234-123456789abc',profile:{server:'https://guard.example',stateDir:'/var/lib/selfguard-agent-production',proxyUrl:'http://proxy.example:3128'},release:{sha256:'a'.repeat(64)},trustRoot:'test-public-root'});expect(command).toContain("--noproxy");expect(command).toContain('AGENT_PROXY_URL=');expect(command).toContain('AGENT_INSTALL_STATE_DIR=');});
});
describe('offline preparation profile',()=>{
 it('keeps authorized local configuration while excluding platform ownership, identities and tickets',()=>{
  const task={release:{version:'0.4.0'},profile:{server:'https://guard.example',stateDir:'/var/lib/selfguard-agent',collectionRoot:'/srv/app',fimPaths:['/srv/app/config'],applicationInputs:[{format:'GO_BINARY',path:'/srv/app/service'}],proxyMode:'DIRECT',executorEnabled:true,allowedRoot:'/srv/app',allowedServices:[],cpuQuotaPercent:20,caCertificate:'public-ca',releaseId:'release-id',targetAssetId:'asset-id',business:'private-business',tags:['private-tag'],ticket:'private-ticket',token:'private-token',identity:'private-identity',futurePlatformSecret:'private-secret'}};
  const output=offlineInstallationProfile(task)!;expect(output.server).toBe(task.profile.server);expect(output.executorEnabled).toBe(true);expect(output.applicationInputs).toEqual(task.profile.applicationInputs);expect(output.cpuQuotaPercent).toBe(20);expect(output.caCertificate).toBe('public-ca');expect(JSON.stringify(output)).not.toContain('private-');expect(output).not.toHaveProperty('releaseId');expect(output).not.toHaveProperty('targetAssetId');
 });
 it('does not export a newer configuration contract for old releases',()=>{
  expect(offlineInstallationProfile({release:{version:'0.3.6'},profile:{server:'https://guard.example'}})).toBeUndefined();expect(offlineInstallationProfile({release:{version:'0.4.1-rc.8'},profile:{server:'https://guard.example'}})?.server).toBe('https://guard.example');
 });
});
import {supportsHTTPAgent} from './agent-installation';
it('allows explicit HTTP platform commands only with supported release selection',()=>{expect(supportsHTTPAgent('0.4.9')).toBe(false);expect(supportsHTTPAgent('0.4.10')).toBe(true);expect(supportsHTTPAgent('0.5.0')).toBe(true)});
it('generates an explicit HTTP bootstrap without forcing HTTPS',()=>{const command=installationCommand({id:'12345678-1234-1234-1234-123456789abc',profile:{server:'http://platform.example:8080'},release:{sha256:'a'.repeat(64)},trustRoot:'test-public-root'});expect(command).toContain('http://platform.example:8080');expect(command).toContain('=http');expect(command).not.toContain('=https');});
