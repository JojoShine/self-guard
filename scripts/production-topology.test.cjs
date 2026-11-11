const{test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),yaml=require(require.resolve('yaml',{paths:[path.join(__dirname,'../apps/api'),process.cwd()]}));
const root=path.resolve(__dirname,'..');
test('production monitoring topology has no retired WAF runtime or required WAF secret',()=>{
 const c=yaml.parse(fs.readFileSync(path.join(root,'compose.prod.yaml'),'utf8'));
 assert.deepEqual(Object.keys(c.services).sort(),['app','backup','migrate','postgres']);
 for(const key of ['WAF_TOKEN','HOST_WAF_IMAGE','WAF_TEST_URL'])assert.equal(c.services.app.environment[key],undefined);
 assert.equal(c.services.app.environment.WAF_RULE_RUNTIME_ENABLED,'false');
 assert.equal(c.services.app.image,c.services.migrate.image);
 assert.ok(c.services.app.ports.every(p=>p.startsWith('127.0.0.1:')));
 assert.equal(c.services.postgres.ports,undefined);
});
