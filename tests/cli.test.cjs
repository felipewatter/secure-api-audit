const {test}=require('node:test');
const assert=require('node:assert/strict');
const {execFileSync,spawnSync}=require('node:child_process');
const {join}=require('node:path');
const cli=join(__dirname,'..','dist','bin','index.js');
const {parseArgs}=require('../dist/bin/index.js');
test('CLI options parse documented flags, legacy equal syntax',()=>{
  const args=parseArgs(['--url=https://example.com/a','--aggressive','--timeout=5000','--format=json','--fail-on=medium'],{});
  assert.equal(args.url,'https://example.com/a');assert.equal(args.aggressive,true);assert.equal(args.timeoutMs,5000);assert.equal(args.format,'json');
});
test('authentication token supplied via environment',()=>{
  const args=parseArgs(['--url','https://example.com','--token-env','PRIVATE_TOKEN'],{PRIVATE_TOKEN:'secret'});
  assert.equal(args.token,'secret');
});
test('CLI rejects invalid arguments and token newlines',()=>{
  for(const a of [['--url'],['--target','oops'],['--url','example.com','--timeout','1'],['--url','https://example.com','--format','xml']])assert.throws(()=>parseArgs(a,{}));
  assert.throws(()=>parseArgs(['--url','https://example.com','--token','bad\nvalue'],{}));
});
test('CLI --help and --version run without probing',()=>{
  assert.match(execFileSync(process.execPath,[cli,'--help'],{encoding:'utf8'}),/allow-private/);
  assert.match(execFileSync(process.execPath,[cli,'--version'],{encoding:'utf8'}),/1.1.0/);
});
test('CLI operational failure exits 2 without emitting secret',()=>{
  const result=spawnSync(process.execPath,[cli,'--url','https://127.0.0.1/','--token','S3cr3t'],{encoding:'utf8',timeout:5000});
  assert.equal(result.status,2);assert.ok(!result.stderr.includes('S3cr3t'));
});
