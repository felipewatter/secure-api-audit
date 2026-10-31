const {test}=require('node:test');
const assert=require('node:assert/strict');
const {auditAPI}=require('../dist/src/auditor.js');
const opts={timeoutMs:1000,allowPrivate:false,allowHttp:false,aggressive:false};
const find=(res,id)=>res.findings.find(f=>f.id===id);
test('anonymous unauthorized, bearer authorized: authentication distinguished',async()=>{
  const calls=[];
  const requestProbe=async(url,req)=>{calls.push(req);if(req.headers?.Origin)return {status:200,headers:{'access-control-allow-origin':'https://audit-origin.invalid','x-content-type-options':'nosniff','strict-transport-security':'max-age=31536000'}};if(req.headers?.Authorization)return {status:200,headers:{'x-content-type-options':'nosniff','strict-transport-security':'max-age=31536000','cache-control':'no-store'}};return {status:401,headers:{}};};
  const r=await auditAPI('https://api.example.com/data','redacted-secret',{...opts,requestProbe});
  assert.equal(r.checks,3);assert.equal(r.baselineStatus,401);assert.equal(r.authenticatedStatus,200);
  assert.ok(find(r,'auth-confirmed'));assert.ok(find(r,'cors-reflected-origin'));assert.ok(find(r,'cors-no-vary'));
  assert.equal(calls[0].headers?.Authorization,undefined);assert.equal(calls[1].headers.Authorization,'Bearer redacted-secret');
  assert.ok(!JSON.stringify(r).includes('redacted-secret'));
});
test('public endpoint is not automatically marked as missing authorization proof',async()=>{
  const requestProbe=async()=>({status:200,headers:{'strict-transport-security':'max-age=31536000','x-content-type-options':'nosniff'}});
  const r=await auditAPI('https://example.com','secret',{...opts,requestProbe});
  assert.ok(find(r,'public-access'));assert.ok(!find(r,'auth-confirmed'));
});
test('unknown authentication status is explicitly inconclusive',async()=>{
  const r=await auditAPI('https://example.com',undefined,{...opts,requestProbe:async()=>({status:404,headers:{}})});
  assert.ok(find(r,'auth-inconclusive'));
});
test('wildcard + credentials flagged as inconsistent, no redirect followed',async()=>{
  const r=await auditAPI('https://example.com',undefined,{...opts,requestProbe:async()=>({status:302,headers:{'access-control-allow-origin':'*','access-control-allow-credentials':'true'}})});
  assert.ok(find(r,'cors-wildcard'));assert.ok(find(r,'cors-credential-wildcard'));assert.ok(find(r,'redirect'));assert.equal(r.checks,2);
});
test('aggressive mode adds only safe GET and OPTIONS probes',async()=>{
  const calls=[];
  const requestProbe=async(url,req)=>{calls.push({url:url.href,method:req.method??'GET'});return {status:url.pathname.includes('__audit_probe_')?200:200,headers:{}};};
  const r=await auditAPI('https://example.com/api/data?token=private',undefined,{...opts,aggressive:true,requestProbe});
  assert.equal(r.checks,4);assert.deepEqual(calls.map(x=>x.method),['GET','GET','OPTIONS','GET']);assert.ok(find(r,'missing-path-public'));assert.ok(!JSON.stringify(r).includes('token=private'));
  assert.equal(calls[3].url.includes('token=private'),false);
});
test('invalid probe status fails rather than silently passing',async()=>{
  await assert.rejects(()=>auditAPI('https://example.com',undefined,{...opts,requestProbe:async()=>({status:0,headers:{}})}),/Resposta HTTP inválida/);
});
