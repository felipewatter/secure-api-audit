const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createServer}=require('node:http');
const {validateTarget,isSafeAddress,probe}=require('../dist/src/network.js');
const opt={allowHttp:false,allowPrivate:false,timeoutMs:3000};
test('SSRF: internal and reserved IP ranges fail closed',()=>{
  for(const ip of ['127.0.0.1','10.2.3.4','172.17.1.1','192.168.0.1','169.254.169.254','0.0.0.0','100.64.0.1','198.51.100.1','203.0.113.10','224.0.0.1','::1']){
    assert.equal(isSafeAddress(ip),false,ip);
  }
  assert.equal(isSafeAddress('8.8.8.8'),true);
  assert.equal(isSafeAddress('1.1.1.1'),true);
});
test('URL parser rejects unsafe schemes, credentials and loopback by default',()=>{
  const rejected=['http://example.com/','file:///etc/passwd','https://localhost/','https://127.0.0.1/','https://user:pass@example.com/','https://169.254.169.254/latest','https://[::1]/'];
  for(const url of rejected)assert.throws(()=>validateTarget(url,opt),url);
  assert.equal(validateTarget('https://example.com/api',opt).protocol,'https:');
});
test('internal HTTP targets require two explicit opt-ins',()=>{
  assert.throws(()=>validateTarget('http://127.0.0.1:8080',opt));
  assert.throws(()=>validateTarget('http://127.0.0.1:8080',{...opt,allowHttp:true}));
  assert.equal(validateTarget('http://127.0.0.1:8080',{...opt,allowPrivate:true,allowHttp:true}).hostname,'127.0.0.1');
});
test('TLS verification cannot be disabled',()=>{
  const old=process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try{process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';assert.throws(()=>validateTarget('https://example.com',opt),/TLS/);}finally{if(old===undefined)delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;else process.env.NODE_TLS_REJECT_UNAUTHORIZED=old;}
});
test('live HTTP probe reads headers without redirecting or downloading response body',async()=>{
  let visits=0;
  const server=createServer((req,res)=>{visits++;res.writeHead(302,{'Location':'http://127.0.0.1:2/other','X-Test':'hello'});res.end('secret-token-body');});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{
    const url=new URL('http://127.0.0.1:'+server.address().port+'/api');
    const response=await probe(url,{method:'GET'},{allowHttp:true,allowPrivate:true,timeoutMs:3000});
    assert.equal(response.status,302);assert.equal(response.headers['x-test'],'hello');assert.equal(visits,1);
  }finally{await new Promise(r=>server.close(r));}
});
