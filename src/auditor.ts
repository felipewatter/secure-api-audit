import {randomUUID} from 'node:crypto';
import {header, hasHeader} from './utils';
import {probe, validateTarget, type ProbeFn, type ProbeOptions, type ProbeRequest, type Probe} from './network';
export type Severity='info'|'low'|'medium'|'high';
export type Finding={id:string;severity:Severity;message:string;recommendation?:string};
export type AuditResult={target:string;scannedAt:string;checks:number;findings:Finding[];baselineStatus:number;authenticatedStatus:number|null;corsStatus:number|null;aggressive:boolean;limitations:string[]};
export type AuditOptions=ProbeOptions&{aggressive:boolean;token?:string;requestProbe?:ProbeFn};
const PROBE_ORIGIN='https://audit-origin.invalid';

export async function auditAPI(input:string, token?:string, partial:Partial<AuditOptions>={}):Promise<AuditResult> {
  const options:AuditOptions={allowHttp:false,allowPrivate:false,timeoutMs:8000,aggressive:false,token,...partial};
  const url=validateTarget(input,options);
  const executor=options.requestProbe??probe;
  const findings:Finding[]=[];
  const add=(id:string,severity:Severity,message:string,recommendation?:string)=>findings.push({id,severity,message,recommendation});
  let checks=0;
  async function run(req:ProbeRequest):Promise<Probe>{
    checks++;
    const result=await executor(url,req,options);
    if(!Number.isInteger(result.status)||result.status<100||result.status>599)throw new Error('Resposta HTTP inválida');
    return result;
  }
  // Always probe unauthenticated, even when a token was provided.
  const baseline=await run({});
  let authenticated:Probe|null=null;
  if(options.token)authenticated=await run({headers:{Authorization:'Bearer '+options.token}});
  const primary=authenticated??baseline;
  const cors=await run({headers:{Origin:PROBE_ORIGIN,...(options.token?{Authorization:'Bearer '+options.token}:{})}});
  if(url.protocol!=='https:')add('http-transport','high','Destino utiliza HTTP sem TLS','Use HTTPS com certificado válido');
  if(url.protocol==='https:'&&!hasHeader(primary.headers,'strict-transport-security'))
    add('hsts','medium','Strict-Transport-Security ausente','Habilite HSTS no domínio HTTPS após avaliação do ambiente');
  if(header(primary.headers,'x-content-type-options').toLowerCase()!=='nosniff')
    add('nosniff','medium','X-Content-Type-Options: nosniff ausente');
  if(baseline.status===401||baseline.status===403)
    add('auth-required','info','Endpoint negou requisição sem credenciais (status '+baseline.status+')');
  else if(baseline.status>=200&&baseline.status<300)
    add('public-access','medium','Endpoint responde sem credenciais; confirme se o acesso público é intencional');
  else add('auth-inconclusive','info','Autenticação inconclusiva com status '+baseline.status);
  if(authenticated){
    if(authenticated.status===401||authenticated.status===403)
      add('auth-token-rejected','medium','Token não autorizado; verifique emissor/permissões sem expor o segredo');
    else if(authenticated.status>=200&&authenticated.status<300 && (baseline.status===401||baseline.status===403))
      add('auth-confirmed','info','Requisição autenticada aceita e requisição anônima negada');
  }
  if(primary.status>=300&&primary.status<400)
    add('redirect','info','Destino respondeu com redirecionamento; auditor não o seguiu');
  const origin=header(cors.headers,'access-control-allow-origin');
  const credentials=header(cors.headers,'access-control-allow-credentials').toLowerCase();
  if(origin==='*')add('cors-wildcard','medium','CORS permite qualquer origem; avalie se a API é pública');
  if(origin==='*' && credentials==='true')add('cors-credential-wildcard','high','CORS anuncia origem coringa com credenciais (configuração inconsistente)');
  if(origin===PROBE_ORIGIN){
    add('cors-reflected-origin','high','Servidor autorizou origem arbitrária de teste','Use allowlist explícita de origens');
    if(!header(cors.headers,'vary').toLowerCase().split(',').map(x=>x.trim()).includes('origin'))
      add('cors-no-vary','medium','Vary: Origin ausente com resposta CORS dependente da origem');
  }
  if(authenticated && authenticated.status>=200 && authenticated.status<300){
    if(!/no-store/i.test(header(authenticated.headers,'cache-control')))
      add('authenticated-cache','medium','Cache-Control: no-store ausente na resposta autenticada; verifique dados sensíveis');
  }
  if(options.aggressive){
    await run({method:'OPTIONS',headers:{Origin:PROBE_ORIGIN,'Access-Control-Request-Method':'DELETE'}});
    const nonExistent=new URL(url.href);
    nonExistent.pathname=nonExistent.pathname.replace(/\/$/,'')+'/__audit_probe_'+randomUUID().replace(/-/g,'');
    nonExistent.search='';
    checks++;
    const r=await executor(nonExistent,{method:'GET'},options);
    if(!Number.isInteger(r.status)||r.status<100||r.status>599)throw new Error('Resposta HTTP inválida');
    if(r.status>=200&&r.status<300)add('missing-path-public','medium','Caminho aleatório inexistente retornou sucesso HTTP; avalie fallback/roteamento');
  }
  return {target:url.origin+url.pathname,scannedAt:new Date().toISOString(),checks,findings,
    baselineStatus:baseline.status,authenticatedStatus:authenticated?.status??null,corsStatus:cors.status,
    aggressive:options.aggressive,
    limitations:['Resultados são observacionais, não comprovam exploração ou ausência de vulnerabilidades.',
      'Verificações GET/OPTIONS limitadas; GraphQL introspection, fuzzing mutável e RBAC por objeto não são avaliados.',
      'Não segue redirecionamentos e não armazena corpos HTTP.']};
}
