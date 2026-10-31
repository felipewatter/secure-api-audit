#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {auditAPI, type AuditResult, type Severity} from '../src/auditor';
import {cleanTerminal} from '../src/utils';

type Options={url:string;token?:string;allowHttp:boolean;allowPrivate:boolean;aggressive:boolean;timeoutMs:number;format:'text'|'json';failOn:'none'|'medium'|'high'};
const HELP = [
'Secure API Audit v1.1.0 — verificações HTTP não destrutivas',
'Uso: secure-api-audit --url https://api.example.com [opções]',
'  --url URL              Endpoint explícito para análise',
'  --token-env NOME       Nome da variável com token (padrão: SECURE_API_AUDIT_TOKEN)',
'  --token TOKEN          Legado; evite, pois o token ficará no histórico/processos',
'  --aggressive           Duas sondagens extras seguras (OPTIONS, GET de caminho aleatório)',
'  --allow-http           Permite HTTP sem TLS (somente laboratórios autorizados)',
'  --allow-private        Permite IPs internos ou especiais (somente laboratórios autorizados)',
'  --timeout MS           Limite de tempo por requisição: 100 a 30000 (padrão: 8000)',
'  --format text|json     Formato de saída (padrão: text)',
'  --fail-on none|medium|high   Falha se encontrar severidade igual ou superior (padrão: high)',
'  --help / --version     Ajuda ou versão',
'Saídas: 0=concluído, 1=achados no limiar, 2=erro operacional.',
'HTTPS obrigatório por padrão; URLs internas e redirecionamentos bloqueados.',
].join('\n');

export function parseArgs(args:readonly string[],env:NodeJS.ProcessEnv=process.env):Options|'help'|'version' {
  const values:Options={url:'',allowHttp:false,allowPrivate:false,aggressive:false,timeoutMs:8000,format:'text',failOn:'high'};
  let tokenEnv='SECURE_API_AUDIT_TOKEN';
  let tokenArg:string|undefined;
  for(let i=0;i<args.length;i++){
    const original=args[i]??'';
    const equal=original.indexOf('=');
    const key=equal===-1?original:original.slice(0,equal);
    if(key==='--help'||key==='-h')return 'help';
    if(key==='--version'||key==='-v')return 'version';
    if(key==='--allow-http'){values.allowHttp=true;continue;}
    if(key==='--allow-private'){values.allowPrivate=true;continue;}
    if(key==='--aggressive'){values.aggressive=true;continue;}
    if(!['--url','--token','--token-env','--timeout','--format','--fail-on'].includes(key))throw Error('Argumento desconhecido: '+cleanTerminal(key));
    const value=equal===-1?args[++i]:original.slice(equal+1);
    if(!value || value.startsWith('--'))throw Error('Valor ausente para '+cleanTerminal(key));
    switch(key){
      case '--url':values.url=value;break;
      case '--token':tokenArg=value;break;
      case '--token-env':if(!/^[A-Za-z_][A-Za-z0-9_]{0,80}$/.test(value))throw Error('Nome de variável inválido');tokenEnv=value;break;
      case '--timeout':{
        if(!/^[1-9][0-9]*$/.test(value))throw Error('Timeout inválido');
        const n=Number(value);if(!Number.isSafeInteger(n)||n<100||n>30000)throw Error('Timeout fora do intervalo');
        values.timeoutMs=n;break;
      }
      case '--format':if(value!=='text'&&value!=='json')throw Error('Formato inválido');values.format=value;break;
      case '--fail-on':if(!['none','medium','high'].includes(value))throw Error('Limiar inválido');values.failOn=value as Options['failOn'];break;
    }
  }
  if(!values.url)throw Error('URL obrigatória (use --url)');
  values.token=tokenArg??env[tokenEnv];
  if(values.token && (values.token.includes('\r')||values.token.includes('\n')||values.token.length>8192))
    throw Error('Token inválido');
  return values;
}
function textReport(result:AuditResult):string {
  const lines=['Secure API Audit — resultado observacional','Endpoint: '+cleanTerminal(result.target),
    'Requisições: '+result.checks,'Anônimo: '+result.baselineStatus,
    'Autenticado: '+(result.authenticatedStatus??'não fornecido'),
    'CORS: '+(result.corsStatus??'indisponível'),'Achados: '+result.findings.length];
  for(const item of result.findings){
    lines.push('['+item.severity.toUpperCase()+'] '+cleanTerminal(item.id)+': '+cleanTerminal(item.message));
  }
  lines.push('Limitação: auditoria limitada a métodos seguros; não comprova presença/ausência de falhas.');
  return lines.join('\n');
}
export async function main(args:readonly string[]=process.argv.slice(2),env:NodeJS.ProcessEnv=process.env):Promise<number>{
  let opt:ReturnType<typeof parseArgs>;
  try{opt=parseArgs(args,env);}catch(error){console.error('Secure API Audit: '+(error instanceof Error?error.message:'parâmetro inválido'));return 2;}
  if(opt==='help'){console.log(HELP);return 0;}
  if(opt==='version'){console.log('1.1.0');return 0;}
  if(args.some(x=>x==='--token'||x.startsWith('--token=')))console.error('AVISO: use --token-env para evitar credenciais na linha de comando.');
  try{
    const result=await auditAPI(opt.url,opt.token,{allowHttp:opt.allowHttp,allowPrivate:opt.allowPrivate,aggressive:opt.aggressive,timeoutMs:opt.timeoutMs});
    console.log(opt.format==='json'?JSON.stringify(result,null,2):textReport(result));
    const rank:Record<Severity,number>={info:0,low:1,medium:2,high:3};
    const level=opt.failOn==='none'?100:opt.failOn==='high'?3:2;
    return result.findings.some(x=>rank[x.severity]>=level)?1:0;
  }catch(error){
    // Never echo URLs or token-bearing exception details in operational error output.
    const cause=error instanceof Error?error.message:'erro desconhecido';
    console.error('Secure API Audit: falha operacional: '+cleanTerminal(cause).slice(0,180));
    return 2;
  }
}
if(require.main===module)void main().then(code=>{process.exitCode=code;});
