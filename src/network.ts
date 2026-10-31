import {request as httpRequest, type IncomingHttpHeaders} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {lookup as dnsLookup} from 'node:dns';
import {isIP} from 'node:net';

export type Probe = {status: number; headers: IncomingHttpHeaders};
export type ProbeRequest = {method?: 'GET'|'HEAD'|'OPTIONS'; headers?: Record<string,string>};
export type ProbeOptions = {allowHttp: boolean; allowPrivate: boolean; timeoutMs: number};
export type ProbeFn = (url: URL, request: ProbeRequest, options: ProbeOptions) => Promise<Probe>;

/** RFC1918, link-local, loopback, documentation and reserved IPv4 must not be scanned by default. */
export function isSafeAddress(address: string): boolean {
  if (isIP(address) !== 4) return false; // IPv6 is opt-in until complete coverage of special-purpose ranges.
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n=>!Number.isInteger(n)||n<0||n>255)) return false;
  const [a,b,c] = parts as [number,number,number,number];
  if (a===0 || a===10 || a===127 || a>=224) return false;
  if (a===100 && b>=64 && b<=127) return false;
  if (a===169 && b===254) return false;
  if (a===172 && b>=16 && b<=31) return false;
  if (a===192 && (b===168 || b===0 || (b===88 && c===99))) return false;
  if (a===198 && (b===18 || b===19 || (b===51 && c===100))) return false;
  if (a===203 && b===0 && c===113) return false;
  if (a===192 && b===0 && c===2) return false;
  return true;
}

export function validateTarget(raw: string, options: ProbeOptions): URL {
  let url: URL;
  try {url = new URL(raw);} catch {throw new Error('URL inválida');}
  if (url.protocol!=='https:' && !(options.allowHttp && url.protocol==='http:')) {
    throw new Error('HTTPS obrigatório; HTTP requer --allow-http');
  }
  if (!url.hostname || url.username || url.password || url.hash) throw new Error('URL não pode conter credenciais ou fragmento');
  if (url.href.length>4096 || /[\x00-\x1f]/.test(raw)) throw new Error('URL excessiva ou inválida');
  const address = url.hostname.replace(/^\[|\]$/g,'');
  if (isIP(address) && !options.allowPrivate && !isSafeAddress(address)) {
    throw new Error('Endereço especial/interno bloqueado (use --allow-private apenas com autorização)');
  }
  if (!options.allowPrivate && (address.toLowerCase()==='localhost' || address.toLowerCase().endsWith('.localhost') || address.toLowerCase().endsWith('.local'))) {
    throw new Error('Hostname local bloqueado');
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0') throw new Error('Validação TLS desativada pelo ambiente');
  return url;
}

export const probe: ProbeFn = (url, request, options) => new Promise((resolve,reject)=>{
  let done=false;
  const finish=(error?:Error,result?:Probe)=>{
    if(done)return;done=true;
    if(error)reject(error);else if(result)resolve(result);
  };
  const useHttps=url.protocol==='https:';
  const requester=useHttps?httpsRequest:httpRequest;
  const headers={ 'User-Agent':'secure-api-audit/1.1.0', 'Accept':'application/json', ...(request.headers??{}) };
  const req=requester(url,{
    method:request.method??'GET',
    headers,
    timeout:options.timeoutMs,
    maxHeaderSize:32768,
    // Resolve and validate at the actual connection boundary; disallow DNS rebinding to private IPs.
    lookup:(hostname, opts, cb)=>{
      dnsLookup(hostname,{all:true,verbatim:true},(err,addresses)=>{
        if(err){cb(err,'',4);return;}
        if(!addresses.length || (!options.allowPrivate && addresses.some(entry=>!isSafeAddress(entry.address)))){
          cb(new Error('DNS resolveu endereço não permitido'),'',4);return;
        }
        const entry=addresses.find(x=>x.family===4)??addresses[0];
        cb(null,opts.all ? addresses : entry.address,opts.all ? undefined : entry.family);
      });
    }
  },res=>{
    const result={status:res.statusCode??0,headers:res.headers};
    // Headers only: do not download or store API bodies, and never follow Location redirects.
    res.destroy();finish(undefined,result);
  });
  req.once('timeout',()=>req.destroy(new Error('Tempo limite de conexão excedido')));
  req.once('error',error=>finish(error));
  req.end();
});
