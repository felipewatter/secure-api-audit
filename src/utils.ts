import type {IncomingHttpHeaders} from 'node:http';
export function header(headers: IncomingHttpHeaders,name:string):string {
  const value=headers[name.toLowerCase()];
  return typeof value==='string'?value:Array.isArray(value)?value.join(', '):'';
}
export function hasHeader(headers: IncomingHttpHeaders,name:string):boolean {
  return header(headers,name).trim()!=='';
}
export function cleanTerminal(text:string):string {
  return text.replace(/[\x00-\x1f\x7f-\x9f]/g,'?').slice(0,500);
}
