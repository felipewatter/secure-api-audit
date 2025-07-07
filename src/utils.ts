export function hasHeader(headers: any, name: string): boolean {
  return Object.keys(headers).some(h => h.toLowerCase() === name.toLowerCase());
}