#!/usr/bin/env node
import { auditAPI } from '../src/auditor';

const args = process.argv.slice(2);
const urlArg = args.find(arg => arg.startsWith('--url='));
const tokenArg = args.find(arg => arg.startsWith('--token='));

if (!urlArg) {
  console.error('❌ Please provide --url');
  process.exit(1);
}

const url = urlArg.split('=')[1];
const token = tokenArg ? tokenArg.split('=')[1] : undefined;

(async () => {
  console.log('🔎 Secure API Audit\n---------------------------------------');
  const results = await auditAPI(url, token);
  results.forEach(line => console.log(line));
  console.log(`---------------------------------------\nSummary: ${results.filter(r => r.startsWith('⚠️')).length} warnings found`);
})();