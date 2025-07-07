import axios from 'axios';
import { hasHeader } from './utils';

export async function auditAPI(url: string, token?: string) {
  const headers: any = {};
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const response = await axios.get(url, { headers });
    const results: string[] = [];

    if (!url.startsWith('https://')) {
      results.push('⚠️ API is not using HTTPS');
    } else {
      results.push('✔️ HTTPS enforced');
    }

    if (!hasHeader(response.headers, 'strict-transport-security')) {
      results.push('⚠️ Missing header: Strict-Transport-Security');
    } else {
      results.push('✔️ Header: Strict-Transport-Security present');
    }

    if (hasHeader(response.headers, 'access-control-allow-origin')) {
      const value = response.headers['access-control-allow-origin'];
      if (value === '*') {
        results.push('⚠️ CORS allows all origins (*)');
      } else {
        results.push('✔️ CORS configuration looks safe');
      }
    }

    if (response.status === 401 || response.status === 403) {
      results.push('✔️ Requires authentication');
    } else {
      results.push('⚠️ Endpoint may be accessible without authentication');
    }

    return results;
  } catch (err: any) {
    return [`❌ Error: ${err.message}`];
  }
}