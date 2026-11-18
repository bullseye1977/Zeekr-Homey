'use strict';

const https = require('https');
const zlib = require('zlib');

const TIMEOUT_MS = 30000;

/**
 * Minimal HTTPS request helper (no dependencies). Header names are sent exactly as given
 * (the gateways are case-insensitive, but this keeps us close to the stock app).
 * @returns {Promise<{ status: number, headers: object, text: string }>}
 */
function request(method, url, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body == null ? null : Buffer.from(body, 'utf8');
    const h = { ...headers };
    if (payload) h['Content-Length'] = String(payload.length);
    const req = https.request({
      method,
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: h,
      timeout: TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = String(res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc.includes('gzip') && buf.length) buf = zlib.gunzipSync(buf);
          else if (enc.includes('deflate') && buf.length) buf = zlib.inflateSync(buf);
        } catch (e) {
          // not actually compressed - keep raw bytes
        }
        resolve({ status: res.statusCode, headers: res.headers, text: buf.toString('utf8') });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`timeout after ${TIMEOUT_MS / 1000}s: ${u.pathname}`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { request };
