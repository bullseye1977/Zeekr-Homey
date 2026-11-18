'use strict';

/**
 * The Zeekr request-signing schemes.
 * Ported from OpenZeekr (MIT) core/net/Signing.kt, VinCrypto.kt and AccountLogin.kt,
 * which in turn port the `zeekr_ev_api` Python library.
 *
 *  - user-center (login) requests: X-HMAC-* headers, HMAC-SHA256 with hmac_secret_key
 *  - TSP gateway requests:         X-SIGNATURE header, HMAC-SHA256 with prod_secret
 */

const crypto = require('crypto');

function hmacB64(data, secret) {
  return crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(Buffer.from(data, 'utf8')).digest('base64');
}

/** "Wed, 18 Nov 2026 10:00:00 GMT" (same as Java's EEE, dd MMM yyyy HH:mm:ss 'GMT'). */
function gmtDate(date = new Date()) {
  return date.toUTCString();
}

function splitQuery(rawQuery) {
  const pairs = [];
  if (!rawQuery) return pairs;
  for (const pair of rawQuery.split('&')) {
    const i = pair.indexOf('=');
    if (i >= 0) pairs.push([pair.substring(0, i), pair.substring(i + 1)]);
    else pairs.push([pair, null]);
  }
  return pairs;
}

function cmp(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// ==================== USER-CENTER (account/login) HMAC ====================

/**
 * @returns {{ 'X-HMAC-ALGORITHM': string, 'X-HMAC-SIGNATURE': string, 'X-HMAC-ACCESS-KEY': string,
 *            'X-HMAC-DIGEST': string, 'X-DATE': string }}
 */
function usercenterHmac(method, url, accessKey, secretKey, body, date = gmtDate()) {
  const u = new URL(url);
  const segs = decodeURIComponent(u.pathname).replace(/^\/+|\/+$/g, '').split('/').filter((s) => s.length > 0);
  const canonicalPath = segs.length === 0 ? '/' : `/${segs.join('/')}`;

  // query keys sorted case-insensitively, "k=v" joined by "&", values raw (pairs without '=' are dropped)
  const map = new Map();
  for (const [k, v] of splitQuery(u.search.replace(/^\?/, ''))) if (v !== null) map.set(k, v);
  const canonicalQuery = [...map.keys()]
    .sort((a, b) => cmp(a.toLowerCase(), b.toLowerCase()))
    .map((k) => `${k}=${map.get(k)}`)
    .join('&');

  const signString = [method.toUpperCase(), canonicalPath, canonicalQuery, accessKey, date].join('\n');
  return {
    'X-HMAC-ALGORITHM': 'hmac-sha256',
    'X-HMAC-SIGNATURE': hmacB64(`${signString}\n`, secretKey),
    'X-HMAC-ACCESS-KEY': accessKey,
    'X-HMAC-DIGEST': hmacB64(body == null ? '' : String(body), secretKey),
    'X-DATE': date,
  };
}

// ==================== TSP gateway (app-signed) X-SIGNATURE ====================

const ALLOWED = new Set([
  'x-app-id', 'content-type', 'x-api-signature-nonce', 'x-timestamp',
  'x-api-signature-version', 'x-project-id', 'authorization', 'accept-language',
  'x-vin', 'x-device-id', 'x-platform',
]);

function sortValue(v) {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
    return out;
  }
  return v;
}

/**
 * Canonical JSON: object keys sorted recursively, compact. The gateway hashes the body
 * exactly as received, so this is also the form that must be SENT.
 */
function canonicalJson(value) {
  const obj = typeof value === 'string' ? JSON.parse(value) : value;
  return JSON.stringify(sortValue(obj));
}

/**
 * X-SIGNATURE over the decorated request.
 * @param {string} method
 * @param {string} url full URL incl. query
 * @param {Object<string,string>} headers all request headers (incl. nonce + timestamp)
 * @param {string|null} body the exact body string that will be sent
 * @param {string} secret prod_secret
 */
function tspSignature(method, url, headers, body, secret) {
  const u = new URL(url);

  const hdr = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), v == null ? '' : String(v)])
    .filter(([k, v]) => ALLOWED.has(k) && !((k === 'x-vin' || k === 'authorization') && v === ''))
    .sort((a, b) => cmp(a[0], b[0]))
    .map(([k, v]) => `${k}:${v}\n`)
    .join('');

  const map = new Map();
  for (const [k, v] of splitQuery(u.search.replace(/^\?/, ''))) map.set(k, v === null ? '' : v);
  const query = [...map.keys()]
    .sort(cmp)
    .map((k) => `${k}=${map.get(k).replace(/%2F/g, '/').replace(/%3F/g, '?').replace(/\*/g, '%2A')}`)
    .join('&');

  const ctEntry = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-type');
  const ct = ctEntry ? String(ctEntry[1]) : '';
  let bodyHash = '';
  if (/application\/json/i.test(ct) && body != null && body.length > 0) {
    try {
      bodyHash = crypto.createHash('md5').update(Buffer.from(canonicalJson(body), 'utf8')).digest('base64');
    } catch (e) {
      bodyHash = '';
    }
  }

  let base = '';
  if (hdr) base += hdr;
  if (query) base += `${query}\n`;
  if (bodyHash) base += `${bodyHash}\n`;
  base += `${method.toUpperCase()}\n`;
  base += decodeURIComponent(u.pathname).trimEnd();
  return hmacB64(base, secret);
}

// ==================== VIN + password crypto ====================

/** X-VIN header value = Base64(AES-128-CBC(VIN, vin_key, vin_iv)), key/iv are the 16-char ASCII strings. */
function encryptVin(vin, key, iv) {
  if (!vin) return vin;
  if (key && key.startsWith('B64:') && key.length > 4) return key.substring(4);
  if (!key || !iv) return vin;
  const k = Buffer.from(key, 'utf8');
  const i = Buffer.from(iv, 'utf8');
  if (k.length !== 16 || i.length !== 16) {
    throw new Error(`vin_key and vin_iv must be exactly 16 bytes (got ${k.length} / ${i.length})`);
  }
  const c = crypto.createCipheriv('aes-128-cbc', k, i);
  return Buffer.concat([c.update(Buffer.from(vin, 'utf8')), c.final()]).toString('base64');
}

/** RSA/ECB/PKCS1Padding encryption of the password with the (base64 X.509 SPKI) public key. */
function encryptPassword(password, pubKeyB64) {
  if (!pubKeyB64) return password;
  const key = crypto.createPublicKey({ key: Buffer.from(pubKeyB64.replace(/\s+/g, ''), 'base64'), format: 'der', type: 'spki' });
  return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(password, 'utf8')).toString('base64');
}

/** Extract a claim from a JWT ("Bearer <h>.<p>.<s>"). */
function jwtClaim(token, claim) {
  try {
    const jwt = String(token).replace(/^Bearer /, '').trim();
    const payload = jwt.split('.')[1];
    if (!payload) return null;
    const v = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))[claim];
    return v == null ? null : String(v);
  } catch (e) {
    return null;
  }
}

module.exports = {
  gmtDate,
  usercenterHmac,
  canonicalJson,
  tspSignature,
  encryptVin,
  encryptPassword,
  jwtClaim,
};
