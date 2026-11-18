#!/usr/bin/env node
'use strict';

/**
 * Extract the Zeekr app keys from an OpenZeekr release APK that YOU downloaded and installed
 * (https://github.com/borconi/openzeekr/releases), and write them as JSON for the Homey app settings.
 *
 *   node tools/extract-keys.js path/to/openzeekr.apk [output.json]
 *
 * How it works (no dependencies, nothing is sent anywhere):
 *  - The release APK contains lib/<abi>/libozsecrets.so: one tiny JNI function per key
 *    (Java_com_openzeekr_app_util_NativeSecrets_nProdSecret, …) that returns a constant string.
 *    We find each function in the ELF symbol table and decode the instruction that loads the
 *    string address (arm64: ADRP+ADD / ADR, x86_64: LEA rsi,[rip+disp]).
 *  - The RSA password public key is a plain BuildConfig string in classes*.dex; we pick the
 *    string(s) that parse as an RSA public key.
 *
 * The key values are written to the output file only - they are not printed unless you pass --print.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const SYMBOL_PREFIX = 'Java_com_openzeekr_app_util_NativeSecrets_';
const NAME_MAP = {
  nHmacAccessKey: 'hmac_access_key',
  nHmacSecretKey: 'hmac_secret_key',
  nProdSecret: 'prod_secret',
  nVinKey: 'vin_key',
  nVinIv: 'vin_iv',
  nXchangerSignSecret: 'xchanger_sign_secret',
  nOverseasAccessKey: 'overseas_access_key',
  nOverseasSecretKey: 'overseas_secret_key',
  nInboxAuthSecret: 'inbox_auth_secret',
  nHmacAccessKeySea: 'sea_hmac_access_key',
  nHmacSecretKeySea: 'sea_hmac_secret_key',
  nProdSecretSea: 'sea_prod_secret',
  nHmacAccessKeyEm: 'em_hmac_access_key',
  nHmacSecretKeyEm: 'em_hmac_secret_key',
  nProdSecretEm: 'em_prod_secret',
};
const REQUIRED = ['hmac_access_key', 'hmac_secret_key', 'password_public_key', 'prod_secret', 'vin_key', 'vin_iv'];

// ---------------------------------------------------------------- ZIP

function readZip(buf) {
  // End Of Central Directory: search backwards for 0x06054b50
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a ZIP/APK file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Corrupt ZIP central directory');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    entries.set(name, { method, csize, localOff });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return {
    names: [...entries.keys()],
    read(name) {
      const e = entries.get(name);
      if (!e) return null;
      const lp = e.localOff;
      const dataStart = lp + 30 + buf.readUInt16LE(lp + 26) + buf.readUInt16LE(lp + 28);
      const raw = buf.subarray(dataStart, dataStart + e.csize);
      if (e.method === 0) return Buffer.from(raw);
      if (e.method === 8) return zlib.inflateRawSync(raw);
      throw new Error(`Unsupported ZIP compression ${e.method} for ${name}`);
    },
  };
}

// ---------------------------------------------------------------- ELF

function parseElf(b) {
  if (b.readUInt32BE(0) !== 0x7f454c46) throw new Error('Not an ELF file');
  if (b[4] !== 2) throw new Error('Only 64-bit libraries are supported');
  const machine = b.readUInt16LE(18);
  const phoff = Number(b.readBigUInt64LE(32));
  const shoff = Number(b.readBigUInt64LE(40));
  const phentsize = b.readUInt16LE(54);
  const phnum = b.readUInt16LE(56);
  const shentsize = b.readUInt16LE(58);
  const shnum = b.readUInt16LE(60);

  const segments = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (b.readUInt32LE(o) !== 1) continue; // PT_LOAD
    segments.push({
      offset: Number(b.readBigUInt64LE(o + 8)),
      vaddr: Number(b.readBigUInt64LE(o + 16)),
      filesz: Number(b.readBigUInt64LE(o + 32)),
    });
  }
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    sections.push({
      type: b.readUInt32LE(o + 4),
      offset: Number(b.readBigUInt64LE(o + 24)),
      size: Number(b.readBigUInt64LE(o + 32)),
      link: b.readUInt32LE(o + 40),
      entsize: Number(b.readBigUInt64LE(o + 56)),
    });
  }
  const toOffset = (vaddr) => {
    const s = segments.find((g) => vaddr >= g.vaddr && vaddr < g.vaddr + g.filesz);
    return s ? s.offset + (vaddr - s.vaddr) : -1;
  };
  const symbols = new Map();
  for (const sec of sections) {
    if (sec.type !== 11 && sec.type !== 2) continue; // SHT_DYNSYM / SHT_SYMTAB
    const strtab = sections[sec.link];
    for (let o = sec.offset; o + 24 <= sec.offset + sec.size; o += sec.entsize || 24) {
      const nameOff = b.readUInt32LE(o);
      const value = Number(b.readBigUInt64LE(o + 8));
      if (!value) continue;
      let e = strtab.offset + nameOff;
      while (b[e] !== 0) e++;
      symbols.set(b.toString('latin1', strtab.offset + nameOff, e), value);
    }
  }
  return { machine, toOffset, symbols };
}

function cString(b, off) {
  if (off < 0) return null;
  let e = off;
  while (e < b.length && b[e] !== 0) e++;
  return b.toString('utf8', off, e);
}

const sext = (v, bits) => (v & (1 << (bits - 1)) ? v - 2 ** bits : v);

/** arm64: emulate ADRP / ADR / ADD(imm) / MOV until the tail call, return x1 (the NewStringUTF arg). */
function arm64StringArg(b, elf, fnAddr) {
  const regs = {};
  const fnOff = elf.toOffset(fnAddr);
  // JS bitwise ops yield a SIGNED int32, so `insn & 0x90000000` comes back negative while the
  // literal is positive; `>>> 0` coerces the masked value back to unsigned before comparing.
  const m = (mask) => (insn & mask) >>> 0;
  let insn;
  for (let i = 0; i < 32; i++) {
    const pc = fnAddr + i * 4;
    insn = b.readUInt32LE(fnOff + i * 4);
    const rd = insn & 0x1f;
    if (m(0x9f000000) === 0x90000000) { // ADRP
      const imm = sext((((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 3), 21);
      regs[rd] = (Math.floor(pc / 4096) * 4096) + imm * 4096;
    } else if (m(0x9f000000) === 0x10000000) { // ADR
      const imm = sext((((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 3), 21);
      regs[rd] = pc + imm;
    } else if (m(0xff800000) === 0x91000000) { // ADD Xd, Xn, #imm{, lsl #12}
      const rn = (insn >>> 5) & 0x1f;
      const sh = (insn >>> 22) & 1;
      const imm = ((insn >>> 10) & 0xfff) * (sh ? 4096 : 1);
      if (regs[rn] !== undefined) regs[rd] = regs[rn] + imm;
    } else if (m(0xffe0ffe0) === 0xaa0003e0) { // MOV Xd, Xm (ORR Xd, XZR, Xm)
      const rm = (insn >>> 16) & 0x1f;
      if (regs[rm] !== undefined) regs[rd] = regs[rm];
    } else if (m(0xfffffc1f) === 0xd61f0000 || m(0xfffffc1f) === 0xd63f0000
      || m(0xfc000000) === 0x14000000 || m(0xfc000000) === 0x94000000 || insn === 0xd65f03c0) {
      break; // BR / BLR / B / BL / RET
    }
  }
  return regs[1];
}

/** x86_64: find LEA rsi,[rip+disp32] (48 8d 35 xx xx xx xx). */
function x64StringArg(b, elf, fnAddr) {
  const fnOff = elf.toOffset(fnAddr);
  for (let i = 0; i < 64; i++) {
    if (b[fnOff + i] === 0x48 && b[fnOff + i + 1] === 0x8d && b[fnOff + i + 2] === 0x35) {
      return fnAddr + i + 7 + b.readInt32LE(fnOff + i + 3);
    }
  }
  return undefined;
}

function extractFromSo(b) {
  const elf = parseElf(b);
  const decode = elf.machine === 183 ? arm64StringArg : elf.machine === 62 ? x64StringArg : null;
  if (!decode) throw new Error(`Unsupported CPU architecture in library (e_machine=${elf.machine})`);
  const out = {};
  for (const [sym, addr] of elf.symbols) {
    if (!sym.startsWith(SYMBOL_PREFIX)) continue;
    const key = NAME_MAP[sym.substring(SYMBOL_PREFIX.length)];
    if (!key) continue;
    const strAddr = decode(b, elf, addr);
    if (strAddr === undefined) continue;
    out[key] = cString(b, elf.toOffset(strAddr));
  }
  return out;
}

// ---------------------------------------------------------------- DEX (password public key)

function uleb(b, o) {
  let result = 0; let shift = 0; let byte;
  do { byte = b[o++]; result |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
  return o;
}

function dexStrings(b) {
  if (b.toString('latin1', 0, 3) !== 'dex') return [];
  const size = b.readUInt32LE(0x38);
  const off = b.readUInt32LE(0x3c);
  const out = [];
  for (let i = 0; i < size; i++) {
    let p = uleb(b, b.readUInt32LE(off + i * 4));
    const start = p;
    while (b[p] !== 0) p++;
    if (p - start >= 100) out.push(b.toString('utf8', start, p)); // RSA keys are long
  }
  return out;
}

function findRsaPublicKeys(strings) {
  const keys = [];
  for (const s of strings) {
    if (!/^MI[GI][A-Za-z0-9+/]{100,}={0,2}$/.test(s)) continue;
    try {
      const k = crypto.createPublicKey({ key: Buffer.from(s, 'base64'), format: 'der', type: 'spki' });
      if (k.asymmetricKeyType === 'rsa') keys.push(s);
    } catch (e) { /* not a key */ }
  }
  return [...new Set(keys)];
}

// ---------------------------------------------------------------- main

function extract(apkPath) {
  const zip = readZip(fs.readFileSync(apkPath));
  const abis = ['arm64-v8a', 'x86_64'];
  let secrets = null;
  let usedAbi = null;
  for (const abi of abis) {
    const so = zip.read(`lib/${abi}/libozsecrets.so`);
    if (!so) continue;
    secrets = extractFromSo(so);
    usedAbi = abi;
    break;
  }
  if (!secrets) {
    const found = zip.names.filter((n) => n.endsWith('libozsecrets.so'));
    throw new Error(found.length
      ? `libozsecrets.so only found for an unsupported ABI: ${found.join(', ')}`
      : 'No libozsecrets.so in this APK - is this the official OpenZeekr release APK?');
  }
  const pubKeys = findRsaPublicKeys(zip.names.filter((n) => /^classes\d*\.dex$/.test(n)).flatMap((n) => dexStrings(zip.read(n))));
  if (pubKeys.length) secrets.password_public_key = pubKeys[0];
  return { secrets, usedAbi, pubKeyCandidates: pubKeys.length, pubKeys };
}

function main() {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const print = process.argv.includes('--print');
  if (!args[0]) {
    console.error('Usage: node tools/extract-keys.js <openzeekr.apk> [output.json] [--print]');
    process.exit(2);
  }
  const outPath = args[1] || path.join(path.dirname(path.resolve(args[0])), 'zeekr-keys.json');
  const { secrets, usedAbi, pubKeyCandidates, pubKeys } = extract(args[0]);

  const result = {};
  for (const k of REQUIRED) if (secrets[k]) result[k] = secrets[k];
  for (const [k, v] of Object.entries(secrets)) if (!(k in result) && v) result[k] = v;

  console.log(`Library: lib/${usedAbi}/libozsecrets.so`);
  for (const k of REQUIRED) {
    const v = result[k];
    console.log(`  ${v ? '✓' : '✗'} ${k.padEnd(20)} ${v ? `(${v.length} chars)` : 'NOT FOUND'}`);
  }
  if (pubKeyCandidates > 1) console.log(`  note: ${pubKeyCandidates} RSA public keys found in the DEX; using the first one.`);
  for (const k of ['vin_key', 'vin_iv']) {
    if (result[k] && Buffer.byteLength(result[k]) !== 16) console.log(`  warning: ${k} is not 16 bytes - it may be wrong`);
  }

  fs.writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  console.log(`\nWritten to ${outPath}`);
  console.log('Open this file, copy its contents and paste it into: Homey app → Apps → Zeekr → Configure → App keys.');
  console.log('Keep this file private and delete it afterwards.');

  // When the DEX holds more than one RSA public key we cannot tell which one signs the
  // password, so also write one alternate file per other candidate. If login fails with a
  // password/4002-type error, try the -alt file(s) instead.
  if (pubKeys && pubKeys.length > 1) {
    console.log(`\n${pubKeys.length} RSA public keys were found. zeekr-keys.json uses candidate #1.`);
    console.log('If "Test login" fails at the password step, try these alternates:');
    for (let i = 1; i < pubKeys.length; i++) {
      const altPath = outPath.replace(/\.json$/i, '') + `-alt${i}.json`;
      fs.writeFileSync(altPath, `${JSON.stringify({ ...result, password_public_key: pubKeys[i] }, null, 2)}\n`, { mode: 0o600 });
      console.log(`  candidate #${i + 1}: ${altPath}`);
    }
  }
  if (print) console.log(JSON.stringify(result, null, 2));
  const missing = REQUIRED.filter((k) => !result[k]);
  if (missing.length) {
    console.error(`\nMissing: ${missing.join(', ')}. This APK may be a build without baked-in keys.`);
    process.exit(1);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { extract, extractFromSo, readZip, findRsaPublicKeys, dexStrings };
