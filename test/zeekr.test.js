'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const path = require('path');

const S = require('../lib/zeekr/signing');
const C = require('../lib/zeekr/constants');
const { Commands } = require('../lib/zeekr/commands');
const { parseStatus } = require('../lib/zeekr/status');

const hmac = (data, key) => crypto.createHmac('sha256', key).update(data).digest('base64');

// ---------------------------------------------------------------- signing

test('canonicalJson sorts keys recursively and keeps array order', () => {
  const s = S.canonicalJson({ setting: { serviceParameters: [{ value: '800', key: 'soc' }, { key: 'rcs.setting', value: '1' }] }, serviceId: 'RCS', command: 'start' });
  assert.strictEqual(s, '{"command":"start","serviceId":"RCS","setting":{"serviceParameters":[{"key":"soc","value":"800"},{"key":"rcs.setting","value":"1"}]}}');
});

test('user-center HMAC builds the documented sign string', () => {
  const date = 'Wed, 18 Nov 2026 10:00:00 GMT';
  const url = 'https://gateway-pub-azure.zeekr.eu/zeekr-cuc-idaas/user/tspCode?tspClientId=abc&B=2';
  const h = S.usercenterHmac('GET', url, 'AK', 'SK', null, date);
  const expected = hmac(['GET', '/zeekr-cuc-idaas/user/tspCode', 'B=2&tspClientId=abc', 'AK', date].join('\n') + '\n', 'SK');
  assert.strictEqual(h['X-HMAC-SIGNATURE'], expected);
  assert.strictEqual(h['X-HMAC-DIGEST'], hmac('', 'SK'));
  assert.strictEqual(h['X-DATE'], date);
  const post = S.usercenterHmac('POST', url, 'AK', 'SK', '{"a":1}', date);
  assert.strictEqual(post['X-HMAC-DIGEST'], hmac('{"a":1}', 'SK'));
});

test('gmtDate matches the Java EEE, dd MMM yyyy HH:mm:ss GMT format', () => {
  assert.strictEqual(S.gmtDate(new Date(Date.UTC(2026, 10, 8, 7, 5, 3))), 'Sun, 08 Nov 2026 07:05:03 GMT');
});

test('TSP signature: allowed headers only, empty authorization dropped, query sorted, body MD5', () => {
  const url = 'https://eu-snc-tsp-api-gw.zeekrlife.com/ms-vehicle-status/api/v1.0/vehicle/status/latest?target=new&latest=false';
  const headers = {
    'X-APP-ID': 'APP', 'Content-Type': 'application/json; charset=UTF-8', 'X-TIMESTAMP': '1',
    'X-API-SIGNATURE-NONCE': 'n', authorization: '', 'user-agent': 'ignored', 'x-vin': 'V',
  };
  const body = '{"b":1,"a":2}';
  const md5 = crypto.createHash('md5').update('{"a":2,"b":1}').digest('base64');
  const base = 'content-type:application/json; charset=UTF-8\nx-api-signature-nonce:n\nx-app-id:APP\nx-timestamp:1\nx-vin:V\n'
    + 'latest=false&target=new\n'
    + `${md5}\n`
    + 'POST\n/ms-vehicle-status/api/v1.0/vehicle/status/latest';
  assert.strictEqual(S.tspSignature('POST', url, headers, body, 'secret'), hmac(base, 'secret'));
  // GET without body: no MD5 line
  const baseGet = base.replace(`${md5}\n`, '').replace('POST', 'GET');
  assert.strictEqual(S.tspSignature('GET', url, headers, null, 'secret'), hmac(baseGet, 'secret'));
});

test('VIN encryption is AES-128-CBC with the ASCII key/iv', () => {
  const enc = S.encryptVin('L6T7824Z0RN000001', 'abcdefghijklmnop', '1234567890abcdef');
  const d = crypto.createDecipheriv('aes-128-cbc', Buffer.from('abcdefghijklmnop'), Buffer.from('1234567890abcdef'));
  assert.strictEqual(Buffer.concat([d.update(Buffer.from(enc, 'base64')), d.final()]).toString(), 'L6T7824Z0RN000001');
  assert.throws(() => S.encryptVin('VIN', 'short', '1234567890abcdef'), /16 bytes/);
});

test('password is RSA PKCS#1 v1.5 encrypted with the SPKI public key', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const a = Buffer.from(S.encryptPassword('geheim!', spki), 'base64');
  const b = Buffer.from(S.encryptPassword('geheim!', spki), 'base64');
  assert.strictEqual(a.length, 256);
  assert.notDeepStrictEqual(a, b); // randomised padding
  // Raw RSA "decrypt" and check the PKCS#1 v1.5 type-2 block: 00 02 <random non-zero> 00 <message>
  const block = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, a);
  assert.strictEqual(block[0], 0x00);
  assert.strictEqual(block[1], 0x02);
  assert.strictEqual(block.subarray(block.indexOf(0, 2) + 1).toString(), 'geheim!');
});

test('jwtClaim reads the userId claim', () => {
  const payload = Buffer.from(JSON.stringify({ userId: 12345 })).toString('base64url');
  assert.strictEqual(S.jwtClaim(`Bearer h.${payload}.s`, 'userId'), '12345');
  assert.strictEqual(S.jwtClaim('garbage', 'userId'), null);
});

// ---------------------------------------------------------------- commands

test('climate command uses ZAF/start with dot-decimal temperature', () => {
  const c = Commands.climateOn(21.3, 20);
  assert.deepStrictEqual(c, {
    serviceId: 'ZAF', command: 'start',
    params: [{ key: 'AC', value: 'true' }, { key: 'AC.temp', value: '21.5' }, { key: 'AC.duration', value: '20' }],
  });
});

test('charge limit puts soc (per-mille) first', () => {
  const c = Commands.setChargeLimit(80);
  assert.strictEqual(c.serviceId, 'RCS');
  assert.deepStrictEqual(c.params[0], { key: 'soc', value: '800' });
  assert.strictEqual(Commands.setChargeLimit(20).params[0].value, '500'); // clamped to 50 %
});

test('seat heat level 0 turns the seat off', () => {
  assert.deepStrictEqual(Commands.seatHeat('passenger', 0).params, [{ key: 'SH.19', value: 'false' }]);
  assert.strictEqual(Commands.seatHeat('driver', 2).params[1].value, '2');
});

// ---------------------------------------------------------------- status

const SAMPLE = {
  updateTime: '1795000000000',
  basicVehicleStatus: { distanceToEmpty: '350', position: { latitude: '52.37', longitude: '4.89' } },
  additionalVehicleStatus: {
    electricVehicleStatus: { stateOfCharge: '', chargeLevel: '64', chargerState: '2', chargeIAct: '16', chargeUAct: '400', distanceToEmptyOnBatteryOnly: '312', statusOfChargerConnection: '1', isCharging: false },
    drivingSafetyStatus: { centralLockingStatus: '1', doorOpenStatusDriver: '0', doorOpenStatusPassenger: '1', trunkOpenStatus: '0' },
    climateStatus: { interiorTemp: '19.5', exteriorTemp: '4', preClimateActive: true, winPosDriver: '0', winPosPassenger: '0' },
    maintenanceStatus: { odometer: '12345' },
  },
};

test('parseStatus maps SOC, charging, power, locks and doors', () => {
  const s = parseStatus(SAMPLE);
  assert.strictEqual(s.soc, 64);
  assert.strictEqual(s.range, 312);
  assert.strictEqual(s.charging, true); // chargerState 2, despite isCharging=false
  assert.strictEqual(s.pluggedIn, true);
  assert.ok(Math.abs(s.chargePowerW - Math.sqrt(3) * 400 * 16) < 1); // 3-phase
  assert.strictEqual(s.locked, true);
  assert.strictEqual(s.anyDoorOpen, true);
  assert.strictEqual(s.trunkOpen, false);
  assert.strictEqual(s.windowsOpen, false);
  assert.strictEqual(s.climateOn, true);
  assert.strictEqual(s.interiorTemp, 19.5);
  assert.strictEqual(s.odometer, 12345);
  assert.strictEqual(s.latitude, 52.37);
});

test('parseStatus tolerates an empty tree', () => {
  const s = parseStatus({});
  assert.strictEqual(s.soc, null);
  assert.strictEqual(s.charging, false);
  assert.strictEqual(s.locked, null);
});

// ---------------------------------------------------------------- client (mocked transport)

function loadClientWithMock(handler) {
  const httpPath = path.join(__dirname, '../lib/zeekr/http.js');
  const clientPath = path.join(__dirname, '../lib/zeekr/ZeekrClient.js');
  delete require.cache[clientPath];
  require.cache[httpPath] = { id: httpPath, filename: httpPath, loaded: true, exports: { request: handler } };
  const mod = require(clientPath);
  delete require.cache[httpPath];
  delete require.cache[clientPath];
  return mod;
}

function makeSecrets() {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  return {
    hmac_access_key: 'AK', hmac_secret_key: 'SK', prod_secret: 'PS',
    password_public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    vin_key: 'abcdefghijklmnop', vin_iv: '1234567890abcdef',
  };
}

const ok = (data) => ({ status: 200, headers: {}, text: JSON.stringify({ code: '000000', success: true, data }) });
const jwt = `Bearer h.${Buffer.from(JSON.stringify({ userId: '777' })).toString('base64url')}.s`;

function fakeServer(calls, { statusFailures = [] } = {}) {
  const failures = [...statusFailures];
  return async (method, url, headers, body) => {
    const p = new URL(url).pathname;
    calls.push({ method, p, headers, body });
    if (p.endsWith('/auth/checkUserV2')) return ok({});
    if (p.endsWith('/auth/loginByEmailEncrypt')) return ok({ tokenName: 'Authorization', tokenValue: 'UC-TOKEN' });
    if (p.endsWith('/user/info')) return ok({ uuid: 'u-1' });
    if (p.endsWith('/user/tspCode')) return ok({ code: 'TSP-CODE' });
    if (p.endsWith('/ms-user-auth/v1.0/auth/login')) return ok({ accessToken: jwt });
    if (p.endsWith('/app/hb')) return ok({});
    if (p.endsWith('/vehicle-list')) return ok([{ vin: 'VIN1', nickName: 'Mijn 7X', modelName: '7X', isOwner: true }]);
    if (p.includes('/vehicle/status/latest')) {
      const f = failures.shift();
      if (f) return { status: 401, headers: {}, text: JSON.stringify({ code: f, success: false }) };
      return ok(SAMPLE);
    }
    if (p.endsWith('/remoteControl/control') || p.endsWith('/charge/control')) return ok({ status: 'ok' });
    return { status: 404, headers: {}, text: '{"code":"404"}' };
  };
}

function makeClient(handler, store = {}) {
  const { ZeekrClient } = loadClientWithMock(handler);
  const secrets = makeSecrets();
  return new ZeekrClient({
    getConfig: () => ({ region: 'EU', email: 'test@example.com', password: 'pw', secrets }),
    getSession: () => store.session,
    saveSession: (s) => { store.session = s; },
  });
}

test('login runs checkUser → login → info → tspCode → bearer → heartbeat with correct auth', async () => {
  const calls = [];
  const store = {};
  const client = makeClient(fakeServer(calls), store);
  await client.login();
  assert.deepStrictEqual(calls.map((c) => c.p.split('/').slice(-2).join('/')), [
    'auth/checkUserV2', 'auth/loginByEmailEncrypt', 'user/info', 'user/tspCode', 'auth/login', 'app/hb',
  ]);
  assert.ok(calls[0].headers['X-HMAC-SIGNATURE']);
  assert.strictEqual(calls[0].headers['client-id'], C.CLIENT_ID);
  assert.strictEqual(calls[2].headers.authorization, 'UC-TOKEN');
  assert.ok(!calls[4].headers.authorization, 'bearer login is unauthenticated');
  assert.ok(calls[4].headers['X-SIGNATURE']);
  assert.strictEqual(JSON.parse(calls[4].body).identifier, 'TSP-CODE');
  assert.strictEqual(store.session.accessToken, jwt);
  assert.strictEqual(store.session.userId, '777');
  assert.strictEqual(calls[5].headers.authorization, jwt);
  assert.notStrictEqual(JSON.parse(calls[1].body).password, 'pw', 'password is encrypted');
});

test('getVehicles maps the vehicle list', async () => {
  const client = makeClient(fakeServer([]));
  const v = await client.getVehicles();
  assert.deepStrictEqual(v, [{ vin: 'VIN1', name: 'Mijn 7X', model: '7X', isOwner: true }]);
});

test('status call sends the encrypted X-VIN and re-logs in after 079012', async () => {
  const calls = [];
  const store = {};
  const client = makeClient(fakeServer(calls, { statusFailures: ['079012'] }), store);
  const raw = await client.getStatus('VIN1');
  assert.strictEqual(parseStatus(raw).soc, 64);
  const statusCalls = calls.filter((c) => c.p.includes('/status/latest'));
  assert.strictEqual(statusCalls.length, 2);
  assert.strictEqual(statusCalls[1].headers['x-vin'], S.encryptVin('VIN1', 'abcdefghijklmnop', '1234567890abcdef'));
  assert.strictEqual(calls.filter((c) => c.p.endsWith('/auth/loginByEmailEncrypt')).length, 2);
});

test('079021 (logged in elsewhere) stops background polling but a user action reclaims the session', async () => {
  const calls = [];
  const store = {};
  const client = makeClient(fakeServer(calls, { statusFailures: ['079021'] }), store);
  await assert.rejects(client.getStatus('VIN1', { interactive: false }), /another device/);
  assert.strictEqual(client.kickedOut, true);
  await assert.rejects(client.getStatus('VIN1', { interactive: false }), /another device/);
  const raw = await client.getStatus('VIN1', { interactive: true });
  assert.strictEqual(parseStatus(raw).soc, 64);
  assert.strictEqual(client.kickedOut, false);
});

test('charge commands go to ms-charge-manage, others to ms-remote-control', async () => {
  const calls = [];
  const client = makeClient(fakeServer(calls));
  await client.sendCommand('VIN1', Commands.setChargeLimit(80));
  await client.sendCommand('VIN1', Commands.climateOn(21, 15));
  const ctl = calls.filter((c) => c.p.endsWith('/control'));
  assert.strictEqual(ctl[0].p, '/ms-charge-manage/api/v1.0/charge/control');
  assert.strictEqual(ctl[1].p, '/ms-remote-control/v1.0/remoteControl/control');
  const body = JSON.parse(ctl[1].body);
  assert.deepStrictEqual(Object.keys(body), ['command', 'serviceId', 'setting']);
  assert.strictEqual(body.setting.serviceParameters[1].value, '21.0');
  // sent body == signed body (canonical)
  assert.strictEqual(ctl[1].body, S.canonicalJson(ctl[1].body));
  assert.strictEqual(ctl[1].headers['X-SIGNATURE'], S.tspSignature('POST', `https://eu-snc-tsp-api-gw.zeekrlife.com${ctl[1].p}`, Object.fromEntries(Object.entries(ctl[1].headers).filter(([k]) => k !== 'X-SIGNATURE')), ctl[1].body, 'PS'));
});

test('missing keys give a clear configuration error', async () => {
  const { ZeekrClient } = loadClientWithMock(async () => ok({}));
  const client = new ZeekrClient({
    getConfig: () => ({ email: 'a@b.c', password: 'x', secrets: { prod_secret: 'x' } }),
    getSession: () => ({}),
    saveSession: () => {},
  });
  await assert.rejects(client.login(), /Missing keys.*hmac_access_key/);
});
