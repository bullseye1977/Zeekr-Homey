'use strict';

const crypto = require('crypto');
const C = require('./constants');
const S = require('./signing');
const { request } = require('./http');

class ZeekrError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ZeekrError';
    this.code = code;
  }
}

/** 079012: the bearer token expired. */
class SessionExpiredError extends ZeekrError {}
/** 079021: the account logged in on another device (e.g. the official Zeekr app). */
class LoggedInElsewhereError extends ZeekrError {}

const REQUIRED_SECRETS = ['hmac_access_key', 'hmac_secret_key', 'password_public_key', 'prod_secret', 'vin_key', 'vin_iv'];

/**
 * Zeekr cloud client: account login + TSP gateway (vehicle list, status, remote control).
 * Ported from OpenZeekr (MIT) core/net/AccountLogin.kt, Interceptors.kt and remote/Repositories.kt.
 *
 * Deliberately left out (not needed for Homey): the BLE digital key, the ECARX/xchanger DK session
 * and the push-endpoint registration.
 *
 * @param {object} opts
 * @param {() => object} opts.getConfig returns { region, countryCode, email, password, secrets }
 * @param {() => object} opts.getSession returns the persisted session { accessToken, userId, appInstanceId }
 * @param {(session: object) => void} opts.saveSession persists the session
 * @param {(...args) => void} [opts.log]
 */
class ZeekrClient {
  constructor({ getConfig, getSession, saveSession, log }) {
    this.getConfig = getConfig;
    this.getSession = getSession;
    this.saveSession = saveSession;
    this.log = log || (() => {});
    this.ucToken = '';
    this.loginPromise = null;
    /** Set after a 079021; background polling then stops until a user action logs in again. */
    this.kickedOut = false;
  }

  // ---------------------------------------------------------------- config helpers

  cfg() {
    const c = this.getConfig() || {};
    const r = C.region(c.region);
    return {
      region: r,
      countryCode: (c.countryCode || r.countryCode || 'SE').toUpperCase(),
      email: String(c.email || '').trim(),
      password: String(c.password || ''),
      secrets: c.secrets || {},
    };
  }

  session() {
    const s = { ...(this.getSession() || {}) };
    if (!s.appInstanceId) {
      s.appInstanceId = crypto.randomUUID();
      this.saveSession(s);
    }
    return s;
  }

  updateSession(patch) {
    const s = { ...this.session(), ...patch };
    this.saveSession(s);
    return s;
  }

  static missingSecrets(secrets) {
    return REQUIRED_SECRETS.filter((k) => !String((secrets || {})[k] || '').trim());
  }

  get loggedIn() {
    return !!this.session().accessToken;
  }

  // ---------------------------------------------------------------- response handling

  static parse(resp, url) {
    const ep = new URL(url).pathname.split('/').pop();
    let root;
    try {
      root = resp.text ? JSON.parse(resp.text) : null;
    } catch (e) {
      throw new ZeekrError(`HTTP ${resp.status}: invalid response from ${ep}`, `HTTP${resp.status}`);
    }
    const text = resp.text || '';
    const code = root && root.code != null ? String(root.code) : '';
    if (code === '079021' || (resp.status === 401 && text.includes('079021'))) {
      throw new LoggedInElsewhereError('Account is logged in on another device (e.g. the Zeekr app)', '079021');
    }
    if (code === '079012' || (resp.status === 401 && text.includes('079012'))) {
      throw new SessionExpiredError('Session expired', '079012');
    }
    if (!root) throw new ZeekrError(`HTTP ${resp.status}: empty response from ${ep}`, `HTTP${resp.status}`);
    return root;
  }

  static requireSuccess(root, url) {
    const ok = root.success === true || root.success === 'true' || String(root.code) === '000000';
    if (!ok) {
      const ep = new URL(url).pathname.split('/').pop();
      const msg = root.msg || root.message || ZeekrClient.friendlyError(String(root.code)) || 'request failed';
      throw new ZeekrError(`${msg} (${root.code}) @ ${ep}`, String(root.code));
    }
    return root;
  }

  static friendlyError(code) {
    switch (code) {
      case '9007': return 'Account not found in this region - check the email address and the selected region';
      case '9300':
      case '9301': return 'Login rejected - check your password';
      case '079025': return 'Signature rejected - check prod_secret';
      case '037005': return 'The car could not execute the command (is it online?)';
      default: return null;
    }
  }

  // ---------------------------------------------------------------- user-center (login) transport

  async uc(method, path, bodyObj) {
    const c = this.cfg();
    const url = `${c.region.azureHost}/${c.region.usercenterSegment}/${path}`;
    // ucPost with no body sends "{}" (OpenZeekr behaviour); GET has no body.
    const body = method === 'GET' ? null : JSON.stringify(bodyObj || {});
    const headers = { ...C.defaultHeaders(c.countryCode) };
    if (this.ucToken) headers.authorization = this.ucToken;
    Object.assign(headers, S.usercenterHmac(method, url, c.secrets.hmac_access_key, c.secrets.hmac_secret_key, body));
    const resp = await request(method, url, headers, body);
    const root = ZeekrClient.requireSuccess(ZeekrClient.parse(resp, url), url);
    return root.data && typeof root.data === 'object' ? root.data : null;
  }

  // ---------------------------------------------------------------- TSP transport

  async tspRaw(method, path, { body = null, vin = null } = {}) {
    const c = this.cfg();
    const s = this.session();
    const url = `${c.region.tspBaseUrl.replace(/\/+$/, '')}/${path}`;
    const headers = { ...C.loggedInHeaders(c.region.projectId, s.appInstanceId) };
    if (s.accessToken) headers.authorization = s.accessToken;
    if (vin && c.secrets.vin_key && c.secrets.vin_iv) {
      headers['x-vin'] = S.encryptVin(vin, c.secrets.vin_key, c.secrets.vin_iv);
    }
    headers['X-API-SIGNATURE-NONCE'] = crypto.randomUUID();
    headers['X-TIMESTAMP'] = String(Date.now());
    // The gateway hashes the body as received, so send the canonical (sorted-key) form.
    const bodyStr = body == null ? null : S.canonicalJson(body);
    headers['X-SIGNATURE'] = S.tspSignature(method, url, headers, bodyStr, c.secrets.prod_secret);
    const resp = await request(method, url, headers, bodyStr);
    return { root: ZeekrClient.parse(resp, url), url };
  }

  /**
   * Authenticated TSP call with automatic re-login on token expiry.
   * @param {boolean} interactive true for user-initiated actions (flows / device controls). Only an
   *   interactive call may take the session back after another device (the Zeekr app) logged in.
   */
  async tsp(method, path, { body = null, vin = null, interactive = false } = {}) {
    await this.ensureLoggedIn({ interactive });
    try {
      const { root, url } = await this.tspRaw(method, path, { body, vin });
      return ZeekrClient.requireSuccess(root, url);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        this.log('Zeekr session expired, logging in again');
        this.updateSession({ accessToken: '' });
        await this.login();
      } else if (err instanceof LoggedInElsewhereError) {
        this.updateSession({ accessToken: '' });
        this.kickedOut = true;
        if (!interactive) throw err;
        this.log('Account was logged in elsewhere; taking the session back (user action)');
        await this.login();
      } else {
        throw err;
      }
      const { root, url } = await this.tspRaw(method, path, { body, vin });
      return ZeekrClient.requireSuccess(root, url);
    }
  }

  async ensureLoggedIn({ interactive = false } = {}) {
    if (this.session().accessToken) return;
    if (this.kickedOut && !interactive) {
      throw new LoggedInElsewhereError('Account is logged in on another device (e.g. the Zeekr app)', '079021');
    }
    await this.login();
  }

  // ---------------------------------------------------------------- login

  login() {
    if (!this.loginPromise) {
      this.loginPromise = this.doLogin().finally(() => { this.loginPromise = null; });
    }
    return this.loginPromise;
  }

  async doLogin() {
    const c = this.cfg();
    if (!c.email || !c.password) throw new ZeekrError('Email/password not set (app settings)', 'CONFIG');
    const missing = ZeekrClient.missingSecrets(c.secrets);
    if (missing.length) throw new ZeekrError(`Missing keys in app settings: ${missing.join(', ')}`, 'CONFIG');
    this.log(`Zeekr login (${c.region.code})…`);
    this.ucToken = '';

    // 1. check user exists - validates the HMAC before a password is ever submitted (no lockout on a bad key)
    await this.uc('POST', C.CHECKUSER_URL, { email: c.email, checkType: '1' });

    // 2. login (RSA-encrypted password) -> user-center token
    const loginData = await this.uc('POST', C.LOGIN_URL, {
      code: '', codeId: '', email: c.email, password: S.encryptPassword(c.password, c.secrets.password_public_key),
    });
    if (!loginData || loginData.tokenName !== 'Authorization' || !loginData.tokenValue) {
      throw new ZeekrError('Login token missing', 'LOGIN');
    }
    this.ucToken = loginData.tokenValue;

    // 3. user info
    const info = await this.uc('POST', C.USERINFO_URL, null);
    const infoUserId = info && (info.userId || info.id);

    // 4. tsp code
    const tspCodeData = await this.uc('GET', `${C.TSPCODE_URL}?tspClientId=${C.CLIENT_ID}`);
    const tspCode = tspCodeData && tspCodeData.code;
    if (!tspCode) throw new ZeekrError('No TSP code received', 'LOGIN');

    // 5. bearer login (TSP) -> accessToken
    this.updateSession({ accessToken: '' });
    const loginDeviceId = `${C.DEVICE_MANUFACTURE}-${C.DEVICE_MODEL}-${C.DEVICE_SDK_INT}-${C.DEVICE_RELEASE}`;
    const { root, url } = await this.tspRaw('POST', C.BEARERLOGIN_URL, {
      body: {
        identifier: tspCode,
        identityType: 10,
        loginDeviceId,
        loginDeviceJgId: '',
        loginDeviceType: 1,
        loginPhoneBrand: C.DEVICE_MANUFACTURE,
        loginPhoneModel: C.DEVICE_MODEL,
        loginSystem: 'Android',
      },
    });
    ZeekrClient.requireSuccess(root, url);
    const bearer = root.data && root.data.accessToken;
    if (!bearer) throw new ZeekrError('No bearer token received', 'LOGIN');

    this.updateSession({
      accessToken: bearer,
      userId: S.jwtClaim(bearer, 'userId') || (infoUserId ? String(infoUserId) : ''),
    });
    this.kickedOut = false;

    // 6. mark this "device" online (the car only executes commands for the online device)
    await this.heartbeat().catch((e) => this.log(`heartbeat after login failed: ${e.message}`));
    this.log('Zeekr login OK');
  }

  logout() {
    this.ucToken = '';
    this.kickedOut = false;
    this.updateSession({ accessToken: '', userId: '' });
  }

  // ---------------------------------------------------------------- API

  async heartbeat() {
    const s = this.session();
    const { root, url } = await this.tspRaw('POST', C.HEARTBEAT_URL, {
      body: { deviceId: s.appInstanceId, deviceType: 1, hbType: 3, ts: Date.now() },
    });
    return ZeekrClient.requireSuccess(root, url);
  }

  /** @returns {Promise<Array<{ vin: string, name: string, model: string, isOwner: boolean }>>} */
  async getVehicles({ interactive = true } = {}) {
    const root = await this.tsp('GET', C.VEHLIST_URL, { interactive });
    let list = root.data;
    if (list && !Array.isArray(list)) list = list.list || list.records || list.vehicleList || [list];
    return (list || [])
      .filter((v) => v && v.vin)
      .map((v) => ({
        vin: String(v.vin),
        name: v.nickName || v.vehicleNickname || v.vehNickname || v.remark || v.modelName || v.seriesName || 'Zeekr',
        model: v.modelName || v.seriesName || v.appModelCode || v.appInnerCode || '',
        isOwner: String(v.isOwner).toLowerCase() === 'true' || String(v.isOwner) === '1',
      }));
  }

  /** Raw vehicle status tree (`data` of vehicle/status/latest). */
  async getStatus(vin, { interactive = false } = {}) {
    await this.ensureLoggedIn({ interactive });
    await this.heartbeat().catch(() => {});
    const root = await this.tsp('GET', C.STATUS_URL, { vin, interactive });
    if (!root.data) throw new ZeekrError('No status data', 'STATUS');
    return root.data;
  }

  /**
   * Send a remote command.
   * @param {string} vin
   * @param {{ serviceId: string, command: string, params?: Array<{key: string, value: string}>, durationSec?: number }} cmd
   */
  async sendCommand(vin, cmd, { interactive = true } = {}) {
    await this.ensureLoggedIn({ interactive });
    // The car only executes commands for the account's ONLINE device: refresh that first.
    await this.heartbeat().catch(() => {});

    // Dedup by key, last value wins (keeps the original position, like a LinkedHashMap).
    const params = new Map();
    for (const p of cmd.params || []) params.set(p.key, { key: p.key, value: String(p.value) });
    const serviceParameters = [...params.values()];

    let root;
    if (cmd.serviceId === 'RDU_2' || cmd.serviceId === 'RDL_2') {
      // "System B" (ECARX device-api): flat body, PUT with the VIN in the path.
      const s = this.session();
      const body = {
        serviceId: cmd.serviceId,
        command: cmd.command,
        creator: 'tc',
        userId: s.userId || '',
        timestamp: String(Date.now()),
        serviceParameters,
        operationScheduling: cmd.durationSec ? { duration: cmd.durationSec } : {},
      };
      root = await this.tspEcarx(vin, body, interactive);
    } else {
      const setting = { serviceParameters };
      if (cmd.durationSec) setting.operationScheduling = { duration: cmd.durationSec };
      const body = { command: cmd.command, serviceId: cmd.serviceId, setting };
      // Charging (RCS) is its own service (ms-charge-manage), same body shape.
      const path = cmd.serviceId === 'RCS' ? C.CHARGE_CONTROL_URL : C.CONTROL_URL;
      root = await this.tsp('POST', path, { body, vin, interactive });
    }
    return root.data || { status: 'ok' };
  }

  async tspEcarx(vin, body, interactive) {
    const path = `${C.ECARX_CONTROL_URL}${encodeURIComponent(vin)}`;
    const attempt = async () => {
      const { root } = await this.tspRaw('PUT', path, { body, vin });
      const ok = root.success === true || Number(root.code) === 1000 || Number(root.code) === 200 || String(root.code) === '000000';
      if (!ok) throw new ZeekrError(`${root.msg || root.message || 'command failed'} (${root.code})`, String(root.code));
      return root;
    };
    try {
      return await attempt();
    } catch (err) {
      if (err instanceof SessionExpiredError || (err instanceof LoggedInElsewhereError && interactive)) {
        this.updateSession({ accessToken: '' });
        await this.login();
        return attempt();
      }
      throw err;
    }
  }
}

module.exports = {
  ZeekrClient,
  ZeekrError,
  SessionExpiredError,
  LoggedInElsewhereError,
  REQUIRED_SECRETS,
};
