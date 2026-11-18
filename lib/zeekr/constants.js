'use strict';

/**
 * Non-secret Zeekr app constants and endpoint paths.
 * Ported from OpenZeekr (MIT, https://github.com/borconi/openzeekr) — core/net/ZeekrConst.kt + Region.kt.
 *
 * These values are app-global and present in plain text in the public Zeekr APK.
 * The actual secrets (HMAC keys, prod_secret, VIN key/iv) are NEVER stored here:
 * the user supplies them via the app settings page.
 */

const REGIONS = {
  EU: {
    code: 'EU',
    name: 'Europe (EU)',
    tspBaseUrl: 'https://eu-snc-tsp-api-gw.zeekrlife.com',
    azureHost: 'https://gateway-pub-azure.zeekr.eu',
    usercenterSegment: 'zeekr-cuc-idaas',
    projectId: 'ZEEKR_EU',
    // OpenZeekr's default; known to work for EU accounts from other countries too.
    countryCode: 'SE',
    verified: true,
  },
  SEA: {
    code: 'SEA',
    name: 'Australia + SEA',
    tspBaseUrl: 'https://sea-snc-tsp-api-gw.zeekrlife.com',
    azureHost: 'https://gateway-pub-hw-em-sg.zeekrlife.com',
    usercenterSegment: 'zeekr-cuc-idaas-sea',
    projectId: 'ZEEKR_SEA',
    countryCode: 'SG',
    verified: false,
  },
  LA: {
    code: 'LA',
    name: 'Latin America',
    tspBaseUrl: 'https://la-snc-tsp-api-gw.zeekrlife.com',
    azureHost: 'https://gateway-pub-hw-em-mx.zeekrlife.com',
    usercenterSegment: 'zeekr-cuc-idaas-la',
    projectId: 'ZEEKR_LA',
    countryCode: 'BR',
    verified: false,
  },
  ME: {
    code: 'ME',
    name: 'Middle East',
    tspBaseUrl: 'https://me-snc-tsp-api-gw.zeekrlife.com',
    azureHost: 'https://gateway-pub-aws-em-ae.zeekrlife.com',
    usercenterSegment: 'zeekr-cuc-idaas-uae',
    projectId: 'ZEEKR_ME',
    countryCode: 'AE',
    verified: false,
  },
};

function region(code) {
  return REGIONS[String(code || 'EU').toUpperCase()] || REGIONS.EU;
}

// ---- user-center paths (relative to {azureHost}/{usercenterSegment}/) ----
const CHECKUSER_URL = 'auth/checkUserV2';
const LOGIN_URL = 'auth/loginByEmailEncrypt';
const USERINFO_URL = 'user/info';
const TSPCODE_URL = 'user/tspCode';

// ---- TSP paths (relative to tspBaseUrl/) ----
const BEARERLOGIN_URL = 'ms-user-auth/v1.0/auth/login';
const VEHLIST_URL = 'ms-app-bff/api/v4.0/veh/vehicle-list?needSharedCar=true';
const HEARTBEAT_URL = 'ms-app-online-manager/api/v1.0/app/hb';
const STATUS_URL = 'ms-vehicle-status/api/v1.0/vehicle/status/latest?latest=false&target=new';
const CONTROL_URL = 'ms-remote-control/v1.0/remoteControl/control';
const CHARGE_CONTROL_URL = 'ms-charge-manage/api/v1.0/charge/control';
const ECARX_CONTROL_URL = 'remote-control/vehicle/telematics/'; // + vin

const CLIENT_ID = '1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc';

// Device identity presented to the backend (same "Pixel 7 / Android 16" identity OpenZeekr uses).
const DEVICE_MANUFACTURE = 'google';
const DEVICE_MODEL = 'Pixel 7';
const DEVICE_SDK_INT = '36';
const DEVICE_RELEASE = '16';

/** DEFAULT_HEADERS for user-center (login) requests. */
function defaultHeaders(countryCode) {
  return {
    'accept-language': 'en-AU',
    'app-authorization': '1003',
    'app-code': '32816dbd-ff17-47b7-e250-5dae7d9f8cd4',
    appcode: 'eu-app',
    appid: 'TSP',
    appsecret: 'zeekr_tis',
    appversion: '1.4.1',
    'call-source': 'android',
    'client-id': CLIENT_ID,
    'Content-Type': 'application/json; charset=UTF-8',
    country: countryCode,
    'device-name': 'sdk_gphone64_x86_64',
    'device-type': 'app',
    language: 'en',
    msgappid: '11002',
    msgclientid: '1003',
    registcountry: countryCode,
    'tmp-tenant-code': '3300743799505195008',
    'user-agent': 'Device/GoogleAppName/com.zeekr.globalAppVersion/1.4.1Platform/androidOSVersion/16Ditto/true',
  };
}

/** LOGGED_IN_HEADERS base for TSP (app-signed) requests. */
function loggedInHeaders(projectId, deviceId) {
  return {
    'ACCEPT-LANGUAGE': 'en-GB',
    AppId: 'ONEX97FB91F061405',
    'Content-Type': 'application/json; charset=UTF-8',
    'user-agent': 'okhttp/4.12.0',
    'X-API-SIGNATURE-VERSION': '2.0',
    'X-APP-ID': 'ZEEKRCNCH001M0001',
    'X-APP-OS-VERSION': '',
    'x-device-id': deviceId,
    'x-p': 'Android',
    'X-PLATFORM': 'APP',
    'X-PROJECT-ID': projectId,
  };
}

module.exports = {
  REGIONS,
  region,
  CHECKUSER_URL,
  LOGIN_URL,
  USERINFO_URL,
  TSPCODE_URL,
  BEARERLOGIN_URL,
  VEHLIST_URL,
  HEARTBEAT_URL,
  STATUS_URL,
  CONTROL_URL,
  CHARGE_CONTROL_URL,
  ECARX_CONTROL_URL,
  CLIENT_ID,
  DEVICE_MANUFACTURE,
  DEVICE_MODEL,
  DEVICE_SDK_INT,
  DEVICE_RELEASE,
  defaultHeaders,
  loggedInHeaders,
};
