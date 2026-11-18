'use strict';

/**
 * Tolerant mapping of the raw vehicle status tree (ms-vehicle-status … /status/latest) to a flat object.
 * Interpretation rules ported from OpenZeekr (MIT) net/model/Models.kt (ElectricStatusVo, ClimateStatus …):
 *  - SOC: `stateOfCharge` is blank on some cars → fall back to `chargeLevel` (%).
 *  - `isCharging` is unreliable → derive from `chargerState` {2,15,24,28,30} or live power > 100 W.
 *  - power: DC = pile U·I, AC 1-phase = U·I, AC 3-phase (U ≥ 300 V line-to-line) = √3·U·I.
 *  - doors / trunk: "0" = closed, anything else = open. Central lock: "1" = locked.
 */

const CHARGING_STATES = new Set([2, 15, 24, 28, 30]);
const CONNECTED_STATES = new Set([1, 2, 3]);

const obj = (o, k) => (o && typeof o[k] === 'object' && o[k] !== null ? o[k] : null);
const str = (o, k) => {
  if (!o || o[k] == null) return null;
  const s = String(o[k]).trim();
  return s === '' ? null : s;
};
const num = (o, k) => {
  const s = str(o, k);
  if (s == null) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
};
const bool = (o, k) => {
  const s = str(o, k);
  if (s == null) return null;
  const l = s.toLowerCase();
  if (l === 'true' || l === '1') return true;
  if (l === 'false' || l === '0') return false;
  return null;
};

function chargePowerW(e) {
  if (!e) return null;
  const dcI = num(e, 'dcChargePileIAct');
  const dcU = num(e, 'dcChargePileUAct');
  if (dcI && dcU && Math.abs(dcI) > 0 && Math.abs(dcU) > 0) return Math.abs(dcI) * Math.abs(dcU);
  const a = num(e, 'chargeIAct');
  const v = num(e, 'chargeUAct');
  if (a == null || v == null || a <= 0 || v <= 0) return null;
  return v >= 300 ? Math.sqrt(3) * v * a : v * a;
}

function parseStatus(root) {
  const basic = obj(root, 'basicVehicleStatus');
  const add = obj(root, 'additionalVehicleStatus');
  const climate = obj(add, 'climateStatus');
  const safety = obj(add, 'drivingSafetyStatus');
  const ev = obj(add, 'electricVehicleStatus');
  const maint = obj(add, 'maintenanceStatus');
  const pos = obj(basic, 'position');

  // ---- battery / charging ----
  const soc = num(ev, 'stateOfCharge') ?? num(ev, 'chargeLevel');
  const powerW = chargePowerW(ev);
  const chargerState = num(ev, 'chargerState');
  const charging = (chargerState != null && CHARGING_STATES.has(chargerState)) || (powerW || 0) > 100;
  const conn = num(ev, 'statusOfChargerConnection');
  const dcConn = num(ev, 'dcDcConnectStatus');
  const pluggedIn = charging || (conn != null && CONNECTED_STATES.has(conn)) || (dcConn != null && CONNECTED_STATES.has(dcConn));
  const evRange = num(ev, 'distanceToEmptyOnBatteryOnly');
  const range = evRange && evRange > 0 ? evRange : num(basic, 'distanceToEmpty');
  const ttf = num(ev, 'timeToFullyCharged');

  // ---- doors / locks ----
  const open = (k) => {
    const s = str(safety, k);
    return s == null ? null : s !== '0';
  };
  const doorKeys = ['doorOpenStatusDriver', 'doorOpenStatusPassenger', 'doorOpenStatusDriverRear', 'doorOpenStatusPassengerRear'];
  const doorStates = doorKeys.map(open).filter((x) => x !== null);
  const lockStr = str(safety, 'centralLockingStatus');

  // ---- windows ----
  const winPos = ['winPosDriver', 'winPosPassenger', 'winPosDriverRear', 'winPosPassengerRear'].map((k) => num(climate, k));
  let windowsOpen = null;
  if (winPos.some((x) => x != null)) {
    windowsOpen = winPos.some((x) => (x || 0) > 0);
  } else {
    const ws = ['winStatusDriver', 'winStatusDriverRear', 'winStatusPassenger', 'winStatusPassengerRear'].map((k) => str(climate, k));
    if (ws.some((x) => x != null)) windowsOpen = ws.some((s) => s != null && s !== '0' && s !== '2');
  }

  const updateTime = num(root, 'updateTime');

  return {
    soc,
    range,
    charging,
    pluggedIn,
    chargePowerW: charging ? (powerW || 0) : 0,
    timeToFullMin: charging && ttf && ttf > 0 ? ttf : null,
    chargePortOpen: str(ev, 'chargeLidAcStatus') === '1' || str(ev, 'chargeLidDcAcStatus') === '1',
    batteryPreheating: bool(ev, 'hvBatteryPreHeatingActive'),

    locked: lockStr == null ? null : lockStr === '1',
    anyDoorOpen: doorStates.length ? doorStates.some(Boolean) : null,
    trunkOpen: open('trunkOpenStatus'),
    hoodOpen: open('engineHoodOpenStatus'),
    windowsOpen,

    interiorTemp: num(climate, 'interiorTemp'),
    exteriorTemp: num(climate, 'exteriorTemp'),
    climateOn: bool(climate, 'preClimateActive'),
    defrostOn: (() => {
      const d = str(climate, 'defrost');
      return d == null ? null : d !== '0' && d.toLowerCase() !== 'false';
    })(),

    odometer: num(maint, 'odometer'),
    lowVoltageBattery: num(obj(maint, 'mainBatteryStatus'), 'voltage'),
    daysToService: num(maint, 'daysToService'),

    latitude: num(pos, 'latitude'),
    longitude: num(pos, 'longitude'),
    speed: num(basic, 'speed'),

    updateTime: updateTime && updateTime > 0 ? updateTime : null,
  };
}

module.exports = { parseStatus };
