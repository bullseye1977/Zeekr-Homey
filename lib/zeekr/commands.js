'use strict';

/**
 * Remote-control command catalog (serviceId, command, serviceParameters).
 * Ported from OpenZeekr (MIT) core/remote/Command.kt — values captured from the stock app.
 *
 * Every builder returns { serviceId, command, params, durationSec? } for ZeekrClient.sendCommand().
 */

const p = (key, value) => ({ key, value: String(value) });

/** Dot-decimal temperature string ("21.5"); the car rejects a locale comma. */
function tempStr(t) {
  const n = Math.round(Number(t) * 2) / 2; // car accepts 0.5 °C steps
  return n.toFixed(1);
}

function clampInt(v, min, max) {
  return Math.max(min, Math.min(max, Math.round(Number(v))));
}

/** Seat positions used by the ZAF climate service. */
const SEATS = {
  driver: '11',
  passenger: '19',
  rear_left: '21',
  rear_right: '29',
};

const Commands = {
  // ---- doors / locks ----
  lock: () => ({ serviceId: 'RDL', command: 'start', params: [p('door', 'all')] }),
  unlock: () => ({ serviceId: 'RDU', command: 'stop', params: [p('door', 'all')] }),
  trunkOpen: () => ({ serviceId: 'RDU_2', command: 'start', params: [p('target', 'trunk')] }),
  trunkClose: () => ({ serviceId: 'RDL_2', command: 'start', params: [p('target', 'trunk')] }),
  chargeLidOpen: () => ({ serviceId: 'RDO', command: 'start', params: [p('target', 'front-charge-lid')] }),
  chargeLidClose: () => ({ serviceId: 'RDC', command: 'stop', params: [p('target', 'front-charge-lid')] }),

  // ---- climate (ZAF: command is ALWAYS "start"; on/off is the boolean value) ----
  climateOn: (temperature = 21, durationMin = 15) => ({
    serviceId: 'ZAF',
    command: 'start',
    params: [p('AC', 'true'), p('AC.temp', tempStr(temperature)), p('AC.duration', clampInt(durationMin, 1, 30))],
  }),
  climateOff: () => ({ serviceId: 'ZAF', command: 'start', params: [p('AC', 'false')] }),
  defrostOn: (durationMin = 15) => ({
    serviceId: 'ZAF',
    command: 'start',
    params: [p('DF', 'true'), p('DF.duration', clampInt(durationMin, 1, 30)), p('DF.level', '2')],
  }),
  defrostOff: () => ({ serviceId: 'ZAF', command: 'start', params: [p('DF', 'false')] }),

  /** level 0 = off, 1-3 = heat level */
  seatHeat: (seat = 'driver', level = 3, durationMin = 15) => {
    const pos = SEATS[seat] || SEATS.driver;
    const n = clampInt(level, 0, 3);
    if (n === 0) return { serviceId: 'ZAF', command: 'start', params: [p(`SH.${pos}`, 'false')] };
    return {
      serviceId: 'ZAF',
      command: 'start',
      params: [p(`SH.${pos}`, 'true'), p(`SH.${pos}.level`, n), p(`SH.${pos}.duration`, clampInt(durationMin, 1, 30)), p(`SV.${pos}`, 'false')],
    };
  },
  /** level 0 = off, 1-3 = ventilation level */
  seatVent: (seat = 'driver', level = 3, durationMin = 15) => {
    const pos = SEATS[seat] || SEATS.driver;
    const n = clampInt(level, 0, 3);
    if (n === 0) return { serviceId: 'ZAF', command: 'start', params: [p(`SV.${pos}`, 'false')] };
    return {
      serviceId: 'ZAF',
      command: 'start',
      params: [p(`SV.${pos}`, 'true'), p(`SV.${pos}.level`, n), p(`SV.${pos}.duration`, clampInt(durationMin, 1, 30)), p(`SH.${pos}`, 'false')],
    };
  },
  steeringWheelHeatOn: (durationMin = 8) => ({
    serviceId: 'ZAF',
    command: 'start',
    params: [p('SW', 'true'), p('SW.duration', clampInt(durationMin, 1, 30)), p('SW.level', '3')],
  }),
  steeringWheelHeatOff: () => ({ serviceId: 'ZAF', command: 'start', params: [p('SW', 'false')] }),

  // ---- charging (RCS → ms-charge-manage) ----
  chargeStart: () => ({ serviceId: 'RCS', command: 'start', params: [p('rcs.restart', '1')] }),
  chargeStop: () => ({ serviceId: 'RCS', command: 'stop', params: [p('rcs.terminate', '1')] }),
  /** Charge limit in %; `soc` must be the FIRST parameter (per-mille). */
  setChargeLimit: (percent) => ({
    serviceId: 'RCS',
    command: 'start',
    params: [p('soc', clampInt(percent, 50, 100) * 10), p('rcs.setting', '1'), p('altCurrent', '1')],
  }),
  batteryPreheatOn: () => ({ serviceId: 'ZAN', command: 'start', params: [] }),
  batteryPreheatOff: () => ({ serviceId: 'ZAN', command: 'stop', params: [] }),

  // ---- windows / sunroof ----
  windowsClose: () => ({ serviceId: 'RWS', command: 'stop', params: [p('target', 'window')] }),
  windowsVent: () => ({ serviceId: 'RWS', command: 'start', params: [p('target', 'ventilate')] }),
  sunshadeOpen: () => ({ serviceId: 'RWS', command: 'start', params: [p('target', 'sunshade')] }),
  sunshadeClose: () => ({ serviceId: 'RWS', command: 'stop', params: [p('target', 'sunshade')] }),

  // ---- signalling ----
  flash: () => ({ serviceId: 'RHL', command: 'start', params: [p('rhl', 'light-flash')] }),
  honk: () => ({ serviceId: 'RHL', command: 'start', params: [p('rhl', 'horn')] }),
  flashHonk: () => ({ serviceId: 'RHL', command: 'start', params: [p('rhl', 'horn-light-flash')] }),

  // ---- security ----
  sentryOn: () => ({ serviceId: 'RSM', command: 'start', params: [p('rsm', '6')] }),
  sentryOff: () => ({ serviceId: 'RSM', command: 'stop', params: [p('rsm', '6')] }),
};

module.exports = { Commands, SEATS, tempStr };
