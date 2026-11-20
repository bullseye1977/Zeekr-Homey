'use strict';

const Homey = require('homey');
const { Commands } = require('../../lib/zeekr/commands');
const { parseStatus } = require('../../lib/zeekr/status');
const { LoggedInElsewhereError, ZeekrError } = require('../../lib/zeekr/ZeekrClient');

/** Re-read the status this long after a command, so Homey shows the car's new state. */
const REFRESH_AFTER_COMMAND_MS = [20 * 1000, 75 * 1000];

/**
 * DEBUG helper: walk the raw status tree and collect every field whose key contains "temp"
 * (case-insensitive), as "path = value". Used to locate the outside-temperature field on cars
 * that report it somewhere other than climateStatus.exteriorTemp.
 */
function findTempFields(node, path = '', out = []) {
  if (node == null) return out;
  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      const p = path ? `${path}.${k}` : k;
      if (v !== null && typeof v === 'object') {
        findTempFields(v, p, out);
      } else if (/temp/i.test(k)) {
        out.push(`${p}=${v}`);
      }
    }
  }
  return out;
}

class ZeekrDevice extends Homey.Device {
  async onInit() {
    this.vin = this.getData().id;
    this.timers = new Set();
    this.pollTimer = null;
    this.prev = null;

    // Add capabilities that were introduced after this device was paired.
    for (const cap of this.driver.manifest.capabilities) {
      if (!this.hasCapability(cap)) await this.addCapability(cap).catch(this.error);
    }
    if (this.getCapabilityValue('target_temperature') == null) {
      await this.setCapabilityValue('target_temperature', 21).catch(this.error);
    }

    this.registerCapabilityListener('locked', async (value) => {
      await this.run(value ? 'lock' : 'unlock', value ? 'lock' : 'unlock');
    });
    this.registerCapabilityListener('zeekr_climate', async (value) => {
      if (value) await this.climateOn(this.getCapabilityValue('target_temperature') || 21, this.getSetting('climate_duration') || 15);
      else await this.climateOff();
    });
    this.registerCapabilityListener('target_temperature', async (value) => {
      // Only re-send when climate is running; otherwise the value is just remembered for the next start.
      if (this.getCapabilityValue('zeekr_climate')) {
        await this.climateOn(value, this.getSetting('climate_duration') || 15);
      }
    });

    this.homey.setTimeout(() => this.poll(), 3000);
  }

  get client() {
    return this.homey.app.client;
  }

  // ---------------------------------------------------------------- polling

  schedulePoll() {
    if (this.pollTimer) this.homey.clearTimeout(this.pollTimer);
    const minutes = Math.max(1, Number(this.getSetting('poll_interval')) || 5);
    this.pollTimer = this.homey.setTimeout(() => this.poll(), minutes * 60 * 1000);
  }

  async poll() {
    try {
      await this.refreshStatus({ interactive: false });
    } catch (err) {
      // already reported via availability/warning
    } finally {
      this.schedulePoll();
    }
  }

  laterRefresh() {
    for (const ms of REFRESH_AFTER_COMMAND_MS) {
      const t = this.homey.setTimeout(() => {
        this.timers.delete(t);
        this.refreshStatus({ interactive: false }).catch(() => {});
      }, ms);
      this.timers.add(t);
    }
  }

  async refreshStatus({ interactive = false } = {}) {
    let raw;
    try {
      raw = await this.client.getStatus(this.vin, { interactive });
    } catch (err) {
      await this.handleError(err);
      throw err;
    }
    if (!this.getAvailable()) await this.setAvailable().catch(this.error);
    await this.unsetWarning().catch(() => {});

    // ---- DEBUG (temperature diagnostics) ----
    // Logs every field in the status whose key mentions "temp", wherever it sits in the tree,
    // plus the whole climate block. Lets us see if/where the car reports the outside temperature.
    // Remove this block once the exterior-temp mapping is confirmed. No GPS/VIN is logged.
    try {
      const temps = findTempFields(raw);
      this.log(`[debug] temp fields (${temps.length}): ${JSON.stringify(temps)}`);
      const climate = raw && raw.additionalVehicleStatus && raw.additionalVehicleStatus.climateStatus;
      this.log(`[debug] climateStatus present: ${climate ? 'yes' : 'no'}`);
      if (climate) this.log(`[debug] climateStatus = ${JSON.stringify(climate)}`);
      const p = parseStatus(raw);
      this.log(`[debug] parsed interior=${p.interiorTemp} exterior=${p.exteriorTemp}`);
    } catch (e) {
      this.log(`[debug] temp diagnostics failed: ${e.message}`);
    }

    await this.applyStatus(parseStatus(raw));
    return true;
  }

  async handleError(err) {
    this.error(`Zeekr: ${err.message}`);
    if (err instanceof LoggedInElsewhereError) {
      await this.setUnavailable(this.homey.__('device.logged_in_elsewhere')).catch(this.error);
    } else if (err instanceof ZeekrError && err.code === 'CONFIG') {
      await this.setUnavailable(this.homey.__('device.not_configured')).catch(this.error);
    } else {
      await this.setWarning(err.message).catch(() => {});
    }
  }

  async set(cap, value) {
    if (value === null || value === undefined || Number.isNaN(value)) return;
    if (!this.hasCapability(cap)) return;
    if (this.getCapabilityValue(cap) === value) return;
    await this.setCapabilityValue(cap, value).catch(this.error);
  }

  async applyStatus(s) {
    let evState = 'plugged_out';
    if (s.charging) evState = 'plugged_in_charging';
    else if (s.pluggedIn) evState = 'plugged_in';

    await this.set('measure_battery', s.soc != null ? Math.max(0, Math.min(100, s.soc)) : null);
    await this.set('zeekr_range', s.range);
    await this.set('ev_charging_state', evState);
    await this.set('zeekr_charge_power', Math.round((s.chargePowerW / 1000) * 10) / 10);
    await this.set('locked', s.locked);
    await this.set('zeekr_climate', s.climateOn);
    await this.set('measure_temperature', s.interiorTemp);
    await this.set('measure_temperature.exterior', s.exteriorTemp);
    await this.set('alarm_contact.doors', s.anyDoorOpen);
    await this.set('alarm_contact.trunk', s.trunkOpen);
    await this.set('alarm_contact.windows', s.windowsOpen);
    await this.set('zeekr_odometer', s.odometer);
    const when = s.updateTime ? new Date(s.updateTime) : new Date();
    await this.set('zeekr_last_update', when.toLocaleString('nl-NL', { timeZone: this.homey.clock.getTimezone(), dateStyle: 'short', timeStyle: 'short' }));

    // ---- flow triggers on transitions (not on the very first status after start-up) ----
    const p = this.prev;
    this.prev = { charging: s.charging, pluggedIn: s.pluggedIn, climateOn: s.climateOn, range: s.range };
    const trig = (id, tokens = {}) => this.homey.flow.getDeviceTriggerCard(id).trigger(this, tokens).catch(this.error);
    const battery = s.soc != null ? s.soc : 0;
    if (p) {
      if (!p.charging && s.charging) trig('charging_started', { battery });
      if (p.charging && !s.charging) trig('charging_stopped', { battery });
      if (!p.pluggedIn && s.pluggedIn) trig('plugged_in');
      if (p.pluggedIn && !s.pluggedIn) trig('unplugged');
      if (s.climateOn != null && p.climateOn != null && p.climateOn !== s.climateOn) {
        trig(s.climateOn ? 'climate_turned_on' : 'climate_turned_off');
      }
      if (s.range != null && p.range != null && s.range !== p.range) trig('range_changed', { range: s.range });
    }
    trig('status_updated', {
      battery,
      range: s.range != null ? s.range : 0,
      latitude: s.latitude != null ? s.latitude : 0,
      longitude: s.longitude != null ? s.longitude : 0,
    });
  }

  // ---------------------------------------------------------------- commands

  /**
   * Send a command from the catalog.
   * @param {string} name    name used in logs / the "command failed" trigger
   * @param {string} builder key in Commands
   */
  async run(name, builder, ...args) {
    const cmd = Commands[builder](...args);
    this.log(`command ${name} -> ${cmd.serviceId}/${cmd.command}`);
    try {
      await this.client.sendCommand(this.vin, cmd, { interactive: true });
    } catch (err) {
      await this.handleError(err);
      this.homey.flow.getDeviceTriggerCard('command_failed')
        .trigger(this, { command: name, error: err.message })
        .catch(this.error);
      throw new Error(this.homey.__('device.command_failed', { error: err.message }));
    }
    if (!this.getAvailable()) await this.setAvailable().catch(this.error);
    this.laterRefresh();
    return true;
  }

  async climateOn(temperature, duration) {
    const t = Number(temperature) || this.getCapabilityValue('target_temperature') || 21;
    const d = Number(duration) || this.getSetting('climate_duration') || 15;
    await this.run('climate_on', 'climateOn', t, d);
    await this.set('target_temperature', Math.round(t * 2) / 2);
    await this.set('zeekr_climate', true);
    return true;
  }

  async climateOff() {
    await this.run('climate_off', 'climateOff');
    await this.set('zeekr_climate', false);
    return true;
  }

  // ---------------------------------------------------------------- lifecycle

  async onSettings({ changedKeys }) {
    if (changedKeys.includes('poll_interval')) this.schedulePoll();
  }

  async onDeleted() {
    this.onUninit();
  }

  onUninit() {
    if (this.pollTimer) this.homey.clearTimeout(this.pollTimer);
    for (const t of this.timers) this.homey.clearTimeout(t);
    this.timers.clear();
  }
}

module.exports = ZeekrDevice;
