'use strict';

const Homey = require('homey');

class ZeekrDriver extends Homey.Driver {
  async onInit() {
    this.registerFlowCards();
    this.log('Zeekr driver ready');
  }

  get client() {
    return this.homey.app.client;
  }

  async onPairListDevices() {
    const info = this.homey.app.getStatusInfo();
    if (!info.hasAccount || info.missingSecrets.length) {
      throw new Error(this.homey.__('pair.not_configured'));
    }
    const vehicles = await this.client.getVehicles({ interactive: true });
    if (!vehicles.length) throw new Error(this.homey.__('pair.no_vehicles'));
    return vehicles.map((v) => ({
      name: v.name,
      data: { id: v.vin },
      store: { model: v.model, isOwner: v.isOwner },
      settings: { vin: v.vin },
    }));
  }

  registerFlowCards() {
    const action = (id, fn) => this.homey.flow.getActionCard(id).registerRunListener(async (args) => fn(args.device, args));
    const condition = (id, fn) => this.homey.flow.getConditionCard(id).registerRunListener(async (args) => fn(args.device, args));

    // ---- actions ----
    action('climate_on', (d, a) => d.climateOn(a.temperature, a.duration));
    action('climate_off', (d) => d.climateOff());
    action('defrost_on', (d, a) => d.run('defrost_on', 'defrostOn', a.duration));
    action('defrost_off', (d) => d.run('defrost_off', 'defrostOff'));
    action('seat_heat', (d, a) => d.run('seat_heat', 'seatHeat', a.seat, Number(a.level)));
    action('seat_vent', (d, a) => d.run('seat_vent', 'seatVent', a.seat, Number(a.level)));
    action('steering_wheel_heat', (d, a) => d.run('steering_wheel_heat', a.state === 'on' ? 'steeringWheelHeatOn' : 'steeringWheelHeatOff'));
    action('charge_start', (d) => d.run('charge_start', 'chargeStart'));
    action('charge_stop', (d) => d.run('charge_stop', 'chargeStop'));
    action('set_charge_limit', (d, a) => d.run('set_charge_limit', 'setChargeLimit', a.percent));
    action('battery_preheat', (d, a) => d.run('battery_preheat', a.state === 'on' ? 'batteryPreheatOn' : 'batteryPreheatOff'));
    action('windows', (d, a) => d.run('windows', a.action === 'vent' ? 'windowsVent' : 'windowsClose'));
    action('trunk', (d, a) => d.run('trunk', a.action === 'open' ? 'trunkOpen' : 'trunkClose'));
    action('signal', (d, a) => d.run('signal', { flash: 'flash', honk: 'honk', both: 'flashHonk' }[a.what] || 'flash'));
    action('sentry', (d, a) => d.run('sentry', a.state === 'on' ? 'sentryOn' : 'sentryOff'));
    action('refresh_status', (d) => d.refreshStatus({ interactive: true }));

    // ---- conditions ----
    condition('is_charging', (d) => d.getCapabilityValue('ev_charging_state') === 'plugged_in_charging');
    condition('is_plugged_in', (d) => {
      const s = d.getCapabilityValue('ev_charging_state');
      return !!s && s !== 'plugged_out';
    });
    condition('is_climate_on', (d) => d.getCapabilityValue('zeekr_climate') === true);
    condition('battery_above', (d, a) => (d.getCapabilityValue('measure_battery') || 0) > a.percent);
    condition('range_above', (d, a) => (d.getCapabilityValue('zeekr_range') || 0) > a.km);
  }
}

module.exports = ZeekrDriver;
