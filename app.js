'use strict';

const Homey = require('homey');
const { ZeekrClient } = require('./lib/zeekr/ZeekrClient');

/** Settings keys that, when changed, invalidate the current Zeekr session. */
const ACCOUNT_KEYS = ['email', 'password', 'region', 'countryCode', 'secrets'];

class ZeekrApp extends Homey.App {
  async onInit() {
    this.client = new ZeekrClient({
      getConfig: () => ({
        region: this.homey.settings.get('region') || 'EU',
        countryCode: this.homey.settings.get('countryCode') || '',
        email: this.homey.settings.get('email') || '',
        password: this.homey.settings.get('password') || '',
        secrets: this.homey.settings.get('secrets') || {},
      }),
      getSession: () => this.homey.settings.get('session') || {},
      saveSession: (s) => this.homey.settings.set('session', s),
      log: (...args) => this.log(...args),
    });

    this.homey.settings.on('set', (key) => {
      if (ACCOUNT_KEYS.includes(key)) {
        this.log(`Setting "${key}" changed - clearing Zeekr session`);
        this.client.logout();
      }
    });

    this.log('Zeekr app started');
  }

  /** Used by the settings page: log in from scratch and list the cars on the account. */
  async testLogin() {
    this.client.logout();
    await this.client.login();
    const vehicles = await this.client.getVehicles();
    return {
      ok: true,
      vehicles: vehicles.map((v) => ({ name: v.name, model: v.model, isOwner: v.isOwner })),
    };
  }

  getStatusInfo() {
    const secrets = this.homey.settings.get('secrets') || {};
    return {
      loggedIn: this.client.loggedIn,
      kickedOut: this.client.kickedOut,
      missingSecrets: ZeekrClient.missingSecrets(secrets),
      hasAccount: !!(this.homey.settings.get('email') && this.homey.settings.get('password')),
    };
  }
}

module.exports = ZeekrApp;
