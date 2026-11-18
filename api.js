'use strict';

/** Web API used by the app settings page (settings/index.html). */
module.exports = {
  async testLogin({ homey }) {
    try {
      return await homey.app.testLogin();
    } catch (err) {
      return { ok: false, error: err.message };
    }
  },

  async logout({ homey }) {
    homey.app.client.logout();
    return { ok: true };
  },

  async status({ homey }) {
    return homey.app.getStatusInfo();
  },
};
