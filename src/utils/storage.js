/**
 * LoginShield - Storage Utility
 * Abstraction layer over chrome.storage with fallback to memory/localStorage for testing.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('./constants');
    module.exports = factory(Constants);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.Storage = factory(root.LoginShield.Constants);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants) {
  'use strict';

  const memoryStore = {};

  const isExtensionContext = () => {
    return typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
  };

  const get = (keys) => {
    return new Promise((resolve) => {
      if (isExtensionContext()) {
        chrome.storage.local.get(keys, (res) => resolve(res || {}));
      } else {
        const result = {};
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) {
          if (typeof k === 'string' && memoryStore[k] !== undefined) {
            result[k] = memoryStore[k];
          }
        }
        resolve(result);
      }
    });
  };

  const set = (items) => {
    return new Promise((resolve) => {
      if (isExtensionContext()) {
        chrome.storage.local.set(items, () => resolve());
      } else {
        Object.assign(memoryStore, items);
        resolve();
      }
    });
  };

  const remove = (keys) => {
    return new Promise((resolve) => {
      if (isExtensionContext()) {
        chrome.storage.local.remove(keys, () => resolve());
      } else {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) {
          delete memoryStore[k];
        }
        resolve();
      }
    });
  };

  return {
    async getSettings() {
      const data = await get('settings');
      return Object.assign({}, Constants.DEFAULT_SETTINGS, data.settings || {});
    },

    async saveSettings(settings) {
      const current = await this.getSettings();
      const updated = Object.assign({}, current, settings);
      await set({ settings: updated });
      return updated;
    },

    async getCustomFingerprints() {
      const data = await get('custom_fingerprints');
      return Array.isArray(data.custom_fingerprints) ? data.custom_fingerprints : [];
    },

    async addCustomFingerprint(fingerprint) {
      const current = await this.getCustomFingerprints();
      const existsIdx = current.findIndex((f) => f.id === fingerprint.id);
      if (existsIdx >= 0) {
        current[existsIdx] = fingerprint;
      } else {
        current.push(fingerprint);
      }
      await set({ custom_fingerprints: current });
      return current;
    },

    async removeCustomFingerprint(id) {
      const current = await this.getCustomFingerprints();
      const filtered = current.filter((f) => f.id !== id);
      await set({ custom_fingerprints: filtered });
      return filtered;
    },

    async getScanResult(tabId) {
      const key = `scan_tab_${tabId}`;
      const data = await get(key);
      return data[key] || null;
    },

    async saveScanResult(tabId, result) {
      const key = `scan_tab_${tabId}`;
      await set({ [key]: result });
      return result;
    },

    async clearScanResult(tabId) {
      const key = `scan_tab_${tabId}`;
      await remove(key);
    },

    _getMemoryStore() {
      return memoryStore;
    }
  };
});
