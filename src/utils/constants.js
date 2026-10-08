/**
 * LoginShield - Constants & Configuration
 * Production-ready client-side phishing & fake login page detection
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.Constants = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  return {
    EXTENSION_NAME: 'LoginShield',
    VERSION: '1.0.0',

    // Risk Classifications
    CLASSIFICATIONS: {
      SAFE: 'SAFE / LIKELY LEGITIMATE',
      SUSPICIOUS: 'SUSPICIOUS',
      HIGH_RISK: 'HIGH RISK',
      UNKNOWN: 'UNKNOWN LOGIN PAGE',
      NOT_LOGIN: 'NOT A LOGIN PAGE'
    },

    // Risk Score Thresholds (0 - 100)
    RISK_THRESHOLDS: {
      SAFE_MAX: 29,
      SUSPICIOUS_MAX: 64,
      HIGH_RISK_MIN: 65
    },

    // Login Detection Threshold
    LOGIN_CONFIDENCE_THRESHOLD: 35,

    // Login Signal Weights
    LOGIN_SIGNALS: {
      PASSWORD_FIELD: 50,
      USERNAME_FIELD: 20,
      LOGIN_BUTTON: 15,
      LOGIN_URL: 10,
      AUTH_AUTOCOMPLETE: 10,
      AUTH_TITLE: 10,
      AUTH_FORM_ACTION: 10
    },

    // Matching Weights for Fingerprint Comparison (Sum = 1.0)
    MATCH_WEIGHTS: {
      formStructure: 0.25,
      inputStructure: 0.20,
      formAction: 0.20,
      scriptOrigins: 0.10,
      iframeStructure: 0.10,
      metaTags: 0.05,
      pageStructure: 0.05,
      protocol: 0.05
    },

    // Similarity Bands
    SIMILARITY_BANDS: {
      STRONG: 90,
      GOOD: 75,
      WEAK: 50
    },

    // Risk Penalty Scores
    RISK_PENALTIES: {
      HTTP_LOGIN: 25,
      CROSS_ORIGIN_FORM: 35,
      RAW_IP_FORM: 25,
      UNEXPECTED_EXTERNAL_SCRIPT: 15,
      SUSPICIOUS_IFRAME: 15,
      TRUSTED_MISMATCH: 25,
      LOGIN_STRUCTURE_MISMATCH: 20,
      SUSPICIOUS_HOSTNAME: 20,
      UNKNOWN_LOGIN: 10,
      DATA_OR_JS_ACTION: 35,
      INSECURE_PORT: 15
    },

    // Suspicious Port Definitions
    STANDARD_PORTS: ['80', '443', ''],

    // Common Authentication Keywords (case-insensitive)
    AUTH_KEYWORDS: [
      'login',
      'signin',
      'sign-in',
      'sign_in',
      'authenticate',
      'authentication',
      'account',
      'auth',
      'session',
      'log-in',
      'log_in',
      'passcode',
      'credentials'
    ],

    // Default Settings
    DEFAULT_SETTINGS: {
      enabled: true,
      autoScan: true,
      strictMode: false,
      debounceMs: 600,
      notifyOnHighRisk: true,
      customFingerprints: []
    },

    // Disallowed DOM property reads for privacy enforcement
    FORBIDDEN_PROPERTIES: ['value', 'defaultValue', 'selectionStart', 'selectionEnd']
  };
});
