/**
 * LoginShield - DOM Fingerprint Generator
 * Generates deterministic, resilient structural fingerprints of login pages.
 *
 * Normalizes dynamic tokens, timestamps, and transient classes so fingerprints
 * represent semantic DOM architecture rather than fragile layout artifacts.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    module.exports = factory(Constants);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.Fingerprint = factory(root.LoginShield.Constants);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants) {
  'use strict';

  /**
   * Fast, deterministic 32-bit FNV-1a hash formatted as 8-character hex string.
   */
  function fnv1a(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = (hash * 0x01000193) >>> 0;
    }
    return ('00000000' + hash.toString(16)).slice(-8);
  }

  /**
   * Normalizes an origin/hostname by removing trailing slashes and port 80/443 defaults.
   */
  function normalizeOrigin(origin) {
    if (!origin) return '';
    return origin.toLowerCase().trim().replace(/:(80|443)$/, '');
  }

  /**
   * Generates a deterministic structural fingerprint from a DOM analysis object.
   */
  function generateFingerprint(domAnalysis) {
    if (!domAnalysis) return null;

    // 1. Normalized Forms profile
    const formsProfile = (domAnalysis.forms || []).map((form) => {
      return {
        method: (form.method || 'GET').toUpperCase(),
        actionPath: form.actionPath || '',
        isSameOrigin: Boolean(form.isSameOrigin),
        isCrossOrigin: Boolean(form.isCrossOrigin),
        isKnownAuthProvider: Boolean(form.isKnownAuthProvider),
        inputTypes: (form.inputTypes || []).slice().sort(),
        inputCount: form.inputCount || 0,
        hasPasswordField: Boolean(form.hasPasswordField),
        hasUsernameField: Boolean(form.hasUsernameField),
        buttonCount: form.buttonCount || 0
      };
    });

    // 2. Normalized Inputs sequence & summary
    const inputTypesSequence = (domAnalysis.inputs || []).map((inp) => inp.type || 'text');
    const inputTypesSorted = inputTypesSequence.slice().sort();
    const autocompleteTypesSorted = Array.from(
      new Set((domAnalysis.inputs || []).map((inp) => inp.autocomplete).filter(Boolean))
    ).sort();
    const idPatternsSorted = Array.from(
      new Set((domAnalysis.inputs || []).map((inp) => inp.idPattern).filter(Boolean))
    ).sort();

    // 3. Script Origins (sorted unique origins)
    const scriptOrigins = Array.from(
      new Set(
        (domAnalysis.scripts || [])
          .filter((s) => !s.isInline && s.origin)
          .map((s) => normalizeOrigin(s.origin))
      )
    ).sort();

    // 4. Iframe Structure
    const iframes = (domAnalysis.iframes || []).map((f) => ({
      origin: normalizeOrigin(f.origin),
      isCrossOrigin: Boolean(f.isCrossOrigin),
      sandboxed: Boolean(f.sandboxed)
    }));

    // 5. Meta Tag Keys
    const metaKeys = Array.from(
      new Set(
        (domAnalysis.metaTags || []).map((m) => (m.name || m.property || '').toLowerCase()).filter(Boolean)
      )
    ).sort();

    // 6. Protocol
    const protocol = (domAnalysis.protocol || '').toLowerCase();

    // Compile deterministic canonical representation
    const canonical = {
      v: '1.0',
      protocol,
      forms: formsProfile,
      inputs: {
        sequence: inputTypesSequence,
        types: inputTypesSorted,
        autocompletes: autocompleteTypesSorted,
        idPatterns: idPatternsSorted,
        total: domAnalysis.inputs ? domAnalysis.inputs.length : 0
      },
      scripts: scriptOrigins,
      iframes: {
        count: iframes.length,
        hasCrossOrigin: iframes.some((f) => f.isCrossOrigin)
      },
      metaKeys
    };

    const canonicalJson = JSON.stringify(canonical);
    const hash = fnv1a(canonicalJson);

    return {
      version: '1.0',
      hash,
      canonical,
      protocol,
      formCount: formsProfile.length,
      forms: formsProfile,
      inputTypes: inputTypesSorted,
      inputSequence: inputTypesSequence,
      autocompleteTypes: autocompleteTypesSorted,
      idPatterns: idPatternsSorted,
      scriptOrigins,
      iframeCount: iframes.length,
      hasCrossOriginIframe: iframes.some((f) => f.isCrossOrigin),
      metaKeys
    };
  }

  return {
    generateFingerprint,
    normalizeOrigin,
    fnv1a
  };
});
