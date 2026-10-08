/**
 * LoginShield - Login Page Detector
 * Evaluates DOM elements, forms, modal dialogs, popups, inputs, buttons, and page metadata
 * to calculate a multi-signal login confidence score without ever accessing input values.
 *
 * Fully supports modern SPAs, popups, and modal login interfaces.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    module.exports = factory(Constants);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.LoginDetector = factory(root.LoginShield.Constants);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants) {
  'use strict';

  // Specific autocomplete values associated with credentials/auth
  const AUTH_AUTOCOMPLETE_VALUES = [
    'current-password',
    'new-password',
    'username',
    'email',
    'webauthn',
    'one-time-code'
  ];

  // Specific username field name patterns
  const USERNAME_NAME_PATTERNS = [
    'user',
    'username',
    'email',
    'login',
    'account',
    'identifier',
    'userid',
    'usr',
    'phone',
    'handle',
    'principal'
  ];

  // Password attribute patterns
  const PASSWORD_PATTERNS = [
    'password',
    'passwd',
    'pwd',
    'passcode',
    'pass'
  ];

  function matchesAnyKeyword(text, keywords) {
    if (!text || typeof text !== 'string') return false;
    const lower = text.toLowerCase();
    return keywords.some((kw) => lower.includes(kw));
  }

  /**
   * Deep query selector that penetrates open shadow roots
   */
  function queryDeep(root, selector) {
    const list = [];
    if (!root) return list;
    if (root.querySelectorAll) {
      try {
        const found = root.querySelectorAll(selector);
        for (let i = 0; i < found.length; i++) {
          list.push(found[i]);
        }
      } catch (e) {}

      try {
        const allElems = root.querySelectorAll('*');
        for (let i = 0; i < allElems.length; i++) {
          if (allElems[i].shadowRoot) {
            list.push(...queryDeep(allElems[i].shadowRoot, selector));
          }
        }
      } catch (e) {}
    }
    return list;
  }

  function detectInDocument(doc, options = {}) {
    const threshold = options.threshold !== undefined ? options.threshold : Constants.LOGIN_CONFIDENCE_THRESHOLD;
    const url = options.url || (doc.location ? doc.location.href : '');
    const title = options.title !== undefined ? options.title : (doc.title || '');

    const signals = [];
    const detectedKeywords = new Set();
    let totalScore = 0;

    // 1. Password input check (including deep shadow root elements and autocomplete)
    const allInputs = queryDeep(doc, 'input');
    const passwordInputs = [];

    for (const input of allInputs) {
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
      const name = (input.getAttribute('name') || '').toLowerCase();
      const id = (input.getAttribute('id') || '').toLowerCase();

      const isPasswordType = type === 'password';
      const isPasswordAuto = auto === 'current-password' || auto === 'new-password';
      const isPasswordName = PASSWORD_PATTERNS.some((p) => name === p || name.endsWith('_' + p) || name.startsWith(p + '_'));

      if (isPasswordType || isPasswordAuto || (isPasswordName && type !== 'hidden')) {
        passwordInputs.push(input);
      }
    }

    const hasPasswordField = passwordInputs.length > 0;
    if (hasPasswordField) {
      const score = Constants.LOGIN_SIGNALS.PASSWORD_FIELD;
      totalScore += score;
      signals.push({
        name: 'PASSWORD_FIELD',
        score,
        description: `Found ${passwordInputs.length} password input field(s).`
      });
    }

    // 2. Username / Email field check
    let hasUsernameField = false;
    let usernameFieldCount = 0;

    for (const input of allInputs) {
      // PRIVACY SAFEGUARD: Do NOT read input.value!
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      const name = (input.getAttribute('name') || '').toLowerCase();
      const id = (input.getAttribute('id') || '').toLowerCase();
      const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
      const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
      const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();

      if (type === 'password' || type === 'hidden' || type === 'submit' || type === 'button' || type === 'checkbox') {
        continue;
      }

      const isTextOrEmail = ['text', 'email', 'tel', ''].includes(type);
      const nameMatches = USERNAME_NAME_PATTERNS.some((p) => name.includes(p) || id.includes(p));
      const autoMatches = autocomplete === 'username' || autocomplete === 'email';
      const labelMatches = matchesAnyKeyword(placeholder, ['username', 'email', 'user id', 'account', 'phone']) ||
                           matchesAnyKeyword(ariaLabel, ['username', 'email', 'user id', 'account', 'phone']);

      if (isTextOrEmail && (nameMatches || autoMatches || labelMatches)) {
        hasUsernameField = true;
        usernameFieldCount++;
      }
    }

    if (hasUsernameField) {
      const score = Constants.LOGIN_SIGNALS.USERNAME_FIELD;
      totalScore += score;
      signals.push({
        name: 'USERNAME_FIELD',
        score,
        description: `Found ${usernameFieldCount} username or email identifier input field(s).`
      });
    }

    // 3. Login-related button
    const buttons = queryDeep(doc, 'button, input[type="submit"], input[type="button"], a[role="button"]');
    let hasLoginButton = false;
    let loginButtonText = '';

    for (const btn of buttons) {
      const text = (btn.textContent || btn.getAttribute('value') || btn.getAttribute('aria-label') || '').trim();
      const btnId = (btn.getAttribute('id') || '').toLowerCase();
      const btnName = (btn.getAttribute('name') || '').toLowerCase();
      const btnTestId = (btn.getAttribute('data-testid') || '').toLowerCase();

      for (const kw of Constants.AUTH_KEYWORDS) {
        if (
          matchesAnyKeyword(text, [kw]) ||
          matchesAnyKeyword(btnId, [kw]) ||
          matchesAnyKeyword(btnName, [kw]) ||
          matchesAnyKeyword(btnTestId, [kw])
        ) {
          hasLoginButton = true;
          loginButtonText = text.slice(0, 30);
          detectedKeywords.add(kw);
          break;
        }
      }
      if (hasLoginButton) break;
    }

    if (hasLoginButton) {
      const score = Constants.LOGIN_SIGNALS.LOGIN_BUTTON;
      totalScore += score;
      signals.push({
        name: 'LOGIN_BUTTON',
        score,
        description: `Found button containing authentication terms ("${loginButtonText || 'login'}").`
      });
    }

    // 4. Modal / Popup Login Dialog Detection
    const modalContainers = queryDeep(
      doc,
      'dialog, [role="dialog"], [aria-modal="true"], .modal, .popup, [class*="login-modal" i], [class*="auth-modal" i], [class*="signin-modal" i]'
    );
    let hasModalLogin = false;

    for (const modal of modalContainers) {
      // Check if modal contains password or credential inputs
      const modalPass = modal.querySelectorAll ? modal.querySelectorAll('input[type="password"], input[name*="pass" i]') : [];
      const modalUser = modal.querySelectorAll ? modal.querySelectorAll('input[type="email"], input[name*="user" i]') : [];
      if (modalPass.length > 0 || modalUser.length > 0) {
        hasModalLogin = true;
        break;
      }
    }

    if (hasModalLogin) {
      const score = 15;
      totalScore += score;
      signals.push({
        name: 'MODAL_LOGIN_DETECTED',
        score,
        description: 'Authentication dialog / popup modal detected on page.'
      });
    }

    // 5. Authentication-related Autocomplete attributes
    let hasAuthAutocomplete = false;
    for (const input of allInputs) {
      const auto = (input.getAttribute('autocomplete') || '').toLowerCase();
      if (AUTH_AUTOCOMPLETE_VALUES.includes(auto)) {
        hasAuthAutocomplete = true;
        break;
      }
    }

    if (hasAuthAutocomplete) {
      const score = Constants.LOGIN_SIGNALS.AUTH_AUTOCOMPLETE;
      totalScore += score;
      signals.push({
        name: 'AUTH_AUTOCOMPLETE',
        score,
        description: 'Input elements specify standard authentication autocomplete attributes.'
      });
    }

    // 6. Login-related URL
    let urlHasLoginKeyword = false;
    for (const kw of Constants.AUTH_KEYWORDS) {
      if (matchesAnyKeyword(url, [kw])) {
        urlHasLoginKeyword = true;
        detectedKeywords.add(kw);
      }
    }

    if (urlHasLoginKeyword) {
      const score = Constants.LOGIN_SIGNALS.LOGIN_URL;
      totalScore += score;
      signals.push({
        name: 'LOGIN_URL',
        score,
        description: 'URL path or query parameters reference authentication keywords.'
      });
    }

    // 7. Login-related page title
    let titleHasLoginKeyword = false;
    for (const kw of Constants.AUTH_KEYWORDS) {
      if (matchesAnyKeyword(title, [kw])) {
        titleHasLoginKeyword = true;
        detectedKeywords.add(kw);
      }
    }

    if (titleHasLoginKeyword) {
      const score = Constants.LOGIN_SIGNALS.AUTH_TITLE;
      totalScore += score;
      signals.push({
        name: 'AUTH_TITLE',
        score,
        description: 'Page title contains authentication keywords.'
      });
    }

    // 8. Authentication-related form structure / actions
    const forms = queryDeep(doc, 'forms, form');
    let authFormDetected = false;

    for (const form of forms) {
      const action = (form.getAttribute('action') || '').toLowerCase();
      const formId = (form.getAttribute('id') || '').toLowerCase();
      const formClass = (form.getAttribute('class') || '').toLowerCase();

      for (const kw of Constants.AUTH_KEYWORDS) {
        if (matchesAnyKeyword(action, [kw]) || matchesAnyKeyword(formId, [kw]) || matchesAnyKeyword(formClass, [kw])) {
          authFormDetected = true;
          detectedKeywords.add(kw);
          break;
        }
      }
      if (authFormDetected) break;
    }

    if (authFormDetected) {
      const score = Constants.LOGIN_SIGNALS.AUTH_FORM_ACTION;
      totalScore += score;
      signals.push({
        name: 'AUTH_FORM_ACTION',
        score,
        description: 'Form action or identifiers match authentication terminology.'
      });
    }

    // Cap confidence at 100
    const confidence = Math.min(100, Math.max(0, totalScore));
    const isLoginPage = confidence >= threshold;

    return {
      isLoginPage,
      confidence,
      threshold,
      signals,
      hasPasswordField,
      hasUsernameField,
      hasLoginButton,
      hasAuthAutocomplete,
      hasModalLogin,
      detectedKeywords: Array.from(detectedKeywords),
      formCount: forms.length,
      inputCount: allInputs.length
    };
  }

  return {
    detectInDocument,
    matchesAnyKeyword,
    queryDeep,
    AUTH_AUTOCOMPLETE_VALUES,
    USERNAME_NAME_PATTERNS
  };
});
