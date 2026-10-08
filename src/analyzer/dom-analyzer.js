/**
 * LoginShield - DOM Analyzer
 * Extracts deep structural DOM properties, forms, inputs, scripts, iframes, stylesheets,
 * and meta tags for fingerprinting and risk analysis.
 *
 * Supports modern popup/modal login forms without explicit <form> wrappers.
 * STRICT PRIVACY GUARANTEE: Never accesses or extracts `input.value` or any user input.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    const UrlAnalyzer = require('./url-analyzer');
    const LoginDetector = require('./login-detector');
    module.exports = factory(Constants, UrlAnalyzer, LoginDetector);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.DomAnalyzer = factory(
      root.LoginShield.Constants,
      root.LoginShield.UrlAnalyzer,
      root.LoginShield.LoginDetector
    );
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants, UrlAnalyzer, LoginDetector) {
  'use strict';

  function normalizeIdPattern(rawId) {
    if (!rawId || typeof rawId !== 'string') return '';
    return rawId
      .replace(/\d+/g, '{num}')
      .replace(/[a-f0-9]{8,}/gi, '{hash}')
      .trim()
      .toLowerCase();
  }

  function getOriginFromUrl(attrUrl, baseUrl) {
    if (!attrUrl) return '';
    const parsed = UrlAnalyzer.parseSafeUrl(attrUrl, baseUrl);
    return parsed && parsed.origin ? parsed.origin : '';
  }

  function analyzeForm(formElem, pageUrl) {
    const actionAttr = formElem.getAttribute('action') || '';
    const methodAttr = (formElem.getAttribute('method') || 'GET').toUpperCase();
    const actionAnalysis = UrlAnalyzer.analyzeFormAction(actionAttr, pageUrl);

    const inputs = Array.from(formElem.querySelectorAll('input, select, textarea'));
    const inputTypes = [];
    const inputNames = [];
    const autocompleteTypes = [];
    let hasPasswordField = false;
    let hasUsernameField = false;

    for (const input of inputs) {
      // STRICT PRIVACY: Read ONLY structural attributes, NEVER input.value
      const type = (input.getAttribute('type') || (input.tagName.toLowerCase() === 'textarea' ? 'textarea' : 'text')).toLowerCase();
      const name = (input.getAttribute('name') || '').toLowerCase();
      const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
      const id = (input.getAttribute('id') || '').toLowerCase();

      inputTypes.push(type);
      if (name) inputNames.push(name);
      if (autocomplete) autocompleteTypes.push(autocomplete);

      if (type === 'password' || autocomplete === 'current-password' || name.includes('password')) {
        hasPasswordField = true;
      }

      if (['text', 'email', 'tel'].includes(type)) {
        if (
          autocomplete === 'username' ||
          autocomplete === 'email' ||
          LoginDetector.USERNAME_NAME_PATTERNS.some((p) => name.includes(p) || id.includes(p))
        ) {
          hasUsernameField = true;
        }
      }
    }

    const buttons = formElem.querySelectorAll('button, input[type="submit"], input[type="button"]');

    return {
      method: methodAttr,
      actionRaw: actionAttr,
      actionOrigin: actionAnalysis.actionOrigin,
      actionPath: actionAnalysis.actionPath,
      actionHostname: actionAnalysis.actionHostname,
      isSameOrigin: actionAnalysis.isSameOrigin,
      isSameHostname: actionAnalysis.isSameHostname,
      isSameRootDomain: actionAnalysis.isSameRootDomain,
      isCrossOrigin: actionAnalysis.isCrossOrigin,
      isRawIp: actionAnalysis.isRawIp,
      isUnusualPort: actionAnalysis.isUnusualPort,
      isHttp: actionAnalysis.isHttp,
      isDataUrl: actionAnalysis.isDataUrl,
      isJavascriptUrl: actionAnalysis.isJavascriptUrl,
      isKnownAuthProvider: actionAnalysis.isKnownAuthProvider,
      inputTypes: inputTypes.sort(),
      inputNames: inputNames.sort(),
      autocompleteTypes: autocompleteTypes.sort(),
      hasPasswordField,
      hasUsernameField,
      buttonCount: buttons.length,
      inputCount: inputs.length,
      isVirtualForm: false
    };
  }

  /**
   * Synthesizes a virtual form entry for credential inputs located inside a modal dialog or popup
   * that do not have an enclosing <form> element.
   */
  function createVirtualFormFromInputs(inputs, container, pageUrl) {
    const pageParsed = UrlAnalyzer.parseSafeUrl(pageUrl);
    const inputTypes = [];
    const inputNames = [];
    const autocompleteTypes = [];
    let hasPasswordField = false;
    let hasUsernameField = false;

    for (const input of inputs) {
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      const name = (input.getAttribute('name') || '').toLowerCase();
      const id = (input.getAttribute('id') || '').toLowerCase();
      const auto = (input.getAttribute('autocomplete') || '').toLowerCase();

      inputTypes.push(type);
      if (name) inputNames.push(name);
      if (auto) autocompleteTypes.push(auto);

      if (type === 'password' || auto === 'current-password' || name.includes('password') || id.includes('password')) {
        hasPasswordField = true;
      }
      if (['text', 'email', 'tel'].includes(type)) {
        if (auto === 'username' || auto === 'email' || LoginDetector.USERNAME_NAME_PATTERNS.some((p) => name.includes(p) || id.includes(p))) {
          hasUsernameField = true;
        }
      }
    }

    const buttons = container && container.querySelectorAll
      ? Array.from(container.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]'))
      : [];

    return {
      method: 'POST',
      actionRaw: pageUrl,
      actionOrigin: pageParsed ? pageParsed.origin : '',
      actionPath: pageParsed ? pageParsed.pathname : '',
      actionHostname: pageParsed ? pageParsed.hostname : '',
      isSameOrigin: true,
      isSameHostname: true,
      isSameRootDomain: true,
      isCrossOrigin: false,
      isRawIp: false,
      isUnusualPort: false,
      isHttp: pageParsed ? pageParsed.isHttp : false,
      isDataUrl: false,
      isJavascriptUrl: false,
      isKnownAuthProvider: false,
      inputTypes: inputTypes.sort(),
      inputNames: inputNames.sort(),
      autocompleteTypes: autocompleteTypes.sort(),
      hasPasswordField,
      hasUsernameField,
      buttonCount: buttons.length,
      inputCount: inputs.length,
      isVirtualForm: true,
      isModalForm: true
    };
  }

  function analyze(doc, pageUrlOverride) {
    const pageUrl = pageUrlOverride || (doc.location ? doc.location.href : '');
    const pageParsed = UrlAnalyzer.parseSafeUrl(pageUrl);
    const hostname = pageParsed ? pageParsed.hostname : '';
    const protocol = pageParsed ? pageParsed.protocol : '';
    const pageTitle = (doc.title || '').trim();

    // 1. Forms Analysis
    const formElements = doc.querySelectorAll ? Array.from(doc.querySelectorAll('form')) : [];
    const forms = formElements.map((f) => analyzeForm(f, pageUrl));

    // 2. All Inputs (deep traversal)
    const inputElements = LoginDetector.queryDeep ? LoginDetector.queryDeep(doc, 'input') : (doc.querySelectorAll ? Array.from(doc.querySelectorAll('input')) : []);
    const inputs = inputElements.map((input) => {
      // PRIVACY SAFEGUARD: Never read input.value
      return {
        type: (input.getAttribute('type') || 'text').toLowerCase(),
        name: (input.getAttribute('name') || '').toLowerCase(),
        autocomplete: (input.getAttribute('autocomplete') || '').toLowerCase(),
        idPattern: normalizeIdPattern(input.getAttribute('id') || ''),
        hasPlaceholder: Boolean(input.getAttribute('placeholder')),
        isRequired: input.hasAttribute('required')
      };
    });

    // 3. Popup / Modal Orphan Form Detection:
    // If credential inputs exist outside of any <form> tag, create a virtual form representation
    const inputsInForms = new Set();
    for (const fe of formElements) {
      if (fe.querySelectorAll) {
        const inF = fe.querySelectorAll('input');
        for (let i = 0; i < inF.length; i++) {
          inputsInForms.add(inF[i]);
        }
      }
    }

    const orphanInputs = inputElements.filter((inp) => !inputsInForms.has(inp));
    const hasOrphanPassword = orphanInputs.some((inp) => {
      const type = (inp.getAttribute('type') || '').toLowerCase();
      const auto = (inp.getAttribute('autocomplete') || '').toLowerCase();
      const name = (inp.getAttribute('name') || '').toLowerCase();
      return type === 'password' || auto === 'current-password' || name.includes('password');
    });

    if (hasOrphanPassword && orphanInputs.length > 0) {
      // Find modal or parent container
      let modalParent = null;
      for (const inp of orphanInputs) {
        if (inp.closest) {
          modalParent = inp.closest('dialog, [role="dialog"], [aria-modal="true"], .modal, .popup, [class*="login" i], [id*="login" i]');
          if (modalParent) break;
        }
      }
      const virtualForm = createVirtualFormFromInputs(orphanInputs, modalParent, pageUrl);
      forms.push(virtualForm);
    }

    // 4. Iframes Analysis
    const iframeElements = doc.querySelectorAll ? Array.from(doc.querySelectorAll('iframe')) : [];
    const pageOrigin = pageParsed ? pageParsed.origin : '';
    const iframes = iframeElements.map((frame) => {
      const src = frame.getAttribute('src') || '';
      const frameOrigin = getOriginFromUrl(src, pageUrl);
      const isCrossOrigin = Boolean(pageOrigin && frameOrigin && frameOrigin !== pageOrigin);
      const isSameRootDomain = UrlAnalyzer.isSameRegistrableDomain(hostname, frameOrigin);
      const isSandboxed = frame.hasAttribute('sandbox');
      const sandboxTokens = isSandboxed ? frame.getAttribute('sandbox') || 'restricted' : 'none';

      return {
        srcRaw: src ? src.slice(0, 100) : '',
        origin: frameOrigin,
        isCrossOrigin: isCrossOrigin && !isSameRootDomain,
        isSameRootDomain,
        sandboxed: isSandboxed,
        sandboxTokens
      };
    });

    // 5. Scripts Analysis
    const scriptElements = doc.querySelectorAll ? Array.from(doc.querySelectorAll('script')) : [];
    const scripts = scriptElements.map((s) => {
      const src = s.getAttribute('src') || '';
      const scriptType = (s.getAttribute('type') || 'text/javascript').toLowerCase();
      const isInline = !src;
      const scriptOrigin = isInline ? pageOrigin : getOriginFromUrl(src, pageUrl);
      const isCrossOrigin = Boolean(!isInline && pageOrigin && scriptOrigin && scriptOrigin !== pageOrigin);
      const isSameRootDomain = UrlAnalyzer.isSameRegistrableDomain(hostname, scriptOrigin);

      return {
        origin: scriptOrigin,
        type: scriptType,
        isInline,
        isCrossOrigin: isCrossOrigin && !isSameRootDomain,
        isSameRootDomain
      };
    });

    // 6. Stylesheets Analysis
    const linkElements = doc.querySelectorAll ? Array.from(doc.querySelectorAll('link[rel="stylesheet"], link[as="style"]')) : [];
    const stylesheets = linkElements.map((l) => {
      const href = l.getAttribute('href') || '';
      return {
        origin: getOriginFromUrl(href, pageUrl)
      };
    }).filter((s) => Boolean(s.origin));

    // 7. Meta Tags Analysis (normalized, deduplicated, sorted)
    const metaElements = doc.querySelectorAll ? Array.from(doc.querySelectorAll('meta')) : [];
    const metaTagMap = new Map();

    for (const m of metaElements) {
      const name = (m.getAttribute('name') || m.getAttribute('http-equiv') || '').toLowerCase().trim();
      const property = (m.getAttribute('property') || '').toLowerCase().trim();
      if (name || property) {
        const key = `${name}::${property}`;
        if (!metaTagMap.has(key)) {
          metaTagMap.set(key, { name, property });
        }
      }
    }

    const metaTags = Array.from(metaTagMap.values()).sort((a, b) => {
      const ka = `${a.name}|${a.property}`;
      const kb = `${b.name}|${b.property}`;
      return ka.localeCompare(kb);
    });

    // 8. Resource Origins Accounting
    let sameOriginCount = 0;
    let crossOriginCount = 0;

    for (const s of scripts) {
      if (!s.isInline) {
        if (s.isCrossOrigin) crossOriginCount++;
        else sameOriginCount++;
      }
    }
    for (const f of iframes) {
      if (f.isCrossOrigin) crossOriginCount++;
      else sameOriginCount++;
    }
    for (const st of stylesheets) {
      if (st.origin && st.origin !== pageOrigin && !UrlAnalyzer.isSameRegistrableDomain(hostname, st.origin)) {
        crossOriginCount++;
      } else if (st.origin) {
        sameOriginCount++;
      }
    }

    // 9. Run Login Detector
    const loginDetection = LoginDetector.detectInDocument(doc, { url: pageUrl, title: pageTitle });

    return {
      hostname,
      protocol,
      pageTitle,
      url: pageUrl,
      forms,
      inputs,
      iframes,
      scripts,
      stylesheets,
      metaTags,
      resources: {
        sameOriginCount,
        crossOriginCount
      },
      loginConfidence: loginDetection.confidence,
      loginDetection
    };
  }

  return {
    analyze,
    analyzeForm,
    createVirtualFormFromInputs,
    normalizeIdPattern
  };
});
