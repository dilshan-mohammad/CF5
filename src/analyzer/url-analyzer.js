/**
 * LoginShield - URL & Hostname Analyzer
 * Analyzes URLs, form actions, origins, raw IP addresses, and hostname anomalies.
 * Supports registrable root-domain matching and reputable CDN / iframe identification.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    module.exports = factory(Constants);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.UrlAnalyzer = factory(root.LoginShield.Constants);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants) {
  'use strict';

  // IPv4 regex (0.0.0.0 to 255.255.255.255)
  const IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  // IPv6 regex basic check
  const IPV6_REGEX = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::1$|^([a-fA-F0-9]{1,4}:)+[a-fA-F0-9]{1,4}$/;

  // Well-known third-party SSO & Auth identity providers
  const KNOWN_AUTH_PROVIDERS = [
    'accounts.google.com',
    'appleid.apple.com',
    'login.microsoftonline.com',
    'login.live.com',
    'github.com',
    'auth0.com',
    'okta.com',
    'cognito-idp.',
    'identity.pingidentity.com',
    'auth.onelogin.com'
  ];

  // Common reputable CDNs and static media infrastructures for major platforms
  const REPUTABLE_CDN_ROOTS = [
    'cdninstagram.com', 'fbcdn.net', 'facebook.net', 'facebook.com', 'instagram.com',
    'licdn.com', 'linkedin.com',
    'gstatic.com', 'googleapis.com', 'google.com', 'googleusercontent.com', 'recaptcha.net', 'googletagmanager.com',
    'msftauth.net', 'microsoft.com', 'live.com', 'azureedge.net', 'office.com', 'bing.com',
    'twimg.com', 'twitter.com', 'x.com',
    'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
    'jsdelivr.net', 'unpkg.com', 'akamaihd.net', 'akamaized.net', 'fastly.net',
    'hcaptcha.com', 'challenges.cloudflare.com'
  ];

  // Legitimate authentication, security, and captcha iframe providers
  const LEGITIMATE_IFRAME_ROOTS = [
    'recaptcha.net', 'google.com', 'gstatic.com',
    'hcaptcha.com', 'challenges.cloudflare.com', 'cloudflare.com',
    'accounts.google.com', 'facebook.com', 'linkedin.com',
    'appleid.apple.com', 'login.microsoftonline.com', 'live.com'
  ];

  function isRawIp(hostname) {
    if (!hostname) return false;
    const clean = hostname.replace(/^\[|\]$/g, '').trim();
    return IPV4_REGEX.test(clean) || IPV6_REGEX.test(clean);
  }

  /**
   * Extracts the registrable root domain (eTLD+1).
   * e.g., 'www.instagram.com' -> 'instagram.com'
   *       'static.cdninstagram.com' -> 'cdninstagram.com'
   *       'portal.study.co.uk' -> 'study.co.uk'
   */
  function getRootDomain(hostname) {
    if (!hostname || typeof hostname !== 'string') return '';
    const clean = hostname.toLowerCase().trim().replace(/^\[|\]$/g, '');
    if (isRawIp(clean)) return clean;

    const parts = clean.split('.');
    if (parts.length <= 2) return clean;

    // Common two-part public suffixes
    const twoPartSuffixes = [
      'co.uk', 'org.uk', 'me.uk', 'ltd.uk',
      'com.au', 'net.au', 'org.au', 'edu.au',
      'co.nz', 'net.nz', 'org.nz',
      'co.jp', 'ne.jp', 'or.jp',
      'com.br', 'net.br', 'org.br',
      'co.in', 'net.in', 'org.in', 'gen.in',
      'com.sg', 'edu.sg',
      'com.mx', 'org.mx',
      'co.za', 'org.za',
      'com.tr', 'edu.tr',
      'com.tw', 'org.tw'
    ];

    const lastTwo = parts.slice(-2).join('.');
    if (twoPartSuffixes.includes(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }

    return parts.slice(-2).join('.');
  }

  function isSameRegistrableDomain(hostA, hostB) {
    if (!hostA || !hostB) return false;
    if (hostA.toLowerCase() === hostB.toLowerCase()) return true;
    const rootA = getRootDomain(hostA);
    const rootB = getRootDomain(hostB);
    return Boolean(rootA && rootB && rootA === rootB);
  }

  function isKnownReputableCdn(hostname) {
    if (!hostname) return false;
    const root = getRootDomain(hostname);
    return REPUTABLE_CDN_ROOTS.includes(root);
  }

  function isKnownLegitimateIframe(srcOrOrigin) {
    if (!srcOrOrigin) return false;
    const parsed = parseSafeUrl(srcOrOrigin);
    const host = parsed && parsed.hostname ? parsed.hostname : srcOrOrigin.toLowerCase();
    const root = getRootDomain(host);
    return LEGITIMATE_IFRAME_ROOTS.includes(root);
  }

  function parseSafeUrl(rawUrl, baseUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') {
      return null;
    }
    const trimmed = rawUrl.trim();
    if (trimmed.startsWith('javascript:')) {
      return { isJavascript: true, protocol: 'javascript:', raw: trimmed };
    }
    if (trimmed.startsWith('data:')) {
      return { isData: true, protocol: 'data:', raw: trimmed };
    }

    try {
      const parsed = baseUrl ? new URL(trimmed, baseUrl) : new URL(trimmed);
      return {
        href: parsed.href,
        protocol: parsed.protocol,
        hostname: parsed.hostname.toLowerCase(),
        rootDomain: getRootDomain(parsed.hostname),
        port: parsed.port,
        pathname: parsed.pathname,
        search: parsed.search,
        origin: parsed.origin.toLowerCase(),
        isRawIp: isRawIp(parsed.hostname),
        isStandardPort: Constants.STANDARD_PORTS.includes(parsed.port),
        isHttp: parsed.protocol === 'http:',
        isHttps: parsed.protocol === 'https:',
        isJavascript: false,
        isData: false
      };
    } catch {
      return {
        href: trimmed,
        protocol: '',
        hostname: '',
        rootDomain: '',
        origin: '',
        invalid: true,
        isRawIp: false,
        isStandardPort: true,
        isHttp: false,
        isHttps: false,
        isJavascript: false,
        isData: false
      };
    }
  }

  function isKnownAuthProvider(hostnameOrOrigin) {
    if (!hostnameOrOrigin) return false;
    const lower = hostnameOrOrigin.toLowerCase();
    return KNOWN_AUTH_PROVIDERS.some((provider) => lower.includes(provider));
  }

  function analyzeFormAction(actionUrl, pageUrl) {
    const pageParsed = parseSafeUrl(pageUrl);
    const actionParsed = parseSafeUrl(actionUrl, pageUrl);

    if (!actionParsed || !actionUrl || actionUrl.trim() === '#' || actionUrl.trim() === '') {
      // Empty or hash action attribute means submit to the current page (same origin)
      return {
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
        actionOrigin: pageParsed ? pageParsed.origin : '',
        actionHostname: pageParsed ? pageParsed.hostname : '',
        actionPath: pageParsed ? pageParsed.pathname : ''
      };
    }

    if (actionParsed.isJavascript) {
      return {
        isSameOrigin: false,
        isSameHostname: false,
        isSameRootDomain: false,
        isCrossOrigin: true,
        isRawIp: false,
        isUnusualPort: false,
        isHttp: false,
        isDataUrl: false,
        isJavascriptUrl: true,
        isKnownAuthProvider: false,
        actionOrigin: 'javascript:',
        actionHostname: '',
        actionPath: ''
      };
    }

    if (actionParsed.isData) {
      return {
        isSameOrigin: false,
        isSameHostname: false,
        isSameRootDomain: false,
        isCrossOrigin: true,
        isRawIp: false,
        isUnusualPort: false,
        isHttp: false,
        isDataUrl: true,
        isJavascriptUrl: false,
        isKnownAuthProvider: false,
        actionOrigin: 'data:',
        actionHostname: '',
        actionPath: ''
      };
    }

    const pageOrigin = pageParsed ? pageParsed.origin : '';
    const pageHostname = pageParsed ? pageParsed.hostname : '';

    const isSameOrigin = Boolean(pageOrigin && actionParsed.origin === pageOrigin);
    const isSameHostname = Boolean(pageHostname && actionParsed.hostname === pageHostname);
    const isSameRootDomain = isSameRegistrableDomain(pageHostname, actionParsed.hostname);
    
    // An action is only cross-origin if it belongs to a completely different organization/root domain
    const isCrossOrigin = !isSameOrigin && !isSameRootDomain;
    const actionIsRawIp = actionParsed.isRawIp;
    const isUnusualPort = !actionParsed.isStandardPort;
    const isHttp = actionParsed.isHttp;
    const authProvider = isKnownAuthProvider(actionParsed.hostname);

    return {
      isSameOrigin,
      isSameHostname,
      isSameRootDomain,
      isCrossOrigin,
      isRawIp: actionIsRawIp,
      isUnusualPort,
      isHttp,
      isDataUrl: false,
      isJavascriptUrl: false,
      isKnownAuthProvider: authProvider,
      actionOrigin: actionParsed.origin,
      actionHostname: actionParsed.hostname,
      actionPath: actionParsed.pathname
    };
  }

  function analyzeHostname(hostname) {
    if (!hostname) return { suspicious: false, reasons: [] };

    const lower = hostname.toLowerCase();
    const reasons = [];

    // Check if raw IP
    if (isRawIp(lower)) {
      reasons.push({
        code: 'HOSTNAME_RAW_IP',
        severity: 'high',
        title: 'Website hosted on raw IP address',
        description: `Page is served directly from IP ${lower} rather than a registered domain name.`
      });
    }

    // Check Punycode (IDN homograph attack indicator)
    if (lower.includes('xn--')) {
      reasons.push({
        code: 'HOSTNAME_PUNYCODE',
        severity: 'medium',
        title: 'Punycode / Internationalized domain detected',
        description: 'Domain uses Punycode (xn--) which can be used for homograph impersonation attacks.'
      });
    }

    // Check excessive hyphens (e.g. secure-login-bank-verification-account.com)
    const hyphenCount = (lower.match(/-/g) || []).length;
    if (hyphenCount >= 4) {
      reasons.push({
        code: 'HOSTNAME_EXCESSIVE_HYPHENS',
        severity: 'medium',
        title: 'Excessive hyphens in domain name',
        description: `Domain contains ${hyphenCount} hyphens, a common pattern in phishing domain spoofing.`
      });
    }

    // Check excessive subdomain depth (excluding common co.uk, com.au etc.)
    const parts = lower.split('.');
    if (parts.length >= 6) {
      reasons.push({
        code: 'HOSTNAME_DEEP_SUBDOMAINS',
        severity: 'medium',
        title: 'Unusually deep subdomain hierarchy',
        description: `Domain has ${parts.length} segments, which may conceal the true root domain.`
      });
    }

    return {
      suspicious: reasons.length > 0,
      reasons
    };
  }

  return {
    isRawIp,
    getRootDomain,
    isSameRegistrableDomain,
    isKnownReputableCdn,
    isKnownLegitimateIframe,
    parseSafeUrl,
    isKnownAuthProvider,
    analyzeFormAction,
    analyzeHostname
  };
});
