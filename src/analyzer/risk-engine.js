/**
 * LoginShield - Risk Engine
 * Computes comprehensive phishing / fake login risk score and generates
 * structured, human-readable explanations.
 *
 * Avoids false positives on reputable services (Instagram, LinkedIn, etc.)
 * by recognizing legitimate CDNs, shared registrable root domains, and auth providers.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    const UrlAnalyzer = require('./url-analyzer');
    module.exports = factory(Constants, UrlAnalyzer);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.RiskEngine = factory(root.LoginShield.Constants, root.LoginShield.UrlAnalyzer);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants, UrlAnalyzer) {
  'use strict';

  function evaluateRisk(domAnalysis, fingerprint, matchResult) {
    const reasons = [];
    let riskScore = 0;
    const appliedCodes = new Set();

    function addReason(code, severity, penalty, title, description) {
      if (appliedCodes.has(code)) return;
      appliedCodes.add(code);
      if (penalty > 0) {
        riskScore += penalty;
      }
      reasons.push({ code, severity, title, description, penalty });
    }

    // 0. Check if page is a login page at all
    const isLogin = domAnalysis.loginDetection && domAnalysis.loginDetection.isLoginPage;
    if (!isLogin) {
      return {
        classification: Constants.CLASSIFICATIONS.NOT_LOGIN,
        riskScore: 0,
        isLoginPage: false,
        loginConfidence: domAnalysis.loginConfidence || 0,
        reasons: [
          {
            code: 'NOT_LOGIN_PAGE',
            severity: 'low',
            penalty: 0,
            title: 'No login form detected',
            description: 'This page does not present login forms, credential fields, or authentication interfaces.'
          }
        ],
        trustedMatch: matchResult && matchResult.bestMatch ? matchResult.bestMatch : null
      };
    }

    const currentHostname = domAnalysis.hostname || '';
    const currentProtocol = (domAnalysis.protocol || '').toLowerCase();
    const forms = domAnalysis.forms || [];
    const bestMatch = matchResult ? matchResult.bestMatch : null;
    const claimedService = matchResult ? matchResult.claimedService : null;

    // 1. Protocol Analysis (HTTP vs HTTPS)
    const isHttp = currentProtocol === 'http:';
    if (isHttp) {
      addReason(
        'HTTP_LOGIN',
        'high',
        Constants.RISK_PENALTIES.HTTP_LOGIN,
        'Insecure HTTP login page',
        'The page is delivered over unencrypted HTTP. Submitted credentials can be intercepted in cleartext.'
      );
    } else if (currentProtocol === 'https:') {
      addReason(
        'HTTPS_INFO',
        'low',
        0,
        'Page uses HTTPS encryption',
        'Connection is encrypted in transit. Note: HTTPS prevents network eavesdropping but does not guarantee the site owner is legitimate.'
      );
    }

    // 2. Form Action Destination Analysis
    const authForms = forms.filter((f) => f.hasPasswordField || f.hasUsernameField);
    const formsToInspect = authForms.length > 0 ? authForms : forms;

    let hasCrossOriginForm = false;
    let hasRawIpForm = false;
    let hasDangerousPseudoProtocol = false;
    let hasUnusualPort = false;

    for (const form of formsToInspect) {
      if (form.isJavascriptUrl || form.isDataUrl) {
        hasDangerousPseudoProtocol = true;
      }
      if (form.isRawIp) {
        hasRawIpForm = true;
      }
      if (form.isUnusualPort) {
        hasUnusualPort = true;
      }
      // Check cross-origin submission: must NOT be same origin, same root domain, or known SSO provider
      const isSameRoot = form.isSameRootDomain || UrlAnalyzer.isSameRegistrableDomain(currentHostname, form.actionHostname);
      if (form.isCrossOrigin && !isSameRoot) {
        if (!form.isKnownAuthProvider) {
          hasCrossOriginForm = true;
        } else {
          addReason(
            'KNOWN_AUTH_PROVIDER',
            'low',
            0,
            'Submits to recognized authentication provider',
            `Form submits to trusted identity provider (${form.actionHostname || form.actionOrigin}).`
          );
        }
      }
    }

    if (hasDangerousPseudoProtocol) {
      addReason(
        'DATA_OR_JS_ACTION',
        'high',
        Constants.RISK_PENALTIES.DATA_OR_JS_ACTION,
        'Form action uses javascript: or data: URL',
        'Credentials are routed through a script execution or data stream rather than a legitimate server endpoint.'
      );
    }

    if (hasCrossOriginForm) {
      addReason(
        'CROSS_ORIGIN_FORM',
        'high',
        Constants.RISK_PENALTIES.CROSS_ORIGIN_FORM,
        'Login form submits to another origin',
        'The form action destination differs from the current website domain. Credentials may be harvested by a third party.'
      );
    }

    if (hasRawIpForm) {
      addReason(
        'RAW_IP_FORM',
        'high',
        Constants.RISK_PENALTIES.RAW_IP_FORM,
        'Form submits directly to an IP address',
        'Credentials are submitted to a raw numeric IP address rather than a verified registered domain name.'
      );
    }

    if (hasUnusualPort) {
      addReason(
        'INSECURE_PORT',
        'medium',
        Constants.RISK_PENALTIES.INSECURE_PORT,
        'Form submits to a non-standard port',
        'Form destination targets an unusual port, which is common in temporary or unauthorized servers.'
      );
    }

    // 3. Hostname Analysis
    const hostAnalysis = UrlAnalyzer.analyzeHostname(currentHostname);
    if (hostAnalysis.suspicious) {
      for (const r of hostAnalysis.reasons) {
        addReason(r.code, r.severity, Constants.RISK_PENALTIES.SUSPICIOUS_HOSTNAME, r.title, r.description);
      }
    }

    // 4. Iframe Analysis (Filter out legitimate security/captcha frames and same-root domains)
    const crossOriginIframes = (domAnalysis.iframes || []).filter((f) => {
      if (!f.isCrossOrigin) return false;
      if (f.isSameRootDomain) return false;
      const frameHost = UrlAnalyzer.parseSafeUrl(f.origin)?.hostname || f.origin;
      if (UrlAnalyzer.isSameRegistrableDomain(currentHostname, frameHost)) return false;
      if (UrlAnalyzer.isKnownLegitimateIframe(f.origin || f.srcRaw)) return false;
      return true;
    });

    if (crossOriginIframes.length > 0) {
      addReason(
        'SUSPICIOUS_IFRAME',
        'medium',
        Constants.RISK_PENALTIES.SUSPICIOUS_IFRAME,
        'Cross-origin iframe detected',
        `Page embeds ${crossOriginIframes.length} unauthorized cross-origin iframe(s). Phishing attacks frequently use iframes for credential trapping or overlays.`
      );
    }

    // 5. Script Analysis (Filter out legitimate CDNs and same-root domains)
    const expectedOrigins = (bestMatch && bestMatch.expectedScriptOrigins) ? bestMatch.expectedScriptOrigins : [];
    const expectedSet = new Set(expectedOrigins.map((o) => UrlAnalyzer.parseSafeUrl(o)?.hostname || o));
    expectedSet.add(currentHostname);

    const unexpectedScripts = (domAnalysis.scripts || []).filter((s) => {
      if (s.isInline || !s.origin) return false;
      const scriptHost = UrlAnalyzer.parseSafeUrl(s.origin)?.hostname || '';
      if (!scriptHost) return false;
      if (expectedSet.has(scriptHost)) return false;
      if (UrlAnalyzer.isSameRegistrableDomain(currentHostname, scriptHost)) return false;
      if (UrlAnalyzer.isKnownAuthProvider(scriptHost)) return false;
      if (UrlAnalyzer.isKnownReputableCdn(scriptHost)) return false;
      return true;
    });

    if (unexpectedScripts.length > 0) {
      const distinctUnexpected = Array.from(new Set(unexpectedScripts.map((s) => s.origin)));
      addReason(
        'UNEXPECTED_EXTERNAL_SCRIPT',
        'medium',
        Constants.RISK_PENALTIES.UNEXPECTED_EXTERNAL_SCRIPT,
        'External script from unexpected origin',
        `Page loads external script(s) from unauthorized origin: ${distinctUnexpected.slice(0, 2).join(', ')}.`
      );
    }

    // 6. Trusted Fingerprint & Impersonation Logic
    let isClonedTrustedStructure = false;

    if (claimedService) {
      // The site domain claims to be a trusted service (e.g. demobank.example)
      if (bestMatch && bestMatch.similarityScore < Constants.SIMILARITY_BANDS.GOOD) {
        addReason(
          'TRUSTED_MISMATCH',
          'high',
          Constants.RISK_PENALTIES.TRUSTED_MISMATCH,
          'Trusted site structure mismatch',
          `Page claims identity of "${claimedService.name}", but the DOM fingerprint deviates significantly (Match: ${bestMatch.similarityScore}%).`
        );
      }
    } else if (bestMatch && bestMatch.similarityScore >= Constants.SIMILARITY_BANDS.GOOD && !bestMatch.isDomainMatch) {
      // High match to a trusted bank/service, but domain is completely different!
      isClonedTrustedStructure = true;
      addReason(
        'CLONED_LOGIN_STRUCTURE',
        'high',
        Constants.RISK_PENALTIES.TRUSTED_MISMATCH,
        'Cloned trusted login structure on unverified domain',
        `Page DOM closely mirrors "${bestMatch.name}" (${bestMatch.similarityScore}% match), but is hosted on an unverified domain (${currentHostname || 'local'}).`
      );
    }

    // 7. Unknown login page logic
    const isKnownTrusted = bestMatch && bestMatch.similarityScore >= Constants.SIMILARITY_BANDS.GOOD && bestMatch.isDomainMatch;

    if (!isKnownTrusted && !isClonedTrustedStructure && !claimedService) {
      addReason(
        'UNKNOWN_LOGIN',
        'low',
        Constants.RISK_PENALTIES.UNKNOWN_LOGIN,
        'Unknown login page',
        'No trusted fingerprint exists for this website. Review the domain and form destination carefully.'
      );
    }

    // CRITICAL SECURITY RULE (Section 17):
    // "If a page matches a trusted fingerprint, but the form submits to another origin:
    // DO NOT mark it safe. Show: HIGH RISK"
    const isCriticalFormDestinationViolation = hasCrossOriginForm || hasDangerousPseudoProtocol || hasRawIpForm;
    if (isCriticalFormDestinationViolation) {
      if (riskScore < Constants.RISK_THRESHOLDS.HIGH_RISK_MIN) {
        riskScore = Constants.RISK_THRESHOLDS.HIGH_RISK_MIN;
      }
    }

    // Cap risk score between 0 and 100
    const finalScore = Math.min(100, Math.max(0, riskScore));

    // Determine Classification
    let classification = Constants.CLASSIFICATIONS.UNKNOWN;

    if (finalScore >= Constants.RISK_THRESHOLDS.HIGH_RISK_MIN || isCriticalFormDestinationViolation) {
      classification = Constants.CLASSIFICATIONS.HIGH_RISK;
    } else if (isKnownTrusted && finalScore <= Constants.RISK_THRESHOLDS.SAFE_MAX) {
      classification = Constants.CLASSIFICATIONS.SAFE;
    } else if (isClonedTrustedStructure) {
      classification = Constants.CLASSIFICATIONS.HIGH_RISK;
    } else if (hasCrossOriginForm || hasRawIpForm || hasDangerousPseudoProtocol || isHttp || unexpectedScripts.length > 0 || crossOriginIframes.length > 0) {
      // Real suspicious signals exist
      classification = Constants.CLASSIFICATIONS.SUSPICIOUS;
    } else if (!isKnownTrusted) {
      // Normal benign unknown login page (e.g. general company website over HTTPS with clean domain)
      classification = Constants.CLASSIFICATIONS.UNKNOWN;
    } else {
      classification = Constants.CLASSIFICATIONS.SAFE;
    }

    return {
      classification,
      riskScore: finalScore,
      isLoginPage: true,
      loginConfidence: domAnalysis.loginConfidence,
      reasons,
      trustedMatch: bestMatch
        ? {
            id: bestMatch.id,
            name: bestMatch.name,
            similarityScore: bestMatch.similarityScore,
            matchBand: bestMatch.matchBand,
            isDomainMatch: bestMatch.isDomainMatch,
            componentScores: bestMatch.componentScores
          }
        : null
    };
  }

  return {
    evaluateRisk
  };
});
