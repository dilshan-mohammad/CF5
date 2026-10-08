/**
 * LoginShield - Content Script
 * Executes client-side DOM analysis, fingerprint generation, matching, and risk evaluation.
 * Listens for dynamic page mutations and popup/modal dialog state changes.
 *
 * STRICT PRIVACY: Operates 100% locally. Never reads input.value. Never transmits data externally.
 */

(function () {
  'use strict';

  // Safeguard: Run only once per document
  if (window.__loginShieldInitialized) return;
  window.__loginShieldInitialized = true;

  const LS = window.LoginShield || {};
  const Constants = LS.Constants;
  const UrlAnalyzer = LS.UrlAnalyzer;
  const LoginDetector = LS.LoginDetector;
  const DomAnalyzer = LS.DomAnalyzer;
  const Fingerprint = LS.Fingerprint;
  const Matcher = LS.Matcher;
  const RiskEngine = LS.RiskEngine;

  let cachedTrustedFingerprints = [];
  let lastAnalysisResult = null;
  let debounceTimeout = null;
  let isScanning = false;
  let lastScanHash = null;

  // Request trusted fingerprints from service worker
  async function fetchTrustedFingerprints() {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'GET_FINGERPRINTS' }, (res) => {
          if (chrome.runtime.lastError) {
            resolve({ fingerprints: [] });
          } else {
            resolve(res || { fingerprints: [] });
          }
        });
      });
      cachedTrustedFingerprints = response.fingerprints || [];
    } catch (e) {
      console.warn('[LoginShield] Could not fetch trusted fingerprints:', e);
      cachedTrustedFingerprints = [];
    }
  }

  // Perform full scan and evaluation pipeline
  async function performScan(triggerSource = 'auto') {
    if (isScanning) return lastAnalysisResult;
    isScanning = true;

    try {
      if (cachedTrustedFingerprints.length === 0) {
        await fetchTrustedFingerprints();
      }

      // If manual scan requested, force full re-evaluation
      if (triggerSource === 'manual') {
        lastScanHash = null;
      }

      const domAnalysis = DomAnalyzer.analyze(document);
      const candidateFingerprint = Fingerprint.generateFingerprint(domAnalysis);

      // Avoid redundant re-evaluation if fingerprint hash has not changed
      if (candidateFingerprint && candidateFingerprint.hash === lastScanHash && triggerSource === 'mutation') {
        isScanning = false;
        return lastAnalysisResult;
      }
      lastScanHash = candidateFingerprint ? candidateFingerprint.hash : null;

      const currentHost = window.location.hostname;
      const currentPath = window.location.pathname;

      const matchResult = Matcher.findBestMatch(
        candidateFingerprint,
        cachedTrustedFingerprints,
        currentHost,
        currentPath
      );

      const riskEvaluation = RiskEngine.evaluateRisk(
        domAnalysis,
        candidateFingerprint,
        matchResult
      );

      const passwordFields = domAnalysis.inputs.filter((i) => i.type === 'password' || i.name.includes('pass'));
      const hasCrossOriginForm = domAnalysis.forms.some((f) => f.isCrossOrigin);

      const packagedResult = {
        url: window.location.href,
        hostname: window.location.hostname,
        protocol: window.location.protocol,
        pageTitle: domAnalysis.pageTitle,
        timestamp: Date.now(),
        trigger: triggerSource,
        isLoginPage: riskEvaluation.isLoginPage,
        loginConfidence: domAnalysis.loginConfidence,
        riskScore: riskEvaluation.riskScore,
        classification: riskEvaluation.classification,
        reasons: riskEvaluation.reasons,
        trustedMatch: riskEvaluation.trustedMatch,
        technical: {
          loginDetected: riskEvaluation.isLoginPage ? 'YES' : 'NO',
          loginConfidence: domAnalysis.loginConfidence,
          protocol: (window.location.protocol || '').toUpperCase(),
          formsCount: domAnalysis.forms.length,
          inputsCount: domAnalysis.inputs.length,
          passwordCount: passwordFields.length,
          iframesCount: domAnalysis.iframes.length,
          scriptsCount: domAnalysis.scripts.length,
          crossOriginScriptCount: domAnalysis.resources.crossOriginCount,
          hasCrossOriginForm: hasCrossOriginForm ? 'YES' : 'NO',
          fingerprintHash: candidateFingerprint ? candidateFingerprint.hash : 'N/A',
          matchedName: riskEvaluation.trustedMatch ? riskEvaluation.trustedMatch.name : 'None',
          matchedScore: riskEvaluation.trustedMatch ? `${riskEvaluation.trustedMatch.similarityScore}%` : 'N/A'
        }
      };

      lastAnalysisResult = packagedResult;

      // Notify background service worker of fresh result
      try {
        chrome.runtime.sendMessage({
          type: 'PAGE_ANALYSIS_COMPLETED',
          data: packagedResult
        });
      } catch (err) {
        // Ignored if extension context invalidated
      }

      return packagedResult;
    } catch (err) {
      console.error('[LoginShield] Scan error:', err);
      return null;
    } finally {
      isScanning = false;
    }
  }

  // Setup MutationObserver with debouncing for SPAs & dynamic popup/modal login forms
  function setupObserver() {
    const DEBOUNCE_MS = Constants.DEFAULT_SETTINGS.debounceMs || 600;

    const observer = new MutationObserver((mutations) => {
      let hasRelevantMutation = false;

      for (const m of mutations) {
        if (m.type === 'childList') {
          for (let i = 0; i < m.addedNodes.length; i++) {
            const node = m.addedNodes[i];
            if (node.nodeType === Node.ELEMENT_NODE) {
              const tag = node.tagName.toLowerCase();
              if (
                tag === 'form' ||
                tag === 'input' ||
                tag === 'button' ||
                tag === 'dialog' ||
                tag === 'iframe' ||
                node.querySelector('input, form, dialog, [role="dialog"], .modal, .popup')
              ) {
                hasRelevantMutation = true;
                break;
              }
            }
          }
          if (hasRelevantMutation) break;
        } else if (m.type === 'attributes') {
          // Attribute changed on modal/dialog (e.g. class="modal show", style="display:block", open attribute on <dialog>)
          const target = m.target;
          if (target && target.nodeType === Node.ELEMENT_NODE) {
            const tag = target.tagName.toLowerCase();
            const cls = (target.getAttribute('class') || '').toLowerCase();
            const id = (target.getAttribute('id') || '').toLowerCase();
            const role = (target.getAttribute('role') || '').toLowerCase();

            if (
              tag === 'dialog' ||
              role === 'dialog' ||
              cls.includes('modal') ||
              cls.includes('popup') ||
              cls.includes('login') ||
              cls.includes('auth') ||
              id.includes('modal') ||
              id.includes('login') ||
              target.querySelector('input[type="password"], input[name*="pass" i]')
            ) {
              hasRelevantMutation = true;
              break;
            }
          }
        }
      }

      if (!hasRelevantMutation) return;

      if (debounceTimeout) {
        clearTimeout(debounceTimeout);
      }

      debounceTimeout = setTimeout(() => {
        performScan('mutation');
      }, DEBOUNCE_MS);
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class', 'style', 'hidden', 'aria-hidden', 'open']
    });
  }

  // Listen for messages from popup (e.g. manual Scan Page request)
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'SCAN_PAGE') {
      performScan('manual').then((result) => {
        sendResponse({ success: true, result });
      });
      return true; // Keep channel open for async response
    }
    return false;
  });

  // Run initial scan once DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      performScan('initial');
      setupObserver();
    });
  } else {
    performScan('initial');
    setupObserver();
  }
})();
