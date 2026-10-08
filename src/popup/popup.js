/**
 * LoginShield - Popup Script
 * Coordinates UI display, messaging with active tab and service worker,
 * and handles manual rescan requests.
 */

document.addEventListener('DOMContentLoaded', async () => {
  'use strict';

  // DOM Elements
  const statusCard = document.getElementById('statusCard');
  const classificationBadge = document.getElementById('classificationBadge');
  const pageMetaDomain = document.getElementById('pageMetaDomain');

  const riskScoreValue = document.getElementById('riskScoreValue');
  const riskScoreBar = document.getElementById('riskScoreBar');

  const trustedMatchValue = document.getElementById('trustedMatchValue');
  const trustedMatchName = document.getElementById('trustedMatchName');

  const loginDetectedValue = document.getElementById('loginDetectedValue');
  const loginConfidenceValue = document.getElementById('loginConfidenceValue');

  const reasonCountBadge = document.getElementById('reasonCountBadge');
  const reasonsList = document.getElementById('reasonsList');

  // Technical fields
  const tLogin = document.getElementById('tLogin');
  const tProto = document.getElementById('tProto');
  const tForms = document.getElementById('tForms');
  const tPass = document.getElementById('tPass');
  const tInputs = document.getElementById('tInputs');
  const tIframes = document.getElementById('tIframes');
  const tScripts = document.getElementById('tScripts');
  const tCross = document.getElementById('tCross');
  const tTrustName = document.getElementById('tTrustName');
  const tSim = document.getElementById('tSim');
  const tHash = document.getElementById('tHash');

  const restrictedNotice = document.getElementById('restrictedNotice');
  const restrictedMessage = document.getElementById('restrictedMessage');
  const mainContent = document.getElementById('mainContent');
  const scanPageBtn = document.getElementById('scanPageBtn');
  const scanBtnText = document.getElementById('scanBtnText');
  const optionsBtn = document.getElementById('optionsBtn');

  let currentTab = null;

  // Open Options page
  optionsBtn.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('src/options/options.html'));
    }
  });

  // Check if URL is restricted
  function isRestrictedUrl(url) {
    if (!url) return true;
    return (
      url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url.startsWith('edge://') ||
      url.startsWith('about:') ||
      url.startsWith('devtools://') ||
      url.startsWith('view-source:') ||
      url.includes('chromewebstore.google.com') ||
      url.includes('chrome.google.com/webstore')
    );
  }

  // Show restricted view
  function showRestricted(reason = 'This page cannot be scanned by LoginShield.') {
    restrictedNotice.classList.remove('hidden');
    restrictedMessage.textContent = reason;
    mainContent.style.opacity = '0.35';
    mainContent.style.pointerEvents = 'none';
    scanPageBtn.disabled = true;
    classificationBadge.textContent = 'RESTRICTED PAGE';
    statusCard.className = 'status-card status-unknown';
    riskScoreValue.textContent = '--';
    trustedMatchValue.textContent = '--';
    loginDetectedValue.textContent = '--';
  }

  // Render analysis in popup UI
  function renderAnalysis(analysis) {
    if (!analysis) {
      classificationBadge.textContent = 'NO ANALYSIS AVAILABLE';
      statusCard.className = 'status-card status-unknown';
      return;
    }

    // 1. Classification & Status Theme
    const classification = analysis.classification || 'UNKNOWN LOGIN PAGE';
    classificationBadge.textContent = classification;

    statusCard.className = 'status-card';
    if (classification === 'SAFE / LIKELY LEGITIMATE') {
      statusCard.classList.add('status-safe');
    } else if (classification === 'SUSPICIOUS') {
      statusCard.classList.add('status-suspicious');
    } else if (classification === 'HIGH RISK') {
      statusCard.classList.add('status-high');
    } else {
      statusCard.classList.add('status-unknown');
    }

    try {
      const urlObj = new URL(analysis.url);
      pageMetaDomain.textContent = `${urlObj.hostname}${urlObj.pathname.length > 1 ? urlObj.pathname : ''}`;
    } catch {
      pageMetaDomain.textContent = analysis.hostname || 'Current Page';
    }

    // 2. Risk Score & Progress Bar
    const score = Math.round(analysis.riskScore || 0);
    riskScoreValue.textContent = `${score}/100`;
    riskScoreBar.style.width = `${score}%`;

    if (score >= 65) {
      riskScoreBar.style.backgroundColor = 'var(--risk-high)';
    } else if (score >= 30) {
      riskScoreBar.style.backgroundColor = 'var(--risk-suspicious)';
    } else {
      riskScoreBar.style.backgroundColor = 'var(--risk-safe)';
    }

    // 3. Trusted Match
    if (analysis.trustedMatch) {
      trustedMatchValue.textContent = `${analysis.trustedMatch.similarityScore}%`;
      trustedMatchName.textContent = analysis.trustedMatch.name || 'Matched Service';
    } else {
      trustedMatchValue.textContent = '0%';
      trustedMatchName.textContent = 'No match';
    }

    // 4. Login Detected
    if (analysis.isLoginPage) {
      loginDetectedValue.textContent = 'YES';
      loginDetectedValue.style.color = 'var(--risk-suspicious)';
    } else {
      loginDetectedValue.textContent = 'NO';
      loginDetectedValue.style.color = 'var(--text-secondary)';
    }
    loginConfidenceValue.textContent = `Confidence: ${analysis.loginConfidence || 0}%`;

    // 5. Reasons List
    const reasons = analysis.reasons || [];
    reasonCountBadge.textContent = reasons.length;
    reasonsList.innerHTML = '';

    if (reasons.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No security issues or suspicious indicators found.';
      reasonsList.appendChild(empty);
    } else {
      for (const r of reasons) {
        const item = document.createElement('div');
        item.className = `reason-item sev-${(r.severity || 'low').toLowerCase()}`;

        const header = document.createElement('div');
        header.className = 'reason-header';

        const badge = document.createElement('span');
        badge.className = `reason-badge badge-${(r.severity || 'low').toLowerCase()}`;
        badge.textContent = (r.severity || 'INFO').toUpperCase();

        const title = document.createElement('span');
        title.className = 'reason-title';
        title.textContent = r.title || 'Security notice';

        header.appendChild(badge);
        header.appendChild(title);

        const desc = document.createElement('div');
        desc.className = 'reason-desc';
        desc.textContent = r.description || '';

        item.appendChild(header);
        item.appendChild(desc);
        reasonsList.appendChild(item);
      }
    }

    // 6. Technical Details
    const tech = analysis.technical || {};
    tLogin.textContent = tech.loginDetected || (analysis.isLoginPage ? 'YES' : 'NO');
    tProto.textContent = tech.protocol || (analysis.protocol || '').toUpperCase();
    tForms.textContent = tech.formsCount !== undefined ? tech.formsCount : '--';
    tPass.textContent = tech.passwordCount !== undefined ? tech.passwordCount : '--';
    tInputs.textContent = tech.inputsCount !== undefined ? tech.inputsCount : '--';
    tIframes.textContent = tech.iframesCount !== undefined ? tech.iframesCount : '--';
    tScripts.textContent = tech.scriptsCount !== undefined ? tech.scriptsCount : '--';
    tCross.textContent = tech.hasCrossOriginForm || '--';
    tTrustName.textContent = tech.matchedName || 'None';
    tSim.textContent = tech.matchedScore || '0%';
    tHash.textContent = tech.fingerprintHash || '--';
  }

  // Request fresh scan from active tab
  async function scanActiveTab() {
    if (!currentTab || !currentTab.id) return;

    scanPageBtn.classList.add('scanning');
    scanBtnText.textContent = 'Scanning...';

    try {
      chrome.tabs.sendMessage(currentTab.id, { type: 'SCAN_PAGE' }, (response) => {
        scanPageBtn.classList.remove('scanning');
        scanBtnText.textContent = 'Scan Page';

        if (chrome.runtime.lastError) {
          console.warn('[LoginShield] Message error:', chrome.runtime.lastError.message);
          // Try fetching cached from background worker
          chrome.runtime.sendMessage(
            { type: 'GET_CURRENT_TAB_ANALYSIS', tabId: currentTab.id },
            (bgRes) => {
              if (bgRes && bgRes.analysis) {
                renderAnalysis(bgRes.analysis);
              } else {
                showRestricted('Could not establish connection to page. Please refresh the page and try again.');
              }
            }
          );
          return;
        }

        if (response && response.result) {
          renderAnalysis(response.result);
        }
      });
    } catch (e) {
      scanPageBtn.classList.remove('scanning');
      scanBtnText.textContent = 'Scan Page';
      console.error('[LoginShield] Failed to initiate scan:', e);
    }
  }

  scanPageBtn.addEventListener('click', scanActiveTab);

  // Initialize: inspect active tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) {
      showRestricted('No active browser tab found.');
      return;
    }

    currentTab = tabs[0];

    if (isRestrictedUrl(currentTab.url)) {
      showRestricted('This page cannot be scanned by LoginShield (internal or protected browser URL).');
      return;
    }

    // First try retrieving cached analysis from background service worker
    chrome.runtime.sendMessage(
      { type: 'GET_CURRENT_TAB_ANALYSIS', tabId: currentTab.id },
      async (res) => {
        if (res && res.analysis) {
          renderAnalysis(res.analysis);
        } else {
          // If no cache, perform an immediate scan
          await scanActiveTab();
        }
      }
    );
  } catch (err) {
    console.error('[LoginShield] Popup initialization error:', err);
    showRestricted('Extension could not read tab status.');
  }
});
