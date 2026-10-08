/**
 * LoginShield - Background Service Worker (Manifest V3)
 * Coordinates tab scanning state, badge updates, trusted fingerprint delivery,
 * and extension messaging.
 */

const tabAnalyses = new Map();
let trustedFingerprintsCache = null;

// Initialize and load trusted fingerprints from local extension JSON
async function loadTrustedFingerprints() {
  if (trustedFingerprintsCache) return trustedFingerprintsCache;
  try {
    const url = chrome.runtime.getURL('data/fingerprints.json');
    const res = await fetch(url);
    if (res.ok) {
      trustedFingerprintsCache = await res.json();
      return trustedFingerprintsCache;
    }
  } catch (err) {
    console.error('[LoginShield] Failed to load trusted fingerprints:', err);
  }
  return [];
}

// Retrieve combined fingerprints (built-in + user custom)
async function getAllFingerprints() {
  const base = await loadTrustedFingerprints();
  return new Promise((resolve) => {
    chrome.storage.local.get(['custom_fingerprints'], (data) => {
      const custom = Array.isArray(data.custom_fingerprints) ? data.custom_fingerprints : [];
      resolve([...base, ...custom]);
    });
  });
}

// Update Chrome extension action badge based on risk
function updateBadge(tabId, analysis) {
  if (!tabId || tabId < 0) return;

  if (!analysis || !analysis.isLoginPage) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const classification = analysis.classification;
  if (classification === 'HIGH RISK') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' }); // Red
  } else if (classification === 'SUSPICIOUS') {
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' }); // Amber
  } else if (classification === 'SAFE / LIKELY LEGITIMATE') {
    chrome.action.setBadgeText({ tabId, text: 'SAFE' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' }); // Green
  } else {
    // UNKNOWN
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' }); // Slate
  }
}

// Clean up state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabAnalyses.delete(tabId);
});

// Reset state when tab navigates
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabAnalyses.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});

// Extension messaging dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  // 1. Content script sends fresh analysis
  if (message.type === 'PAGE_ANALYSIS_COMPLETED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      tabAnalyses.set(tabId, message.data);
      updateBadge(tabId, message.data);
    }
    sendResponse({ received: true });
    return false;
  }

  // 2. Content script or popup requests trusted fingerprints
  if (message.type === 'GET_FINGERPRINTS') {
    getAllFingerprints().then((list) => {
      sendResponse({ fingerprints: list });
    });
    return true; // Keep channel open for async response
  }

  // 3. Popup requests active tab analysis
  if (message.type === 'GET_CURRENT_TAB_ANALYSIS') {
    const tabId = message.tabId;
    const cached = tabAnalyses.get(tabId) || null;
    sendResponse({ analysis: cached });
    return false;
  }

  return false;
});
