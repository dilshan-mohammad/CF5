/**
 * LoginShield - Options Script
 */

document.addEventListener('DOMContentLoaded', async () => {
  'use strict';

  const Storage = window.LoginShield.Storage;

  const autoScanInput = document.getElementById('autoScan');
  const strictModeInput = document.getElementById('strictMode');
  const debounceMsInput = document.getElementById('debounceMs');
  const fingerprintsList = document.getElementById('fingerprintsList');
  const addCustomBtn = document.getElementById('addCustomBtn');
  const addModal = document.getElementById('addModal');
  const cancelModalBtn = document.getElementById('cancelModalBtn');
  const saveCustomBtn = document.getElementById('saveCustomBtn');
  const customNameInput = document.getElementById('customName');
  const customDomainInput = document.getElementById('customDomain');
  const customPathInput = document.getElementById('customPath');
  const saveToast = document.getElementById('saveToast');

  let toastTimeout = null;

  function showToast(msg) {
    saveToast.textContent = msg || 'Settings saved.';
    saveToast.classList.remove('hidden');
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      saveToast.classList.add('hidden');
    }, 2500);
  }

  // Load general settings
  const settings = await Storage.getSettings();
  autoScanInput.checked = Boolean(settings.autoScan);
  strictModeInput.checked = Boolean(settings.strictMode);
  debounceMsInput.value = settings.debounceMs || 750;

  // Auto-save setting changes
  async function persistSettings() {
    await Storage.saveSettings({
      autoScan: autoScanInput.checked,
      strictMode: strictModeInput.checked,
      debounceMs: parseInt(debounceMsInput.value, 10) || 750
    });
    showToast('Preferences updated');
  }

  autoScanInput.addEventListener('change', persistSettings);
  strictModeInput.addEventListener('change', persistSettings);
  debounceMsInput.addEventListener('change', persistSettings);

  // Load and render fingerprints
  async function renderFingerprints() {
    fingerprintsList.innerHTML = '';

    // Fetch built-in
    let builtIn = [];
    try {
      const url = chrome.runtime ? chrome.runtime.getURL('data/fingerprints.json') : '../../data/fingerprints.json';
      const res = await fetch(url);
      if (res.ok) builtIn = await res.json();
    } catch (e) {
      console.warn('Could not load built-in fingerprints:', e);
    }

    const custom = await Storage.getCustomFingerprints();

    // Render built-in
    for (const fp of builtIn) {
      const item = document.createElement('div');
      item.className = 'fp-item';

      const info = document.createElement('div');
      info.className = 'fp-info';

      const h4 = document.createElement('h4');
      h4.textContent = fp.name;
      const badge = document.createElement('span');
      badge.className = 'fp-badge';
      badge.textContent = 'Built-in';
      h4.appendChild(badge);

      const p = document.createElement('p');
      p.textContent = `Domains: ${fp.domains.join(', ')} | Paths: ${fp.loginPathPatterns.join(', ')}`;

      info.appendChild(h4);
      info.appendChild(p);
      item.appendChild(info);
      fingerprintsList.appendChild(item);
    }

    // Render custom
    for (const fp of custom) {
      const item = document.createElement('div');
      item.className = 'fp-item';

      const info = document.createElement('div');
      info.className = 'fp-info';

      const h4 = document.createElement('h4');
      h4.textContent = fp.name;
      const badge = document.createElement('span');
      badge.className = 'fp-badge';
      badge.style.background = 'rgba(16, 185, 129, 0.2)';
      badge.style.color = '#34d399';
      badge.textContent = 'Custom';
      h4.appendChild(badge);

      const p = document.createElement('p');
      p.textContent = `Domains: ${fp.domains.join(', ')} | Paths: ${fp.loginPathPatterns.join(', ')}`;

      info.appendChild(h4);
      info.appendChild(p);

      const delBtn = document.createElement('button');
      delBtn.className = 'delete-fp-btn';
      delBtn.textContent = 'Remove';
      delBtn.addEventListener('click', async () => {
        await Storage.removeCustomFingerprint(fp.id);
        renderFingerprints();
        showToast(`Removed ${fp.name}`);
      });

      item.appendChild(info);
      item.appendChild(delBtn);
      fingerprintsList.appendChild(item);
    }
  }

  await renderFingerprints();

  // Modal interactions
  addCustomBtn.addEventListener('click', () => {
    addModal.classList.remove('hidden');
    customNameInput.focus();
  });

  cancelModalBtn.addEventListener('click', () => {
    addModal.classList.add('hidden');
    customNameInput.value = '';
    customDomainInput.value = '';
    customPathInput.value = '';
  });

  saveCustomBtn.addEventListener('click', async () => {
    const name = customNameInput.value.trim();
    const domain = customDomainInput.value.trim().toLowerCase();
    const path = customPathInput.value.trim() || '/login';

    if (!name || !domain) {
      alert('Please provide both a service name and a domain.');
      return;
    }

    const id = 'custom_' + Date.now();
    const newFingerprint = {
      id,
      name,
      domains: [domain],
      loginPathPatterns: [path],
      expectedScriptOrigins: [`https://${domain}`],
      fingerprint: {
        version: '1.0',
        protocol: 'https:',
        formCount: 1,
        forms: [
          {
            method: 'POST',
            actionPath: path,
            isSameOrigin: true,
            isCrossOrigin: false,
            isKnownAuthProvider: false,
            inputTypes: ['password', 'submit', 'text'],
            inputCount: 3,
            hasPasswordField: true,
            hasUsernameField: true,
            buttonCount: 1
          }
        ],
        inputTypes: ['password', 'submit', 'text'],
        inputSequence: ['text', 'password', 'submit'],
        autocompleteTypes: ['current-password', 'username'],
        idPatterns: [],
        scriptOrigins: [`https://${domain}`],
        iframeCount: 0,
        hasCrossOriginIframe: false,
        metaKeys: ['viewport']
      }
    };

    await Storage.addCustomFingerprint(newFingerprint);
    addModal.classList.add('hidden');
    customNameInput.value = '';
    customDomainInput.value = '';
    customPathInput.value = '';
    renderFingerprints();
    showToast(`Added custom service: ${name}`);
  });
});
