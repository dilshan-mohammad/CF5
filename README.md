# LoginShield 🛡️

> **Client-side protection against suspicious and fake login pages using DOM fingerprint analysis.**  
> A production-ready Chrome / Chromium Manifest V3 extension engineered with a zero-knowledge, 100% client-side security architecture.

---

## 🌟 Key Highlights

* **100% Client-Side Operation**: Zero remote servers, zero external AI APIs, zero telemetry.
* **Strict Privacy By Design**: **NEVER** accesses `input.value`, passwords, or keystrokes. Only structural DOM topology is analyzed.
* **Structural DOM Fingerprinting**: Generates deterministic, resilient structural signatures representing forms, field sequences, origins, iframes, scripts, and metadata.
* **Multi-Signal Login Detector**: Analyzes password inputs (+50), username fields (+20), buttons (+15), URLs (+10), and authentication autocomplete tags (+10) to compute a calibrated confidence score.
* **Weighted Similarity Matching**: Matches live pages against a local database of trusted service fingerprints using configurable weights.
* **Independent Risk Engine**: Evaluates cross-origin form actions, raw IP targets, insecure HTTP, injected third-party scripts, and deceptive iframe overlays.
* **Critical Security Guardrail**: If a cloned page resembles a trusted service but submits credentials to another origin, it is immediately flagged as **HIGH RISK**.
* **SPA & Dynamic Form Support**: Uses a debounced `MutationObserver` (750ms) to scan dynamically mounted login dialogs without infinite loops or performance impact.
* **Chrome Web Store Ready**: Manifest V3 compliant, responsive dark/light UI, accessible, unit tested with 100% passing coverage.

---

## 🏗️ Architecture & Data Flow

```
+-------------------------------------------------------------------+
|                        Web Page / DOM                             |
+-------------------------------------------------------------------+
                                  │
                                  ▼
+-------------------------------------------------------------------+
|                   Content Script (content.js)                     |
+-------------------------------------------------------------------+
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
+-------------------------+                       +-------------------------+
|     Login Detector      |                       |      DOM Analyzer       |
| Multi-signal confidence |                       | Extracts form topology, |
| (password, user, btn)   |                       | scripts, iframes, meta  |
+-------------------------+                       +-------------------------+
                                                           │
                                                           ▼
                                                  +-------------------------+
                                                  |  Fingerprint Generator  |
                                                  | Canonical normalization |
                                                  | & deterministic hash    |
                                                  +-------------------------+
                                                           │
                                  ┌────────────────────────┴────────────────────────┐
                                  ▼                                                 ▼
+------------------------------------------------------+                  +-------------------+
|                 Trusted Database                     |                  |   URL Analyzer    |
| (data/fingerprints.json + custom local fingerprints) |                  | Origins, IPs,     |
+------------------------------------------------------+                  | Ports, Hostnames  |
                                  │                                       +-------------------+
                                  ▼                                                 │
+------------------------------------------------------+                            │
|                   Matching Engine                    |                            │
| Weighted similarity scoring (forms, inputs, actions) |                            │
+------------------------------------------------------+                            │
                                  │                                                 │
                                  └────────────────────────┬────────────────────────┘
                                                           ▼
                                          +---------------------------------+
                                          |           Risk Engine           |
                                          | Cross-origin, HTTP, scripts,    |
                                          | iframes, impersonation penalties|
                                          +---------------------------------+
                                                           │
                                  ┌────────────────────────┴────────────────────────┐
                                  ▼                                                 ▼
+------------------------------------------------------+  +-----------------------------------+
|                  Popup UI (popup.js)                 |  | Background Worker (service-worker)|
| Risk score, match %, reasons, technical details      |  | Tab cache & status badges         |
+------------------------------------------------------+  +-----------------------------------+
```

---

## 🔒 Privacy & Zero-Knowledge Guarantee

LoginShield operates under strict client-side constraints:

1. **NO `input.value` Access**: LoginShield inspects element attributes (`type`, `name`, `id`, `autocomplete`) and never accesses entered text.
2. **NO Remote Transmission**: Fingerprints, URLs, and form actions are evaluated entirely in browser memory.
3. **NO Telemetry / AI APIs**: No external cloud services or tracking SDKs are bundled or invoked.
4. **Automated Privacy Verification**: Tested continuously via `tests/privacy.test.js`, where a DOM spy ensures that any access to `input.value` throws a fatal error.

See [PRIVACY.md](PRIVACY.md) for full documentation.

---

## 📁 Repository Structure

```
LoginShield/
├── manifest.json              # Manifest V3 extension configuration
├── package.json               # Node.js test script & metadata
├── README.md                  # Comprehensive engineering guide
├── PRIVACY.md                 # Formal zero-knowledge privacy policy
├── LICENSE                    # MIT License
│
├── icons/                     # Standard extension icons
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
│
├── data/
│   └── fingerprints.json      # Trusted demo service fingerprints
│
├── src/
│   ├── background/
│   │   └── service-worker.js  # Tab state management & badge updates
│   ├── content/
│   │   └── content.js         # Content script, DOM observer & messaging
│   ├── analyzer/
│   │   ├── url-analyzer.js    # Origin, IP, port, and hostname analyzer
│   │   ├── login-detector.js  # Multi-signal login confidence detector
│   │   ├── dom-analyzer.js    # Deep structural DOM extractor (no values)
│   │   ├── fingerprint.js     # Canonical fingerprint generator
│   │   ├── matcher.js         # Weighted similarity matching engine
│   │   └── risk-engine.js     # Risk penalty calculator & reasons builder
│   ├── popup/
│   │   ├── popup.html         # 380x560 security popup interface
│   │   ├── popup.css          # Dark/light responsive styling
│   │   └── popup.js           # Popup controller & tab communicator
│   ├── options/
│   │   ├── options.html       # Preferences & custom fingerprints manager
│   │   ├── options.css        # Settings styling
│   │   └── options.js         # Settings & fingerprint storage handlers
│   └── utils/
│       ├── constants.js       # Thresholds, signal weights, & codes
│       └── storage.js         # Local storage abstraction
│
├── tests/
│   ├── test-utils.js          # Mock DOM & Privacy spy harness
│   ├── login-detector.test.js # Login signals unit tests
│   ├── matcher.test.js        # Similarity engine unit tests
│   ├── risk-engine.test.js    # Risk scoring & guardrail unit tests
│   ├── privacy.test.js        # Privacy assertion tests (zero input reads)
│   └── demo-integration.test.js # End-to-end integration tests on demo pages
│
└── demo/                      # Interactive test pages
    ├── legit-demobank.html               # Legitimate HTTPS banking portal
    ├── legit-cloudmail.html              # Legitimate webmail interface
    ├── legit-studyportal.html            # Legitimate university CAS portal
    ├── phish-demobank-cross-origin.html  # Phish: Cross-origin form target
    ├── phish-demobank-iframe.html        # Phish: Rogue hidden iframe
    ├── phish-demobank-script.html        # Phish: Injected third-party script
    └── phish-demobank-mismatch.html      # Phish: Cloned identity mismatch & raw IP
```

---

## 🚀 Installation & Loading in Chrome

To install and test LoginShield in Google Chrome, Microsoft Edge, Brave, or any Chromium browser:

1. Open your browser and navigate to `chrome://extensions/` (or `edge://extensions/`).
2. Toggle **Developer mode** in the top right corner.
3. Click the **Load unpacked** button.
4. Select this project root folder:
   ```
   c:\Users\DILSHAN MOHAMMAD\OneDrive\Desktop\CODING\C\CF5
   ```
5. Click **Select Folder**.
6. The **LoginShield** extension icon will now appear in your browser toolbar!

> **Tip for Local Testing**: To allow LoginShield to automatically analyze local `file:///` demo pages, click **Details** on the LoginShield extension card in `chrome://extensions/` and enable the toggle **"Allow access to file URLs"**.

---

## 🧪 Testing the Extension

### 1. Running Automated Unit & Integration Tests

The test suite runs with Node.js built-in test runner:

```powershell
node --test tests/*.test.js
```

All 20 tests across 5 suites will execute and verify:
* Login detection scoring (+50 password, +20 username, +15 button, etc.)
* Fingerprint generation & weighted similarity calculation
* Cross-origin submission risk penalties and security guardrails
* Zero-knowledge privacy guarantees (throws if `input.value` is read)
* Full pipeline execution on the demo HTML files

### 2. Testing Interactive Demo Pages

Open any of the files in the `demo/` folder directly in your browser:

| Test Page | Scenario | Expected Classification | Key Reason |
| :--- | :--- | :--- | :--- |
| `demo/legit-demobank.html` | Legitimate Bank | **SAFE / LIKELY LEGITIMATE** | Matched DemoBank fingerprint (94%+), same-origin POST |
| `demo/phish-demobank-cross-origin.html` | Phishing Simulation | **HIGH RISK** | Trusted structure detected, but form submits to another origin |
| `demo/phish-demobank-iframe.html` | Hidden Frame Attack | **SUSPICIOUS** | Cross-origin iframe embedded on authentication page |
| `demo/phish-demobank-script.html` | Script Injection | **SUSPICIOUS** | Unauthorized external script origin loaded on form |
| `demo/phish-demobank-mismatch.html` | Impersonation / Raw IP | **HIGH RISK** | Claims DemoBank identity, but structure deviates & submits to raw IP |

---

## 📊 Classifications Explained

* **`SAFE / LIKELY LEGITIMATE`**: Page matches a verified trusted fingerprint and submits credentials securely to its own verified domain.
* **`SUSPICIOUS`**: Page contains minor structural anomalies, unexpected external scripts, or cross-origin iframes.
* **`HIGH RISK`**: Page submits credentials across origins, targets raw IP addresses, uses unencrypted HTTP, or impersonates a trusted service.
* **`UNKNOWN LOGIN PAGE`**: A login form is detected, but no trusted fingerprint exists. Users are advised to review the domain and destination carefully.
* **`NOT A LOGIN PAGE`**: Standard browsing pages without credential inputs or authentication interfaces.

*(Note: In accordance with security best practices, LoginShield never asserts that a page is "100% safe" or "100% phishing".)*

---

## 📜 Chrome Web Store Compliance

LoginShield is fully prepared for Chrome Web Store submission:
* Uses standard **Manifest V3**.
* Minimal required permissions (`storage`, `activeTab`, `http://*/*`, `https://*/*`).
* No obfuscated code or remote code execution (`unsafe-eval` is not used).
* Fully accessible, high-contrast, responsive UI.
* Complete MIT open source license and privacy documentation.
