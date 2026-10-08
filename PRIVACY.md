# LoginShield Privacy Policy & Security Guarantee

**Version:** 1.0.0  
**Effective Date:** October 2026  
**Target:** Google Chrome / Chromium Browsers (Manifest V3)

LoginShield is designed with a **Zero-Knowledge, 100% Client-Side Architecture**. We believe that security software should never become a surveillance tool.

---

## 1. Absolute Privacy Guarantees

LoginShield **NEVER**:
* **Reads password values** (`input.value` is strictly prohibited and enforced via architectural safeguards and automated tests).
* **Stores password or credential values** in memory, persistent storage, or logs.
* **Reads arbitrary user input values** from forms, textboxes, or input fields.
* **Captures keystrokes** (no `keypress`, `keydown`, `keyup` event listeners).
* **Captures clipboard contents** (no clipboard permissions or access).
* **Sends form data or page content to a server** (no backend server exists).
* **Transmits browsing history or URLs to remote services**.
* **Uploads screenshots or canvas captures**.
* **Uses analytics, telemetry, or tracking scripts** (zero Google Analytics, Mixpanel, Sentry, etc.).
* **Connects to external AI APIs or cloud models** (no OpenAI, Anthropic, or cloud dependencies).
* **Sends DOM fingerprints to remote servers**.

---

## 2. What LoginShield Actually Inspects (Structural Metadata Only)

LoginShield analyzes exclusively the **structural composition** and DOM architecture of the web page to detect deception and anomalies:

| Property Inspected | Purpose | Example |
| :--- | :--- | :--- |
| `input.type` | Identify credential field topology | `password`, `text`, `email` |
| `input.name` | Distinguish username vs generic input | `username`, `login_id` |
| `input.id` (Pattern-abstracted) | Map semantic form structure | `user_{num}`, `pass_{num}` |
| `input.autocomplete` | Evaluate standard authentication hints | `current-password`, `username` |
| `input.placeholder` (presence only) | Verify field labeling layout | Boolean presence check |
| Form `action` origin & path | Verify submission target origin | `https://demobank.example/auth` |
| Form `method` | Verify standard submission protocol | `POST`, `GET` |
| `<script>` & `<iframe>` origins | Detect unauthorized injection/overlays | Verified against trusted origins |
| `<meta>` tags (names/properties) | Check page declaration structure | Normalized tags |
| Protocol | Verify transport layer encryption | `https:` vs `http:` |

**CRITICAL NOTICE:** LoginShield **NEVER calls `element.value`** on any input element. Our automated test suite includes a strict privacy spy (`tests/privacy.test.js`) that verifies attempting to read `input.value` throws a fatal error, confirming that zero user-entered data is ever accessed.

---

## 3. Data Storage & Local State

* All configuration options (such as custom fingerprints and detection thresholds) are stored locally on your device via `chrome.storage.local`.
* Active tab analysis results are cached temporarily in browser memory for the lifetime of that specific tab session and are cleared automatically upon tab closure or navigation.
* No data ever leaves your device.

---

## 4. Open Source Transparency

LoginShield is open-source under the MIT License. Every line of code can be audited by security researchers and users directly in the extension repository.
