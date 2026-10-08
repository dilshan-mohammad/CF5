const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const LoginDetector = require('../src/analyzer/login-detector');
const DomAnalyzer = require('../src/analyzer/dom-analyzer');
const Fingerprint = require('../src/analyzer/fingerprint');
const { MockDocument, MockElement } = require('./test-utils');

describe('Strict Privacy Verification Tests', () => {
  it('NEVER accesses input.value or defaultValue during detection and DOM analysis', () => {
    // Construct inputs where accessing .value throws a fatal error
    const userInput = new MockElement('input', {
      type: 'text',
      name: 'username',
      id: 'user_123',
      autocomplete: 'username',
      placeholder: 'Enter username'
    });

    const passInput = new MockElement('input', {
      type: 'password',
      name: 'password',
      id: 'pass_123',
      autocomplete: 'current-password'
    });

    const btn = new MockElement('button', { type: 'submit' }, [], 'Log In');
    const form = new MockElement('form', { method: 'POST', action: '/login' }, [userInput, passInput, btn]);

    const doc = new MockDocument({
      children: [form]
    });

    // 1. Run LoginDetector - Must NOT throw or touch input.value
    assert.doesNotThrow(() => {
      LoginDetector.detectInDocument(doc);
    }, 'LoginDetector must not touch input.value');

    // 2. Run DomAnalyzer - Must NOT throw or touch input.value
    let domAnalysis;
    assert.doesNotThrow(() => {
      domAnalysis = DomAnalyzer.analyze(doc);
    }, 'DomAnalyzer must not touch input.value');

    // 3. Run Fingerprint generator
    let fp;
    assert.doesNotThrow(() => {
      fp = Fingerprint.generateFingerprint(domAnalysis);
    }, 'Fingerprint generator must not touch input.value');

    // Verify spy was never touched
    assert.strictEqual(userInput._valueAccessCount, 0, 'Username input.value should never be accessed');
    assert.strictEqual(passInput._valueAccessCount, 0, 'Password input.value should never be accessed');

    // Ensure generated analysis data structures contain zero 'value' keys from inputs
    const serialized = JSON.stringify(domAnalysis);
    assert.strictEqual(serialized.includes('"value":'), false, 'Analysis must never contain input value properties');
  });

  it('verifies extension source code contains zero external network telemetry endpoints', () => {
    const srcDir = path.resolve(__dirname, '../src');
    
    function checkDir(dir) {
      const files = fs.readdirSync(dir, { withFileTypes: true });
      for (const f of files) {
        const full = path.join(dir, f.name);
        if (f.isDirectory()) {
          checkDir(full);
        } else if (f.name.endsWith('.js')) {
          const content = fs.readFileSync(full, 'utf8');
          // Verify no analytics / tracking / external AI APIs
          assert.strictEqual(
            content.includes('google-analytics.com') ||
            content.includes('api.openai.com') ||
            content.includes('api.anthropic.com') ||
            content.includes('telemetry.send') ||
            content.includes('navigator.sendBeacon'),
            false,
            `File ${f.name} contains forbidden external telemetry strings`
          );
        }
      }
    }

    checkDir(srcDir);
  });
});
