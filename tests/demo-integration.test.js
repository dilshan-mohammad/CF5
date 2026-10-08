const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const LoginDetector = require('../src/analyzer/login-detector');
const DomAnalyzer = require('../src/analyzer/dom-analyzer');
const Fingerprint = require('../src/analyzer/fingerprint');
const Matcher = require('../src/analyzer/matcher');
const RiskEngine = require('../src/analyzer/risk-engine');
const Constants = require('../src/utils/constants');
const fingerprintsDb = require('../data/fingerprints.json');
const { MockDocument, MockElement } = require('./test-utils');

/**
 * Lightweight HTML-to-MockDocument parser for integration testing the demo HTML files.
 */
function parseHtmlFileToMockDoc(filePath, url, hostname) {
  const html = fs.readFileSync(filePath, 'utf8');

  // Title
  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  const title = titleMatch ? titleMatch[1] : '';

  // Extract meta tags
  const metaRegex = /<meta\s+([^>]+)>/gi;
  const metas = [];
  let m;
  while ((m = metaRegex.exec(html)) !== null) {
    const attrStr = m[1];
    const nameM = attrStr.match(/name=["']([^"']+)["']/i);
    const propM = attrStr.match(/property=["']([^"']+)["']/i);
    const httpM = attrStr.match(/http-equiv=["']([^"']+)["']/i);
    metas.push(
      new MockElement('meta', {
        name: nameM ? nameM[1] : '',
        property: propM ? propM[1] : '',
        'http-equiv': httpM ? httpM[1] : ''
      })
    );
  }

  // Extract forms and their child inputs & buttons
  const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  const forms = [];
  let f;
  while ((f = formRegex.exec(html)) !== null) {
    const formAttrsStr = f[1];
    const formInner = f[2];

    const methodM = formAttrsStr.match(/method=["']([^"']+)["']/i);
    const actionM = formAttrsStr.match(/action=["']([^"']+)["']/i);
    const idM = formAttrsStr.match(/id=["']([^"']+)["']/i);

    const formChildren = [];

    // Inputs inside form
    const inputRegex = /<input([^>]*)>/gi;
    let inp;
    while ((inp = inputRegex.exec(formInner)) !== null) {
      const a = inp[1];
      const typeM = a.match(/type=["']([^"']+)["']/i);
      const nameM = a.match(/name=["']([^"']+)["']/i);
      const idInputM = a.match(/id=["']([^"']+)["']/i);
      const autoM = a.match(/autocomplete=["']([^"']+)["']/i);

      formChildren.push(
        new MockElement('input', {
          type: typeM ? typeM[1] : 'text',
          name: nameM ? nameM[1] : '',
          id: idInputM ? idInputM[1] : '',
          autocomplete: autoM ? autoM[1] : ''
        })
      );
    }

    // Buttons inside form
    const btnRegex = /<button([^>]*)>([^<]*)<\/button>/gi;
    let b;
    while ((b = btnRegex.exec(formInner)) !== null) {
      const typeBtnM = b[1].match(/type=["']([^"']+)["']/i);
      const idBtnM = b[1].match(/id=["']([^"']+)["']/i);
      formChildren.push(
        new MockElement('button', {
          type: typeBtnM ? typeBtnM[1] : 'submit',
          id: idBtnM ? idBtnM[1] : ''
        }, [], b[2])
      );
    }

    forms.push(
      new MockElement('form', {
        method: methodM ? methodM[1] : 'POST',
        action: actionM ? actionM[1] : '',
        id: idM ? idM[1] : ''
      }, formChildren)
    );
  }

  // Scripts
  const scriptRegex = /<script\s+([^>]+)>/gi;
  const scripts = [];
  let sc;
  while ((sc = scriptRegex.exec(html)) !== null) {
    const srcM = sc[1].match(/src=["']([^"']+)["']/i);
    if (srcM) {
      scripts.push(new MockElement('script', { src: srcM[1] }));
    }
  }

  // Iframes
  const iframeRegex = /<iframe\s+([^>]+)>/gi;
  const iframes = [];
  let ifr;
  while ((ifr = iframeRegex.exec(html)) !== null) {
    const srcM = ifr[1].match(/src=["']([^"']+)["']/i);
    if (srcM) {
      iframes.push(new MockElement('iframe', { src: srcM[1] }));
    }
  }

  return new MockDocument({
    title,
    url,
    hostname,
    children: [...metas, ...forms, ...scripts, ...iframes]
  });
}

describe('Demo Integration Pipeline Tests', () => {
  it('analyzes legit-demobank.html and classifies as SAFE / LIKELY LEGITIMATE', () => {
    const filePath = path.resolve(__dirname, '../demo/legit-demobank.html');
    const doc = parseHtmlFileToMockDoc(filePath, 'https://demobank.example/login', 'demobank.example');

    const dom = DomAnalyzer.analyze(doc);
    assert.strictEqual(dom.loginDetection.isLoginPage, true);

    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'demobank.example', '/login');
    assert.ok(match.bestMatch.similarityScore >= 80, `Expected similarity >= 80, got ${match.bestMatch.similarityScore}`);

    const risk = RiskEngine.evaluateRisk(dom, fp, match);
    assert.strictEqual(risk.classification, Constants.CLASSIFICATIONS.SAFE);
  });

  it('analyzes phish-demobank-cross-origin.html and classifies as HIGH RISK', () => {
    const filePath = path.resolve(__dirname, '../demo/phish-demobank-cross-origin.html');
    const doc = parseHtmlFileToMockDoc(filePath, 'https://demobank.example/login', 'demobank.example');

    const dom = DomAnalyzer.analyze(doc);
    assert.strictEqual(dom.loginDetection.isLoginPage, true);

    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'demobank.example', '/login');
    const risk = RiskEngine.evaluateRisk(dom, fp, match);

    assert.strictEqual(risk.classification, Constants.CLASSIFICATIONS.HIGH_RISK);
    assert.ok(risk.reasons.some((r) => r.code === 'CROSS_ORIGIN_FORM'));
  });

  it('analyzes phish-demobank-iframe.html and flags SUSPICIOUS_IFRAME', () => {
    const filePath = path.resolve(__dirname, '../demo/phish-demobank-iframe.html');
    const doc = parseHtmlFileToMockDoc(filePath, 'https://demobank.example/login', 'demobank.example');

    const dom = DomAnalyzer.analyze(doc);
    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'demobank.example', '/login');
    const risk = RiskEngine.evaluateRisk(dom, fp, match);

    assert.ok(risk.reasons.some((r) => r.code === 'SUSPICIOUS_IFRAME'));
  });

  it('analyzes phish-demobank-script.html and flags UNEXPECTED_EXTERNAL_SCRIPT', () => {
    const filePath = path.resolve(__dirname, '../demo/phish-demobank-script.html');
    const doc = parseHtmlFileToMockDoc(filePath, 'https://demobank.example/login', 'demobank.example');

    const dom = DomAnalyzer.analyze(doc);
    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'demobank.example', '/login');
    const risk = RiskEngine.evaluateRisk(dom, fp, match);

    assert.ok(risk.reasons.some((r) => r.code === 'UNEXPECTED_EXTERNAL_SCRIPT'));
  });
});
