const { describe, it } = require('node:test');
const assert = require('node:assert');
const LoginDetector = require('../src/analyzer/login-detector');
const DomAnalyzer = require('../src/analyzer/dom-analyzer');
const Fingerprint = require('../src/analyzer/fingerprint');
const Matcher = require('../src/analyzer/matcher');
const RiskEngine = require('../src/analyzer/risk-engine');
const UrlAnalyzer = require('../src/analyzer/url-analyzer');
const Constants = require('../src/utils/constants');
const fingerprintsDb = require('../data/fingerprints.json');
const { MockDocument, MockElement } = require('./test-utils');

describe('Trusted Sites & Popup Modal Detection Tests', () => {
  it('recognizes same registrable root-domain (e.g. www.instagram.com to api.instagram.com)', () => {
    assert.strictEqual(UrlAnalyzer.getRootDomain('www.instagram.com'), 'instagram.com');
    assert.strictEqual(UrlAnalyzer.getRootDomain('static.cdninstagram.com'), 'cdninstagram.com');
    assert.strictEqual(UrlAnalyzer.getRootDomain('api.instagram.com'), 'instagram.com');
    assert.strictEqual(UrlAnalyzer.isSameRegistrableDomain('www.instagram.com', 'instagram.com'), true);
    assert.strictEqual(UrlAnalyzer.isSameRegistrableDomain('www.linkedin.com', 'linkedin.com'), true);
    assert.strictEqual(UrlAnalyzer.isSameRegistrableDomain('www.linkedin.com', 'evil-phish.com'), false);
  });

  it('correctly identifies reputable CDNs and legitimate iframe providers', () => {
    assert.strictEqual(UrlAnalyzer.isKnownReputableCdn('static.cdninstagram.com'), true);
    assert.strictEqual(UrlAnalyzer.isKnownReputableCdn('static.licdn.com'), true);
    assert.strictEqual(UrlAnalyzer.isKnownReputableCdn('www.google.com'), true);
    assert.strictEqual(UrlAnalyzer.isKnownReputableCdn('untrusted-hacker-analytics.com'), false);

    assert.strictEqual(UrlAnalyzer.isKnownLegitimateIframe('https://www.google.com/recaptcha/api2/anchor'), true);
    assert.strictEqual(UrlAnalyzer.isKnownLegitimateIframe('https://challenges.cloudflare.com/turnstile'), true);
    assert.strictEqual(UrlAnalyzer.isKnownLegitimateIframe('https://rogue-capture.xyz/embed'), false);
  });

  it('classifies legitimate Instagram login page as SAFE / LIKELY LEGITIMATE and NOT SUSPICIOUS', () => {
    const userInp = new MockElement('input', { type: 'text', name: 'username', autocomplete: 'username' });
    const passInp = new MockElement('input', { type: 'password', name: 'password', autocomplete: 'current-password' });
    const btn = new MockElement('button', { type: 'submit' }, [], 'Log in');
    const form = new MockElement('form', { method: 'POST', action: 'https://www.instagram.com/api/v1/web/accounts/login/ajax/' }, [userInp, passInp, btn]);

    // Scripts from legitimate Instagram CDNs
    const scriptCdn = new MockElement('script', { src: 'https://static.cdninstagram.com/rsrc.php/v3/yM/r/bundle.js' });
    const scriptMeta = new MockElement('script', { src: 'https://connect.facebook.net/en_US/sdk.js' });

    const doc = new MockDocument({
      title: 'Login • Instagram',
      url: 'https://www.instagram.com/accounts/login/',
      hostname: 'www.instagram.com',
      children: [form, scriptCdn, scriptMeta]
    });

    const dom = DomAnalyzer.analyze(doc);
    assert.strictEqual(dom.loginDetection.isLoginPage, true);

    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'www.instagram.com', '/accounts/login');

    assert.ok(match.bestMatch, 'Should find Instagram match');
    assert.strictEqual(match.bestMatch.id, 'instagram');

    const risk = RiskEngine.evaluateRisk(dom, fp, match);
    assert.strictEqual(risk.classification, Constants.CLASSIFICATIONS.SAFE);
    assert.ok(risk.riskScore <= Constants.RISK_THRESHOLDS.SAFE_MAX);
    assert.strictEqual(risk.reasons.some((r) => r.code === 'CROSS_ORIGIN_FORM'), false);
    assert.strictEqual(risk.reasons.some((r) => r.code === 'UNEXPECTED_EXTERNAL_SCRIPT'), false);
  });

  it('classifies legitimate LinkedIn login page as SAFE / LIKELY LEGITIMATE and NOT SUSPICIOUS', () => {
    const userInp = new MockElement('input', { type: 'text', name: 'session_key', id: 'username', autocomplete: 'username' });
    const passInp = new MockElement('input', { type: 'password', name: 'session_password', id: 'password', autocomplete: 'current-password' });
    const btn = new MockElement('button', { type: 'submit' }, [], 'Sign in');
    const form = new MockElement('form', { method: 'POST', action: '/checkpoint/lg/login-submit' }, [userInp, passInp, btn]);

    const scriptLi = new MockElement('script', { src: 'https://static.licdn.com/sc/h/bundle.js' });

    const doc = new MockDocument({
      title: 'LinkedIn Login, Sign in | LinkedIn',
      url: 'https://www.linkedin.com/login',
      hostname: 'www.linkedin.com',
      children: [form, scriptLi]
    });

    const dom = DomAnalyzer.analyze(doc);
    assert.strictEqual(dom.loginDetection.isLoginPage, true);

    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'www.linkedin.com', '/login');

    assert.ok(match.bestMatch, 'Should find LinkedIn match');
    assert.strictEqual(match.bestMatch.id, 'linkedin');

    const risk = RiskEngine.evaluateRisk(dom, fp, match);
    assert.strictEqual(risk.classification, Constants.CLASSIFICATIONS.SAFE);
    assert.ok(risk.riskScore <= Constants.RISK_THRESHOLDS.SAFE_MAX);
  });

  it('detects login forms inside dynamic popup modal dialogs without <form> tags', () => {
    // Popup modal: <div role="dialog" class="modal"> with inputs and button but NO <form>
    const userInp = new MockElement('input', { type: 'text', name: 'email', autocomplete: 'username', placeholder: 'Enter email' });
    const passInp = new MockElement('input', { type: 'password', name: 'password', autocomplete: 'current-password', placeholder: 'Enter password' });
    const submitBtn = new MockElement('button', { type: 'button' }, [], 'Sign In');
    const modalBox = new MockElement('div', { class: 'modal-dialog', role: 'dialog', 'aria-modal': 'true' }, [userInp, passInp, submitBtn]);

    const doc = new MockDocument({
      title: 'Portal Dashboard with Modal Login',
      url: 'https://portal.example/home',
      hostname: 'portal.example',
      children: [modalBox]
    });

    // 1. LoginDetector must detect login page and modal
    const loginRes = LoginDetector.detectInDocument(doc);
    assert.strictEqual(loginRes.isLoginPage, true);
    assert.strictEqual(loginRes.hasPasswordField, true);
    assert.strictEqual(loginRes.hasUsernameField, true);
    assert.strictEqual(loginRes.hasModalLogin, true);

    // 2. DomAnalyzer must synthesize virtual form for the modal inputs
    const dom = DomAnalyzer.analyze(doc);
    assert.ok(dom.forms.length > 0, 'Should synthesize a form for modal credential inputs');
    assert.strictEqual(dom.forms[0].hasPasswordField, true);
    assert.strictEqual(dom.forms[0].isModalForm, true);

    // 3. RiskEngine evaluates virtual form cleanly without crashes
    const fp = Fingerprint.generateFingerprint(dom);
    const match = Matcher.findBestMatch(fp, fingerprintsDb, 'portal.example', '/home');
    const risk = RiskEngine.evaluateRisk(dom, fp, match);

    assert.strictEqual(risk.isLoginPage, true);
    assert.strictEqual(risk.classification, Constants.CLASSIFICATIONS.UNKNOWN);
  });
});
