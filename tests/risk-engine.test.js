const { describe, it } = require('node:test');
const assert = require('node:assert');
const RiskEngine = require('../src/analyzer/risk-engine');
const Constants = require('../src/utils/constants');

describe('RiskEngine Tests', () => {
  function createBaseDomAnalysis(overrides = {}) {
    return Object.assign(
      {
        hostname: 'demobank.example',
        protocol: 'https:',
        url: 'https://demobank.example/login',
        pageTitle: 'DemoBank Online Banking',
        forms: [
          {
            method: 'POST',
            actionOrigin: 'https://demobank.example',
            actionPath: '/auth/login',
            isSameOrigin: true,
            isCrossOrigin: false,
            isRawIp: false,
            isUnusualPort: false,
            hasPasswordField: true,
            hasUsernameField: true
          }
        ],
        inputs: [
          { type: 'text', name: 'username' },
          { type: 'password', name: 'password' },
          { type: 'submit', name: 'submit' }
        ],
        iframes: [],
        scripts: [
          { origin: 'https://demobank.example', isInline: false },
          { origin: 'https://cdn.demobank.example', isInline: false }
        ],
        resources: { sameOriginCount: 2, crossOriginCount: 0 },
        loginConfidence: 90,
        loginDetection: { isLoginPage: true, confidence: 90 }
      },
      overrides
    );
  }

  it('classifies legitimate verified bank page as SAFE / LIKELY LEGITIMATE', () => {
    const dom = createBaseDomAnalysis();
    const match = {
      bestMatch: {
        id: 'demobank',
        name: 'DemoBank Online Banking',
        similarityScore: 95,
        matchBand: 'Strong match',
        isDomainMatch: true,
        expectedScriptOrigins: ['https://cdn.demobank.example', 'https://demobank.example']
      },
      claimedService: null
    };

    const res = RiskEngine.evaluateRisk(dom, {}, match);
    assert.strictEqual(res.classification, Constants.CLASSIFICATIONS.SAFE);
    assert.ok(res.riskScore <= Constants.RISK_THRESHOLDS.SAFE_MAX);
    assert.strictEqual(res.isLoginPage, true);
  });

  it('CRITICAL SECURITY RULE: Cloned bank structure submitting to cross-origin MUST be HIGH RISK', () => {
    const dom = createBaseDomAnalysis({
      forms: [
        {
          method: 'POST',
          actionOrigin: 'https://evil-phish-collector.example',
          actionPath: '/collect.php',
          isSameOrigin: false,
          isCrossOrigin: true,
          isRawIp: false,
          isUnusualPort: false,
          hasPasswordField: true,
          hasUsernameField: true
        }
      ]
    });

    const match = {
      bestMatch: {
        id: 'demobank',
        name: 'DemoBank Online Banking',
        similarityScore: 92,
        matchBand: 'Strong match',
        isDomainMatch: true,
        expectedScriptOrigins: ['https://demobank.example']
      },
      claimedService: null
    };

    const res = RiskEngine.evaluateRisk(dom, {}, match);
    assert.strictEqual(res.classification, Constants.CLASSIFICATIONS.HIGH_RISK);
    assert.ok(res.riskScore >= Constants.RISK_THRESHOLDS.HIGH_RISK_MIN);
    const hasCrossCode = res.reasons.some((r) => r.code === 'CROSS_ORIGIN_FORM');
    assert.strictEqual(hasCrossCode, true);
  });

  it('applies penalty for unencrypted HTTP login pages (+25)', () => {
    const dom = createBaseDomAnalysis({
      protocol: 'http:',
      url: 'http://demobank.example/login'
    });

    const res = RiskEngine.evaluateRisk(dom, {}, null);
    const httpReason = res.reasons.find((r) => r.code === 'HTTP_LOGIN');
    assert.ok(httpReason, 'Should include HTTP_LOGIN reason');
    assert.strictEqual(httpReason.penalty, 25);
  });

  it('penalizes raw IP form action destinations (+25)', () => {
    const dom = createBaseDomAnalysis({
      forms: [
        {
          method: 'POST',
          actionOrigin: 'http://192.168.1.100',
          actionPath: '/steal',
          isSameOrigin: false,
          isCrossOrigin: true,
          isRawIp: true,
          hasPasswordField: true
        }
      ]
    });

    const res = RiskEngine.evaluateRisk(dom, {}, null);
    const rawIpReason = res.reasons.find((r) => r.code === 'RAW_IP_FORM');
    assert.ok(rawIpReason, 'Should include RAW_IP_FORM reason');
  });

  it('classifies unknown login pages without trusted match as UNKNOWN LOGIN PAGE', () => {
    const dom = createBaseDomAnalysis({
      hostname: 'portal.example',
      url: 'https://portal.example/login',
      forms: [
        {
          method: 'POST',
          actionOrigin: 'https://portal.example',
          actionPath: '/auth/login',
          isSameOrigin: true,
          isCrossOrigin: false,
          isRawIp: false,
          isUnusualPort: false,
          hasPasswordField: true,
          hasUsernameField: true
        }
      ],
      scripts: [{ origin: 'https://portal.example', isInline: false }]
    });

    const res = RiskEngine.evaluateRisk(dom, {}, { bestMatch: null, claimedService: null });
    assert.strictEqual(res.classification, Constants.CLASSIFICATIONS.UNKNOWN);
    const unknownReason = res.reasons.find((r) => r.code === 'UNKNOWN_LOGIN');
    assert.ok(unknownReason, 'Should include UNKNOWN_LOGIN reason');
    assert.ok(res.riskScore < Constants.RISK_THRESHOLDS.HIGH_RISK_MIN);
  });

  it('returns NOT A LOGIN PAGE when no credentials interface is detected', () => {
    const dom = createBaseDomAnalysis({
      loginConfidence: 10,
      loginDetection: { isLoginPage: false, confidence: 10 }
    });

    const res = RiskEngine.evaluateRisk(dom, {}, null);
    assert.strictEqual(res.classification, Constants.CLASSIFICATIONS.NOT_LOGIN);
    assert.strictEqual(res.riskScore, 0);
  });
});
