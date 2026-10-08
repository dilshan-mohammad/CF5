const { describe, it } = require('node:test');
const assert = require('node:assert');
const Matcher = require('../src/analyzer/matcher');
const fingerprintsDb = require('../data/fingerprints.json');

describe('Matcher Engine Tests', () => {
  const sampleTrusted = fingerprintsDb.find((f) => f.id === 'demobank');

  it('awards 100% similarity score for identical structural fingerprints', () => {
    const candidate = JSON.parse(JSON.stringify(sampleTrusted.fingerprint));
    const result = Matcher.calculateSimilarity(candidate, sampleTrusted.fingerprint);

    assert.strictEqual(result.similarityScore, 100);
    assert.strictEqual(result.matchBand, 'Strong match');
    assert.strictEqual(result.componentScores.formStructure, 1.0);
    assert.strictEqual(result.componentScores.inputStructure, 1.0);
  });

  it('detects best match when candidate matches demobank fingerprint', () => {
    const candidate = JSON.parse(JSON.stringify(sampleTrusted.fingerprint));
    const match = Matcher.findBestMatch(candidate, fingerprintsDb, 'demobank.example', '/login');

    assert.ok(match.bestMatch, 'Should find a best match');
    assert.strictEqual(match.bestMatch.id, 'demobank');
    assert.ok(match.bestMatch.similarityScore >= 95);
    assert.strictEqual(match.bestMatch.isDomainMatch, true);
  });

  it('penalizes structural differences when inputs or forms differ significantly', () => {
    const modifiedCandidate = JSON.parse(JSON.stringify(sampleTrusted.fingerprint));
    // Drastically alter form and input structure
    modifiedCandidate.inputTypes = ['date', 'range', 'color', 'file', 'time'];
    modifiedCandidate.inputSequence = ['date', 'range', 'color', 'file', 'time'];
    modifiedCandidate.autocompleteTypes = ['off'];
    modifiedCandidate.forms[0].method = 'GET';
    modifiedCandidate.forms[0].hasPasswordField = false;
    modifiedCandidate.forms[0].hasUsernameField = false;
    modifiedCandidate.forms[0].inputTypes = ['date', 'range', 'color'];
    modifiedCandidate.forms[0].actionPath = '/completely/different/search';

    const result = Matcher.calculateSimilarity(modifiedCandidate, sampleTrusted.fingerprint);
    assert.ok(result.similarityScore < 50, `Expected similarity < 50, got ${result.similarityScore}`);
    assert.strictEqual(result.matchBand, 'Poor match');
  });

  it('handles empty or missing candidate fingerprint gracefully', () => {
    const res = Matcher.calculateSimilarity(null, sampleTrusted.fingerprint);
    assert.strictEqual(res.similarityScore, 0);

    const bestRes = Matcher.findBestMatch(null, fingerprintsDb, 'example.com');
    assert.strictEqual(bestRes.bestMatch, null);
  });
});
