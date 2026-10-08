/**
 * LoginShield - Matching Engine
 * Compares a candidate DOM fingerprint against trusted fingerprints using
 * configurable weighted similarity scoring.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Constants = require('../utils/constants');
    module.exports = factory(Constants);
  } else {
    root.LoginShield = root.LoginShield || {};
    root.LoginShield.Matcher = factory(root.LoginShield.Constants);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Constants) {
  'use strict';

  /**
   * Jaccard similarity index between two arrays of strings.
   */
  function jaccardSimilarity(arr1, arr2) {
    if (!arr1 || !arr2) return 0;
    const s1 = new Set(arr1);
    const s2 = new Set(arr2);
    if (s1.size === 0 && s2.size === 0) return 1.0;
    if (s1.size === 0 || s2.size === 0) return 0.0;

    let intersection = 0;
    for (const item of s1) {
      if (s2.has(item)) intersection++;
    }
    const union = s1.size + s2.size - intersection;
    return union === 0 ? 1.0 : intersection / union;
  }

  /**
   * Numeric proximity score: 1.0 if identical, decays linearly with difference.
   */
  function countSimilarity(c1, c2) {
    const maxVal = Math.max(c1 || 0, c2 || 0);
    if (maxVal === 0) return 1.0;
    const diff = Math.abs((c1 || 0) - (c2 || 0));
    return Math.max(0, 1 - diff / maxVal);
  }

  /**
   * Compares form structure between candidate and trusted fingerprint.
   */
  function compareFormStructure(candidateForms, trustedForms) {
    if (!candidateForms || !trustedForms) return 0;
    if (candidateForms.length === 0 && trustedForms.length === 0) return 1.0;
    if (candidateForms.length === 0 || trustedForms.length === 0) return 0.0;

    const countScore = countSimilarity(candidateForms.length, trustedForms.length);
    const cand = candidateForms[0] || {};
    const trust = trustedForms[0] || {};

    const methodScore = cand.method === trust.method ? 1.0 : 0.0;
    const passScore = Boolean(cand.hasPasswordField) === Boolean(trust.hasPasswordField) ? 1.0 : 0.0;
    const userScore = Boolean(cand.hasUsernameField) === Boolean(trust.hasUsernameField) ? 1.0 : 0.0;
    const btnScore = countSimilarity(cand.buttonCount, trust.buttonCount);

    const baseScore = countScore * 0.2 + methodScore * 0.3 + passScore * 0.3 + userScore * 0.1 + btnScore * 0.1;
    // Severely penalize if password field existence differs
    const passPenalty = passScore === 1.0 ? 1.0 : 0.3;

    return baseScore * passPenalty;
  }

  /**
   * Compares input types, count, and autocompletes.
   */
  function compareInputStructure(cand, trust) {
    const candTypes = cand.inputTypes || [];
    const trustTypes = trust.inputTypes || [];
    const typeSim = jaccardSimilarity(candTypes, trustTypes);

    const candAutos = cand.autocompleteTypes || [];
    const trustAutos = trust.autocompleteTypes || [];
    const autoSim = jaccardSimilarity(candAutos, trustAutos);

    const candCount = candTypes.length;
    const trustCount = trustTypes.length;
    const countSim = countSimilarity(candCount, trustCount);

    return typeSim * 0.60 + autoSim * 0.25 + countSim * 0.15;
  }

  /**
   * Compares form action origin and path.
   */
  function compareFormAction(candidateForms, trustedForms) {
    if (!candidateForms || !trustedForms) return 0;
    if (candidateForms.length === 0 && trustedForms.length === 0) return 1.0;
    if (candidateForms.length === 0 || trustedForms.length === 0) return 0.0;

    const cand = candidateForms[0] || {};
    const trust = trustedForms[0] || {};

    const originScore = cand.isSameOrigin === trust.isSameOrigin ? 1.0 : 0.0;
    let pathScore = 0.0;

    if (cand.actionPath && trust.actionPath) {
      if (cand.actionPath === trust.actionPath) {
        pathScore = 1.0;
      } else if (
        cand.actionPath.toLowerCase().includes(trust.actionPath.toLowerCase()) ||
        trust.actionPath.toLowerCase().includes(cand.actionPath.toLowerCase())
      ) {
        pathScore = 0.5;
      }
    } else if (!cand.actionPath && !trust.actionPath) {
      pathScore = 1.0;
    }

    return originScore * 0.4 + pathScore * 0.6;
  }

  /**
   * Compares script origins.
   */
  function compareScriptOrigins(candOrigins, trustOrigins) {
    const c = candOrigins || [];
    const t = trustOrigins || [];
    if (c.length === 0 && t.length === 0) return 1.0;
    return jaccardSimilarity(c, t);
  }

  /**
   * Compares iframe structure.
   */
  function compareIframeStructure(cand, trust) {
    const countSim = countSimilarity(cand.iframeCount || 0, trust.iframeCount || 0);
    const crossSim = cand.hasCrossOriginIframe === trust.hasCrossOriginIframe ? 1.0 : 0.0;
    return countSim * 0.6 + crossSim * 0.4;
  }

  /**
   * Compares meta tags.
   */
  function compareMetaTags(candKeys, trustKeys) {
    return jaccardSimilarity(candKeys || [], trustKeys || []);
  }

  /**
   * Compares overall page input sequencing.
   */
  function comparePageStructure(cand, trust) {
    const candSeq = cand.inputSequence || [];
    const trustSeq = trust.inputSequence || [];
    if (candSeq.length === 0 && trustSeq.length === 0) return 1.0;

    let matches = 0;
    const minLen = Math.min(candSeq.length, trustSeq.length);
    const maxLen = Math.max(candSeq.length, trustSeq.length);
    if (maxLen === 0) return 1.0;

    for (let i = 0; i < minLen; i++) {
      if (candSeq[i] === trustSeq[i]) matches++;
    }
    return matches / maxLen;
  }

  /**
   * Compares protocol.
   */
  function compareProtocol(candProto, trustProto) {
    if (!candProto || !trustProto) return 0.5;
    return candProto.toLowerCase() === trustProto.toLowerCase() ? 1.0 : 0.0;
  }

  /**
   * Calculates similarity (0-100) between a candidate fingerprint and a trusted fingerprint.
   */
  function calculateSimilarity(candidate, trustedFingerprint, customWeights = {}) {
    if (!candidate || !trustedFingerprint) {
      return { similarityScore: 0, componentScores: {}, matchBand: 'Poor match' };
    }

    const weights = Object.assign({}, Constants.MATCH_WEIGHTS, customWeights);

    const scores = {
      formStructure: compareFormStructure(candidate.forms, trustedFingerprint.forms),
      inputStructure: compareInputStructure(candidate, trustedFingerprint),
      formAction: compareFormAction(candidate.forms, trustedFingerprint.forms),
      scriptOrigins: compareScriptOrigins(candidate.scriptOrigins, trustedFingerprint.scriptOrigins),
      iframeStructure: compareIframeStructure(candidate, trustedFingerprint),
      metaTags: compareMetaTags(candidate.metaKeys, trustedFingerprint.metaKeys),
      pageStructure: comparePageStructure(candidate, trustedFingerprint),
      protocol: compareProtocol(candidate.protocol, trustedFingerprint.protocol)
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const key of Object.keys(weights)) {
      if (scores[key] !== undefined) {
        weightedSum += scores[key] * weights[key];
        totalWeight += weights[key];
      }
    }

    const normalized = totalWeight > 0 ? (weightedSum / totalWeight) * 100 : 0;
    const similarityScore = Math.round(Math.min(100, Math.max(0, normalized)));

    let matchBand = 'Poor match';
    if (similarityScore >= Constants.SIMILARITY_BANDS.STRONG) {
      matchBand = 'Strong match';
    } else if (similarityScore >= Constants.SIMILARITY_BANDS.GOOD) {
      matchBand = 'Good match';
    } else if (similarityScore >= Constants.SIMILARITY_BANDS.WEAK) {
      matchBand = 'Weak match';
    }

    return {
      similarityScore,
      matchBand,
      componentScores: scores
    };
  }

  /**
   * Finds the closest match in a trusted fingerprint database.
   */
  function findBestMatch(candidateFingerprint, trustedList, currentHostname, currentPath = '', customWeights = {}) {
    if (!candidateFingerprint || !Array.isArray(trustedList) || trustedList.length === 0) {
      return {
        bestMatch: null,
        allMatches: [],
        claimedService: null
      };
    }

    const hostLower = (currentHostname || '').toLowerCase();
    const pathLower = (currentPath || '').toLowerCase();

    // Check if the current domain claims to be one of the trusted services
    let claimedService = null;
    for (const item of trustedList) {
      const domains = item.domains || [];
      const domainMatches = domains.some((d) => hostLower === d.toLowerCase() || hostLower.endsWith('.' + d.toLowerCase()));
      const brandMatches = item.name && hostLower.includes(item.id.toLowerCase());
      if (domainMatches || brandMatches) {
        claimedService = item;
        break;
      }
    }

    const matches = trustedList.map((entry) => {
      const result = calculateSimilarity(candidateFingerprint, entry.fingerprint, customWeights);
      const isDomainMatch = (entry.domains || []).some(
        (d) => hostLower === d.toLowerCase() || hostLower.endsWith('.' + d.toLowerCase())
      );
      const isPathMatch = (entry.loginPathPatterns || []).some((p) => pathLower.includes(p.toLowerCase()));

      return {
        id: entry.id,
        name: entry.name,
        domains: entry.domains,
        similarityScore: result.similarityScore,
        matchBand: result.matchBand,
        componentScores: result.componentScores,
        isDomainMatch,
        isPathMatch,
        expectedScriptOrigins: entry.expectedScriptOrigins || []
      };
    });

    matches.sort((a, b) => b.similarityScore - a.similarityScore);
    const bestMatch = matches[0] || null;

    return {
      bestMatch,
      allMatches: matches,
      claimedService
    };
  }

  return {
    calculateSimilarity,
    findBestMatch,
    jaccardSimilarity,
    countSimilarity
  };
});
