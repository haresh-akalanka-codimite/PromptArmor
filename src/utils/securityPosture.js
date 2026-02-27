// PromptArmor - CEP Security Posture Index
// Enterprise-grade Browser Security Score (0-100)

const POSTURE_VERSION = '1.0.0';

// Weight configuration per signal category
const SIGNAL_WEIGHTS = {
  extensionRisk:       { weight: 0.25, label: 'Extension Risk' },
  policyCompliance:    { weight: 0.20, label: 'Policy Compliance' },
  safeBrowsing:        { weight: 0.15, label: 'Safe Browsing Events' },
  deviceManagement:    { weight: 0.15, label: 'Device Management' },
  urlFiltering:        { weight: 0.15, label: 'URL Filtering' },
  aiGovernance:        { weight: 0.10, label: 'AI Governance' }
};

// Deduction rules per finding
const DEDUCTIONS = {
  criticalExtension:       { points: 20, label: 'Critical-risk extension installed' },
  highRiskExtension:       { points: 10, label: 'High-risk extension installed' },
  policyViolation:         { points: 15, label: 'Policy violation detected' },
  safeBrowsingBlock:       { points: 5,  label: 'Safe Browsing block event' },
  unmanagedDevice:         { points: 20, label: 'Device not managed via CEP' },
  noExtensionPolicy:       { points: 10, label: 'No extension allowlist policy' },
  unsanctionedAITool:      { points: 8,  label: 'Unsanctioned AI tool detected' },
  sensitiveDataToAI:       { points: 12, label: 'Sensitive data sent to AI site' },
  injectionAttempt:        { points: 15, label: 'Prompt injection attempt detected' },
  piiExposure:             { points: 10, label: 'PII exposure risk' }
};

/**
 * Calculate Security Posture Index from all signals
 * @param {Object} signals - All collected security signals
 * @returns {Object} Posture result with score, grade, breakdown, and findings
 */
function calculatePosture(signals = {}) {
  const findings = [];
  let totalDeductions = 0;

  // --- Extension Risk ---
  const extensions = signals.extensions || [];
  const criticalExts = extensions.filter(e => e.score >= 50);
  const highRiskExts = extensions.filter(e => e.score >= 30 && e.score < 50);

  criticalExts.forEach(e => {
    findings.push({
      category: 'extensionRisk',
      severity: 'critical',
      deduction: DEDUCTIONS.criticalExtension.points,
      label: `${DEDUCTIONS.criticalExtension.label}: ${e.name}`
    });
    totalDeductions += DEDUCTIONS.criticalExtension.points;
  });

  highRiskExts.forEach(e => {
    findings.push({
      category: 'extensionRisk',
      severity: 'high',
      deduction: DEDUCTIONS.highRiskExtension.points,
      label: `${DEDUCTIONS.highRiskExtension.label}: ${e.name}`
    });
    totalDeductions += DEDUCTIONS.highRiskExtension.points;
  });

  // --- Policy Compliance ---
  const policies = signals.policies || {};
  if (!policies.extensionAllowlistEnabled) {
    findings.push({
      category: 'policyCompliance',
      severity: 'high',
      deduction: DEDUCTIONS.noExtensionPolicy.points,
      label: DEDUCTIONS.noExtensionPolicy.label
    });
    totalDeductions += DEDUCTIONS.noExtensionPolicy.points;
  }

  const policyViolations = policies.violations || 0;
  for (let i = 0; i < Math.min(policyViolations, 3); i++) {
    findings.push({
      category: 'policyCompliance',
      severity: 'medium',
      deduction: DEDUCTIONS.policyViolation.points,
      label: DEDUCTIONS.policyViolation.label
    });
    totalDeductions += DEDUCTIONS.policyViolation.points;
  }

  // --- Safe Browsing ---
  const safeBrowsingEvents = signals.safeBrowsingEvents || 0;
  const cappedSBEvents = Math.min(safeBrowsingEvents, 5);
  if (cappedSBEvents > 0) {
    findings.push({
      category: 'safeBrowsing',
      severity: 'medium',
      deduction: DEDUCTIONS.safeBrowsingBlock.points * cappedSBEvents,
      label: `${cappedSBEvents} Safe Browsing block event(s)`
    });
    totalDeductions += DEDUCTIONS.safeBrowsingBlock.points * cappedSBEvents;
  }

  // --- Device Management ---
  if (signals.deviceManaged === false) {
    findings.push({
      category: 'deviceManagement',
      severity: 'critical',
      deduction: DEDUCTIONS.unmanagedDevice.points,
      label: DEDUCTIONS.unmanagedDevice.label
    });
    totalDeductions += DEDUCTIONS.unmanagedDevice.points;
  }

  // --- AI Governance ---
  const aiSignals = signals.aiGovernance || {};
  if (aiSignals.unsanctionedToolsDetected) {
    findings.push({
      category: 'aiGovernance',
      severity: 'medium',
      deduction: DEDUCTIONS.unsanctionedAITool.points,
      label: DEDUCTIONS.unsanctionedAITool.label
    });
    totalDeductions += DEDUCTIONS.unsanctionedAITool.points;
  }
  if (aiSignals.sensitiveDataExposure) {
    findings.push({
      category: 'aiGovernance',
      severity: 'high',
      deduction: DEDUCTIONS.sensitiveDataToAI.points,
      label: DEDUCTIONS.sensitiveDataToAI.label
    });
    totalDeductions += DEDUCTIONS.sensitiveDataToAI.points;
  }

  // --- Injection / PII ---
  const injections = signals.injectionAttempts || 0;
  if (injections > 0) {
    findings.push({
      category: 'urlFiltering',
      severity: 'high',
      deduction: Math.min(DEDUCTIONS.injectionAttempt.points * injections, 30),
      label: `${injections} prompt injection attempt(s)`
    });
    totalDeductions += Math.min(DEDUCTIONS.injectionAttempt.points * injections, 30);
  }

  const score = Math.max(0, Math.min(100, 100 - totalDeductions));
  const grade = scoreToGrade(score);
  const trend = computeTrend(signals.history || [], score);

  return {
    score,
    grade,
    trend,
    findings,
    totalDeductions,
    breakdown: buildBreakdownByCategory(findings),
    timestamp: Date.now(),
    cepConnected: signals.cepConnected || false,
    recommendations: generateRecommendations(findings)
  };
}

function scoreToGrade(score) {
  if (score >= 90) return { label: 'EXCELLENT', color: '#22c55e' };
  if (score >= 75) return { label: 'GOOD',      color: '#84cc16' };
  if (score >= 60) return { label: 'FAIR',       color: '#f59e0b' };
  if (score >= 40) return { label: 'POOR',       color: '#f97316' };
  return                   { label: 'CRITICAL',  color: '#ef4444' };
}

function buildBreakdownByCategory(findings) {
  const breakdown = {};
  for (const key of Object.keys(SIGNAL_WEIGHTS)) {
    breakdown[key] = {
      label: SIGNAL_WEIGHTS[key].label,
      deductions: 0,
      findings: []
    };
  }
  findings.forEach(f => {
    if (breakdown[f.category]) {
      breakdown[f.category].deductions += f.deduction;
      breakdown[f.category].findings.push(f);
    }
  });
  return breakdown;
}

function computeTrend(history, currentScore) {
  if (history.length < 2) return { direction: 'stable', delta: 0 };
  const prev = history[history.length - 1].score;
  const delta = currentScore - prev;
  return {
    direction: delta > 2 ? 'improving' : delta < -2 ? 'declining' : 'stable',
    delta: Math.round(delta)
  };
}

function generateRecommendations(findings) {
  const recs = [];
  const categories = [...new Set(findings.map(f => f.category))];

  if (categories.includes('extensionRisk')) {
    recs.push({
      priority: 'high',
      action: 'Enable CEP extension allowlist policy to restrict high-risk extensions',
      cepRequired: true
    });
  }
  if (categories.includes('policyCompliance')) {
    recs.push({
      priority: 'high',
      action: 'Enroll device in Chrome Enterprise Policy for centralized control',
      cepRequired: true
    });
  }
  if (categories.includes('deviceManagement')) {
    recs.push({
      priority: 'critical',
      action: 'Enroll this device in Chrome Enterprise management immediately',
      cepRequired: true
    });
  }
  if (categories.includes('aiGovernance')) {
    recs.push({
      priority: 'medium',
      action: 'Configure AI domain allowlist in CEP to govern AI tool usage',
      cepRequired: true
    });
  }
  if (categories.includes('urlFiltering')) {
    recs.push({
      priority: 'high',
      action: 'Enable URL filtering and Safe Browsing Enhanced Protection in CEP',
      cepRequired: true
    });
  }

  return recs;
}

/**
 * Collect signals from Chrome APIs and local storage
 */
async function collectSignals() {
  const signals = { extensions: [], policies: {}, aiGovernance: {} };

  // Extensions
  try {
    const exts = await chrome.management.getAll();
    signals.extensions = exts
      .filter(e => e.type === 'extension' && e.enabled)
      .map(e => ({
        id: e.id,
        name: e.name,
        score: calcExtScore(e)
      }));
  } catch (e) { /* management API not available */ }

  // CEP device management signal (heuristic via managed storage)
  try {
    const managed = await chrome.storage.managed.get(null);
    signals.deviceManaged = Object.keys(managed).length > 0;
    signals.policies = {
      extensionAllowlistEnabled: !!managed.ExtensionInstallAllowlist,
      violations: 0
    };
    signals.cepConnected = signals.deviceManaged;
  } catch (e) {
    signals.deviceManaged = false;
    signals.cepConnected = false;
  }

  // Stored signals from runtime
  const stored = await chrome.storage.local.get([
    'firewallStats', 'aiGovernanceStats', 'safeBrowsingEvents', 'postureHistory'
  ]);

  const fw = stored.firewallStats || {};
  signals.injectionAttempts = fw.blocked || 0;
  signals.safeBrowsingEvents = stored.safeBrowsingEvents || 0;
  signals.history = stored.postureHistory || [];

  const ag = stored.aiGovernanceStats || {};
  signals.aiGovernance = {
    unsanctionedToolsDetected: (ag.unsanctionedTools || 0) > 0,
    sensitiveDataExposure: (ag.sensitiveSubmissions || 0) > 0
  };

  return signals;
}

function calcExtScore(ext) {
  const RISK = {
    critical: ['debugger', 'proxy', 'vpnProvider', 'webRequest', 'webRequestBlocking'],
    high: ['cookies', 'history', 'bookmarks', 'downloads', 'nativeMessaging', 'management'],
    medium: ['tabs', 'storage', 'clipboardRead', 'clipboardWrite']
  };
  const W = { critical: 30, high: 20, medium: 10 };
  let score = 0;
  const perms = ext.permissions || [];
  const hosts = ext.hostPermissions || [];
  for (const [level, list] of Object.entries(RISK)) {
    for (const p of list) { if (perms.includes(p)) score += W[level]; }
  }
  if (hosts.includes('<all_urls>') || hosts.includes('*://*/*')) score += 25;
  return score;
}

/**
 * Run a full posture assessment and persist result
 */
async function runPostureAssessment() {
  const signals = await collectSignals();
  const result = calculatePosture(signals);

  // Append to history (keep last 30)
  const history = signals.history || [];
  history.push({ score: result.score, timestamp: result.timestamp });
  if (history.length > 30) history.splice(0, history.length - 30);

  await chrome.storage.local.set({
    postureResult: result,
    postureHistory: history
  });

  return result;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    calculatePosture,
    collectSignals,
    runPostureAssessment,
    scoreToGrade,
    generateRecommendations,
    SIGNAL_WEIGHTS,
    DEDUCTIONS
  };
}
