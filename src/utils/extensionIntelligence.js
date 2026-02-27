// PromptArmor - Extension Behavioral Intelligence Engine
// Goes beyond static permission scanning to detect runtime anomalies

const BEHAVIORAL_FLAGS = {
  SUSPICIOUS_NETWORK:     'suspicious_network_call',
  EXCESSIVE_CLIPBOARD:    'excessive_clipboard_access',
  UPDATE_ANOMALY:         'update_anomaly',
  PERMISSION_ESCALATION:  'permission_escalation',
  DEVELOPER_REPUTATION:   'developer_reputation',
  BACKGROUND_EXFIL:       'background_exfiltration'
};

// Known suspicious developer patterns (heuristic)
const SUSPICIOUS_DEVELOPER_PATTERNS = [
  /^[a-z]{8,12}\d{3,6}@gmail\.com$/i,  // Random gmail
  /no.?reply|support@.*?\.xyz/i,
  /unknown|anonymous/i
];

// Domains commonly used for data collection by malicious extensions
const KNOWN_EXFIL_DOMAINS = [
  'api.segment.io', 'dc.services.visualstudio.com', 'webhook.site',
  'requestbin.com', 'pipedream.net'
];

/**
 * Analyse a single extension's behaviour profile
 */
function analyzeExtensionBehavior(ext, runtimeData = {}) {
  const flags = [];
  const permissions = ext.permissions || [];
  const hostPermissions = ext.hostPermissions || [];

  // ── Network call patterns ──────────────────────────────────────────────
  const networkCalls = runtimeData.networkCalls || [];
  const exfilCalls = networkCalls.filter(url =>
    KNOWN_EXFIL_DOMAINS.some(d => url.includes(d))
  );
  if (exfilCalls.length > 0) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.SUSPICIOUS_NETWORK,
      severity: 'critical',
      detail: `Calls to ${exfilCalls.length} known exfil domain(s): ${exfilCalls.slice(0, 2).join(', ')}`,
      evidence: exfilCalls
    });
  }

  // Background fetches to unfamiliar domains
  const bgCalls = runtimeData.backgroundFetches || [];
  const unknownBgCalls = bgCalls.filter(url => {
    try {
      const domain = new URL(url).hostname;
      return !ext.homepageUrl?.includes(domain) && !url.includes('google');
    } catch { return false; }
  });
  if (unknownBgCalls.length > 3) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.BACKGROUND_EXFIL,
      severity: 'high',
      detail: `${unknownBgCalls.length} background fetches to unknown domains`,
      evidence: unknownBgCalls.slice(0, 5)
    });
  }

  // ── Clipboard access frequency ─────────────────────────────────────────
  const clipboardReads = runtimeData.clipboardReads || 0;
  if (permissions.includes('clipboardRead') && clipboardReads > 20) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.EXCESSIVE_CLIPBOARD,
      severity: 'high',
      detail: `${clipboardReads} clipboard reads detected — unusually high`,
      evidence: { clipboardReads }
    });
  }

  // ── Permission escalation ─────────────────────────────────────────────
  const previousPermissions = runtimeData.previousPermissions || [];
  const newPermissions = permissions.filter(p => !previousPermissions.includes(p));
  if (newPermissions.length > 0) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.PERMISSION_ESCALATION,
      severity: 'high',
      detail: `Gained ${newPermissions.length} new permission(s) since last update: ${newPermissions.join(', ')}`,
      evidence: { newPermissions }
    });
  }

  // ── Update anomalies ──────────────────────────────────────────────────
  const updateInterval = runtimeData.updateIntervalDays;
  if (updateInterval !== undefined && updateInterval < 1) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.UPDATE_ANOMALY,
      severity: 'medium',
      detail: 'Extension updated multiple times within 24 hours (possible payload swap)',
      evidence: { updateIntervalDays: updateInterval }
    });
  }

  // ── Developer reputation ──────────────────────────────────────────────
  const developer = ext.homepage_url || ext.developer?.name || '';
  const isSuspiciousDev = SUSPICIOUS_DEVELOPER_PATTERNS.some(p => p.test(developer));
  if (isSuspiciousDev) {
    flags.push({
      flag: BEHAVIORAL_FLAGS.DEVELOPER_REPUTATION,
      severity: 'medium',
      detail: `Developer identity appears suspicious: "${developer}"`,
      evidence: { developer }
    });
  }

  // Broad host permissions from unknown publisher
  const broadHosts = hostPermissions.filter(h =>
    h === '<all_urls>' || h.includes('*://*/*')
  );
  if (broadHosts.length > 0 && ext.installType === 'normal') {
    flags.push({
      flag: BEHAVIORAL_FLAGS.SUSPICIOUS_NETWORK,
      severity: 'high',
      detail: 'Requests all-URL access — can intercept any website traffic',
      evidence: { hostPermissions: broadHosts }
    });
  }

  return {
    extensionId: ext.id,
    extensionName: ext.name,
    flags,
    behavioralRiskScore: computeBehavioralScore(flags),
    verdict: flags.some(f => f.severity === 'critical') ? 'quarantine'
           : flags.some(f => f.severity === 'high')     ? 'review'
           : flags.length > 0                            ? 'monitor'
           : 'clean',
    cepActions: suggestCEPActions(flags, ext)
  };
}

function computeBehavioralScore(flags) {
  const weights = { critical: 40, high: 25, medium: 12, low: 5 };
  const total = flags.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  return Math.min(100, total);
}

function suggestCEPActions(flags, ext) {
  const actions = [];
  if (flags.some(f => f.severity === 'critical')) {
    actions.push({
      action: 'force_remove',
      policy: { ExtensionInstallBlocklist: [ext.id] },
      cepRequired: true,
      label: 'Force-remove via CEP blocklist'
    });
  }
  if (flags.some(f => f.flag === BEHAVIORAL_FLAGS.PERMISSION_ESCALATION)) {
    actions.push({
      action: 'freeze_permissions',
      policy: { ExtensionSettings: { [ext.id]: { blocked_permissions: ['ALL'] } } },
      cepRequired: true,
      label: 'Freeze extension permissions via CEP'
    });
  }
  if (flags.some(f => f.flag === BEHAVIORAL_FLAGS.UPDATE_ANOMALY)) {
    actions.push({
      action: 'pin_version',
      policy: { ExtensionSettings: { [ext.id]: { update_url: 'none' } } },
      cepRequired: true,
      label: 'Pin extension version via CEP'
    });
  }
  return actions;
}

/**
 * Scan all installed extensions for behavioral anomalies
 * @param {Array} extensions - from chrome.management.getAll()
 * @param {Object} runtimeDataMap - keyed by extension ID
 */
function scanAllExtensions(extensions = [], runtimeDataMap = {}) {
  return extensions
    .filter(e => e.type === 'extension' && e.enabled)
    .map(ext => analyzeExtensionBehavior(ext, runtimeDataMap[ext.id] || {}))
    .sort((a, b) => b.behavioralRiskScore - a.behavioralRiskScore);
}

/**
 * Generate a mock runtime data profile for demo / testing
 */
function generateMockRuntimeData(extensionId, risk = 'low') {
  if (risk === 'critical') {
    return {
      networkCalls: ['https://api.segment.io/collect', 'https://webhook.site/abc123'],
      backgroundFetches: ['https://exfil-server.evil.com/data', 'https://c2.malware.net/beacon'],
      clipboardReads: 45,
      updateIntervalDays: 0.4,
      previousPermissions: ['tabs']
    };
  }
  if (risk === 'high') {
    return {
      networkCalls: [],
      backgroundFetches: ['https://analytics-unknown.io/track', 'https://unknown-cdn.net/js'],
      clipboardReads: 25,
      updateIntervalDays: 2,
      previousPermissions: ['storage']
    };
  }
  return {
    networkCalls: [],
    backgroundFetches: [],
    clipboardReads: 2,
    updateIntervalDays: 30,
    previousPermissions: []
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    analyzeExtensionBehavior,
    scanAllExtensions,
    computeBehavioralScore,
    generateMockRuntimeData,
    BEHAVIORAL_FLAGS,
    KNOWN_EXFIL_DOMAINS
  };
}
