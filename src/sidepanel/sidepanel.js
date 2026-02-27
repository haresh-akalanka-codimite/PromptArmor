// PromptArmor Side Panel — v2.1 Controller
// Enhanced multi-factor Extension Score Calculation Engine
// Integrates all 7 security features + AI provider settings

'use strict';

//=============================================================================
// NAVIGATION
//=============================================================================
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(view + '-view').classList.add('active');
    if (view === 'posture')    loadPostureView();
    if (view === 'threats')    loadThreatsView();
    if (view === 'governance') loadGovernanceView();
    if (view === 'simulator')  renderScenarios();
    if (view === 'settings')   loadSettingsView();
  });
});

//=============================================================================
// HELPERS
//=============================================================================
function h(text) {
  const d = document.createElement('div');
  d.textContent = String(text ?? '');
  return d.innerHTML;
}

function badgeClass(level) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', safe: 'badge-safe', info: 'badge-info' };
  return 'badge ' + (map[String(level).toLowerCase()] || 'badge-info');
}

function riskColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#f59e0b';
  return '#22c55e';
}

function setToggle(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('on', !!value);
}

function bindToggle(id, storageKey) {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener('click', function () {
    this.classList.toggle('on');
    chrome.storage.local.set({ [storageKey]: this.classList.contains('on') });
  });
}

//=============================================================================
// ② EXTENSIONS — Enhanced Multi-Factor Score Engine
//=============================================================================

/**
 * DIMENSION 1 — Permission Risk
 * Each permission category carries a base weight. Multiple permissions of the
 * same tier receive diminishing returns (via log scaling) so that a storm of
 * medium-risk perms doesn't unfairly eclipse a single critical one.
 */
const EXT_RISK_PERMS = {
  critical: {
    perms: ['debugger', 'proxy', 'vpnProvider', 'webRequestBlocking'],
    weight: 35,
    label: 'Critical'
  },
  high: {
    perms: ['webRequest', 'cookies', 'history', 'nativeMessaging', 'management', 'privacy'],
    weight: 22,
    label: 'High'
  },
  elevated: {
    perms: ['bookmarks', 'downloads', 'browsingData', 'contentSettings', 'declarativeNetRequest'],
    weight: 14,
    label: 'Elevated'
  },
  medium: {
    perms: ['tabs', 'activeTab', 'clipboardRead', 'clipboardWrite', 'notifications', 'webNavigation'],
    weight: 8,
    label: 'Medium'
  },
  low: {
    perms: ['storage', 'contextMenus', 'alarms', 'identity', 'geolocation'],
    weight: 4,
    label: 'Low'
  }
};

/**
 * DIMENSION 2 — Host Scope Risk
 * Measures the blast radius of host access grants.
 * Wildcard patterns are far more dangerous than targeted host access.
 */
function calcHostScopeScore(hostPermissions = []) {
  const hosts = hostPermissions;
  if (!hosts.length) return { score: 0, label: 'None', detail: 'No host permissions' };

  // Universal wildcards — maximum blast radius
  if (hosts.includes('<all_urls>'))   return { score: 40, label: 'Universal', detail: 'Access to ALL websites via <all_urls>' };
  if (hosts.includes('*://*/*'))      return { score: 38, label: 'Universal', detail: 'Access to ALL websites via *://*/*' };
  if (hosts.includes('http://*/*'))   return { score: 28, label: 'Broad HTTP', detail: 'Access to all HTTP sites' };
  if (hosts.includes('https://*/*'))  return { score: 24, label: 'Broad HTTPS', detail: 'Access to all HTTPS sites' };

  // Count partial wildcards (e.g., *://*.google.com/*)
  const partialWildcards = hosts.filter(h => h.includes('*') && !['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'].includes(h));
  const specificHosts    = hosts.filter(h => !h.includes('*'));

  let score = 0;
  score += Math.min(18, partialWildcards.length * 6);  // up to 18 pts for wildcards
  score += Math.min(6,  specificHosts.length * 2);     // up to 6 pts for specific hosts

  const label = partialWildcards.length > 0 ? 'Partial Wildcard' : 'Targeted';
  const detail = `${partialWildcards.length} wildcard(s), ${specificHosts.length} specific host(s)`;
  return { score, label, detail };
}

/**
 * DIMENSION 3 — Dangerous Permission Combinations
 * Certain permission pairings create attack chains that are greater than
 * the sum of their parts (e.g., intercepting and exfiltrating traffic).
 */
const DANGEROUS_COMBOS = [
  {
    perms: ['webRequest', 'cookies'],
    bonus: 20,
    label: 'Traffic interception + cookie theft vector',
    severity: 'critical'
  },
  {
    perms: ['webRequestBlocking', 'cookies'],
    bonus: 25,
    label: 'Blocking request interception with cookie access',
    severity: 'critical'
  },
  {
    perms: ['nativeMessaging', 'history'],
    bonus: 18,
    label: 'Native binary bridge + full browsing history',
    severity: 'high'
  },
  {
    perms: ['debugger', 'tabs'],
    bonus: 22,
    label: 'Full tab debugger attachment',
    severity: 'critical'
  },
  {
    perms: ['cookies', 'browsingData'],
    bonus: 15,
    label: 'Cookie access + data wipe capability',
    severity: 'high'
  },
  {
    perms: ['proxy', 'webRequest'],
    bonus: 28,
    label: 'Full proxy control + traffic inspection',
    severity: 'critical'
  },
  {
    perms: ['clipboardRead', 'tabs'],
    bonus: 12,
    label: 'Clipboard sniffing across all tabs',
    severity: 'high'
  },
  {
    perms: ['management', 'nativeMessaging'],
    bonus: 16,
    label: 'Extension manager + native binary execution',
    severity: 'critical'
  },
  {
    perms: ['identity', 'cookies'],
    bonus: 14,
    label: 'OAuth identity + cookie access (session hijack vector)',
    severity: 'high'
  },
  {
    perms: ['downloads', 'nativeMessaging'],
    bonus: 12,
    label: 'File download + native binary (dropper potential)',
    severity: 'high'
  }
];

function calcComboBonuses(perms = []) {
  const triggered = [];
  for (const combo of DANGEROUS_COMBOS) {
    if (combo.perms.every(p => perms.includes(p))) {
      triggered.push(combo);
    }
  }
  // Cap total combo bonus at 50 to avoid unfair saturation
  const totalBonus = Math.min(50, triggered.reduce((s, c) => s + c.bonus, 0));
  return { score: totalBonus, combos: triggered };
}

/**
 * DIMENSION 4 — Metadata & Provenance Risk
 * Analyzes extension install source, update path, and verification signals.
 * An extension from outside the Web Store with no verified publisher is
 * inherently less trustworthy regardless of its permissions.
 */
function calcMetadataScore(ext) {
  const signals = [];
  let score = 0;

  // Sideloaded / developer mode
  if (ext.installType === 'development') {
    score += 20;
    signals.push({ severity: 'high', text: 'Installed in developer mode (sideloaded)' });
  }
  if (ext.installType === 'sideload') {
    score += 15;
    signals.push({ severity: 'high', text: 'Sideloaded — not installed from Web Store' });
  }

  // No update URL = not auto-updated, potential abandoned/malicious
  if (!ext.updateUrl) {
    score += 8;
    signals.push({ severity: 'medium', text: 'No update URL — extension is not auto-updated' });
  }

  // Update URL pointing outside CWS
  const cwsUpdateHosts = ['clients2.google.com', 'clients.google.com'];
  if (ext.updateUrl) {
    const isCWS = cwsUpdateHosts.some(h => ext.updateUrl.includes(h));
    if (!isCWS) {
      score += 12;
      signals.push({ severity: 'high', text: `Update URL points to non-CWS host: ${new URL(ext.updateUrl).hostname}` });
    }
  }

  // No homepage URL
  if (!ext.homepageUrl) {
    score += 3;
    signals.push({ severity: 'low', text: 'No homepage URL declared' });
  }

  return { score: Math.min(35, score), signals };
}

/**
 * DIMENSION 5 — Behavioral Heuristics (Name/Description Anomaly)
 * Detects mismatches between an extension's declared purpose and its
 * permissions — a common trait of trojanised or malicious extensions.
 */
const BEHAVIORAL_HEURISTICS = [
  {
    // "Productivity" apps with network interception
    namePattern: /(?:productivity|notes?|todo|task|calendar|agenda|planner)/i,
    dangerPerms:  ['webRequest', 'webRequestBlocking', 'proxy', 'nativeMessaging'],
    bonus: 15,
    label: 'Productivity-labeled extension with traffic interception permissions'
  },
  {
    // "Translator" / "Grammar" with native messaging
    namePattern: /(?:translat|grammar|spell|writ|language)/i,
    dangerPerms:  ['nativeMessaging', 'debugger'],
    bonus: 12,
    label: 'Language tool with privileged system access permissions'
  },
  {
    // "Coupon" / "Shopping" with full history access
    namePattern: /(?:coupon|deal|discount|cashback|shop|price)/i,
    dangerPerms:  ['history', 'browsingData', 'cookies'],
    bonus: 14,
    label: 'Shopping tool with broad data harvesting permissions'
  },
  {
    // "Theme" / "New Tab" with remote code execution potential
    namePattern: /(?:theme|wallpaper|new\s?tab|start\s?page|dark\s?mode)/i,
    dangerPerms:  ['webRequest', 'cookies', 'history'],
    bonus: 13,
    label: 'Cosmetic extension with data access permissions'
  },
  {
    // "VPN" / "Proxy" with cookie access (MITM vector)
    namePattern: /(?:vpn|proxy|tunnel|privacy|secure|shield|guard)/i,
    dangerPerms:  ['cookies', 'history', 'browsingData'],
    bonus: 16,
    label: 'Privacy tool with data harvesting permissions (MITM risk)'
  },
  {
    // Generic names — single word / very short names are often malicious
    namePattern: /^[a-z]{2,8}$/i,
    dangerPerms:  ['webRequest', 'cookies', 'nativeMessaging'],
    bonus: 10,
    label: 'Suspiciously generic extension name with sensitive permissions'
  }
];

function calcBehavioralScore(ext) {
  const signals = [];
  let score = 0;
  const perms = ext.permissions || [];
  const name  = ext.name || '';

  for (const heuristic of BEHAVIORAL_HEURISTICS) {
    const nameMatch = heuristic.namePattern.test(name);
    const hasAnyDangerPerm = heuristic.dangerPerms.some(p => perms.includes(p));
    if (nameMatch && hasAnyDangerPerm) {
      score += heuristic.bonus;
      signals.push({ severity: 'high', text: heuristic.label });
    }
  }

  // Unusually high permission count (>8 perms is suspicious even if individually benign)
  if (perms.length > 8) {
    const excess = perms.length - 8;
    const bonus  = Math.min(12, excess * 2);
    score += bonus;
    signals.push({ severity: 'medium', text: `Declares ${perms.length} permissions (${excess} above typical threshold)` });
  }

  return { score: Math.min(30, score), signals };
}

/**
 * MASTER SCORE FUNCTION — calcExtScore(ext)
 * Aggregates all 5 dimensions into a single 0–100 risk score.
 * Each dimension is capped individually before combining to prevent
 * any single factor from dominating the result.
 *
 * Dimension weights (max contribution):
 *   Permission Risk     → up to 45 pts  (core capability risk)
 *   Host Scope          → up to 40 pts  (blast radius)
 *   Combo Bonuses       → up to 50 pts  (attack chain risk)
 *   Metadata/Provenance → up to 35 pts  (trust/origin risk)
 *   Behavioral Heuristic→ up to 30 pts  (intent mismatch risk)
 *
 * Raw total can exceed 100; final score is clamped to [0, 100].
 */
function calcExtScore(ext) {
  const perms = ext.permissions || [];
  const hosts = ext.hostPermissions || [];

  // --- Dimension 1: Permission Risk (with diminishing returns per tier) ---
  let permScore = 0;
  for (const [tier, def] of Object.entries(EXT_RISK_PERMS)) {
    const matched = def.perms.filter(p => perms.includes(p));
    if (matched.length === 0) continue;
    // First match = full weight; subsequent matches = log-scaled reduction
    const baseContrib  = def.weight;
    const extraContrib = matched.length > 1
      ? Math.floor(def.weight * 0.4 * Math.log2(matched.length))
      : 0;
    permScore += baseContrib + extraContrib;
  }
  permScore = Math.min(45, permScore);

  // --- Dimension 2: Host Scope ---
  const hostResult = calcHostScopeScore(hosts);
  const hostScore  = Math.min(40, hostResult.score);

  // --- Dimension 3: Dangerous Combos ---
  const comboResult = calcComboBonuses(perms);
  const comboScore  = comboResult.score; // already capped at 50

  // --- Dimension 4: Metadata / Provenance ---
  const metaResult = calcMetadataScore(ext);
  const metaScore  = metaResult.score; // already capped at 35

  // --- Dimension 5: Behavioral Heuristics ---
  const behavResult = calcBehavioralScore(ext);
  const behavScore  = behavResult.score; // already capped at 30

  // --- Composite ---
  const raw   = permScore + hostScore + comboScore + metaScore + behavScore;
  const final = Math.max(0, Math.min(100, raw));

  return final;
}

/**
 * explainExtScore(ext) — returns a full breakdown for UI display.
 * Call this in showExtDetail() to power the enhanced detail card.
 */
function explainExtScore(ext) {
  const perms = ext.permissions || [];
  const hosts = ext.hostPermissions || [];

  const permFlags = [];
  let permScore = 0;
  for (const [tier, def] of Object.entries(EXT_RISK_PERMS)) {
    const matched = def.perms.filter(p => perms.includes(p));
    if (!matched.length) continue;
    const base  = def.weight;
    const extra = matched.length > 1 ? Math.floor(def.weight * 0.4 * Math.log2(matched.length)) : 0;
    const contrib = Math.min(45, base + extra);
    permScore += contrib;
    matched.forEach(p => permFlags.push({ severity: tier === 'critical' ? 'critical' : tier === 'high' || tier === 'elevated' ? 'high' : 'medium', text: `[${def.label}] permission: ${p}`, pts: def.weight }));
  }
  permScore = Math.min(45, permScore);

  const hostResult = calcHostScopeScore(hosts);
  const comboResult = calcComboBonuses(perms);
  const metaResult  = calcMetadataScore(ext);
  const behavResult = calcBehavioralScore(ext);

  const breakdown = [
    { dimension: 'Permission Risk',      score: permScore,                    flags: permFlags },
    { dimension: 'Host Scope',           score: Math.min(40, hostResult.score), flags: hostResult.score > 0 ? [{ severity: 'high', text: `${hostResult.label}: ${hostResult.detail}` }] : [] },
    { dimension: 'Dangerous Combos',     score: comboResult.score,             flags: comboResult.combos.map(c => ({ severity: c.severity, text: c.label, pts: c.bonus })) },
    { dimension: 'Metadata/Provenance',  score: metaResult.score,              flags: metaResult.signals },
    { dimension: 'Behavioral Heuristics',score: behavResult.score,             flags: behavResult.signals }
  ];

  const totalRaw = breakdown.reduce((s, b) => s + b.score, 0);
  const total    = Math.max(0, Math.min(100, totalRaw));

  return { total, breakdown };
}

/**
 * extVerdict(score) — converts numeric score to risk label + badge class + reason.
 */
function extVerdict(score) {
  if (score >= 70) return { label: 'CRITICAL', cls: 'badge-critical', reason: 'Multiple severe risk factors detected — immediate review required' };
  if (score >= 50) return { label: 'HIGH',     cls: 'badge-high',     reason: 'Significant risk factors present — restrict or investigate' };
  if (score >= 30) return { label: 'MEDIUM',   cls: 'badge-medium',   reason: 'Moderate risk factors — monitor closely' };
  if (score >= 10) return { label: 'LOW',      cls: 'badge-safe',     reason: 'Minor risk factors — acceptable for general use' };
  return                   { label: 'SAFE',    cls: 'badge-safe',     reason: 'No significant risk factors detected' };
}

//=============================================================================
// ① POSTURE VIEW — Enhanced
//=============================================================================
const DEDUCTIONS = {
  criticalExtension:  22,   // raised slightly for multi-factor scoring alignment
  highExtension:      12,
  mediumExtension:     5,   // NEW: medium-tier extensions now contribute
  unmanagedDevice:    20,
  policyViolation:    15,
  noExtensionPolicy:  10,
  unsanctionedAITool:  8,
  sensitiveDataToAI:  12,
  injectionAttempt:   15,
  sideloadedExtension: 8,   // NEW: sideloaded ext is a separate deduction
};

function calcPostureLocally(data) {
  let deductions = 0;
  const findings = [];

  const extensions = data.extensions || [];

  // Critical extensions (score >= 70 under new model)
  extensions.filter(e => e.score >= 70).forEach(e => {
    deductions += DEDUCTIONS.criticalExtension;
    findings.push({ label: `Critical extension: ${e.name} (score ${e.score})`, severity: 'critical', d: DEDUCTIONS.criticalExtension });
  });

  // High-risk extensions (50–69)
  extensions.filter(e => e.score >= 50 && e.score < 70).forEach(e => {
    deductions += DEDUCTIONS.highExtension;
    findings.push({ label: `High-risk extension: ${e.name} (score ${e.score})`, severity: 'high', d: DEDUCTIONS.highExtension });
  });

  // Medium extensions (30–49) — now contribute to posture
  const mediumExts = extensions.filter(e => e.score >= 30 && e.score < 50);
  if (mediumExts.length >= 3) {
    // Cluster effect: 3+ medium extensions = elevated posture risk
    const d = Math.min(20, mediumExts.length * DEDUCTIONS.mediumExtension);
    deductions += d;
    findings.push({ label: `${mediumExts.length} medium-risk extensions installed (cluster effect)`, severity: 'medium', d });
  }

  // Sideloaded extensions — provenance risk
  const sideloaded = extensions.filter(e => e._installType === 'development' || e._installType === 'sideload');
  if (sideloaded.length > 0) {
    deductions += DEDUCTIONS.sideloadedExtension * sideloaded.length;
    findings.push({ label: `${sideloaded.length} sideloaded extension(s) detected`, severity: 'high', d: DEDUCTIONS.sideloadedExtension * sideloaded.length });
  }

  // Unmanaged device
  if (!data.cepConnected) {
    deductions += DEDUCTIONS.unmanagedDevice;
    findings.push({ label: 'Device not managed via CEP', severity: 'critical', d: DEDUCTIONS.unmanagedDevice });
  }

  // Injection attempts — proportional with a higher per-event penalty
  if ((data.injectionAttempts || 0) > 0) {
    // Non-linear: first attempt = 15pts, each extra = +5 up to 35 total
    const d = Math.min(35, 15 + Math.max(0, data.injectionAttempts - 1) * 5);
    deductions += d;
    findings.push({ label: `${data.injectionAttempts} injection attempt(s) blocked`, severity: 'high', d });
  }

  // Unsanctioned AI tools
  if ((data.aiUnsanctioned || 0) > 0) {
    deductions += DEDUCTIONS.unsanctionedAITool;
    findings.push({ label: `${data.aiUnsanctioned} unsanctioned AI tool(s) detected`, severity: 'medium', d: DEDUCTIONS.unsanctionedAITool });
  }

  // Sensitive data submitted to AI
  if ((data.sensitiveAISubmissions || 0) > 0) {
    const d = Math.min(24, DEDUCTIONS.sensitiveDataToAI * data.sensitiveAISubmissions);
    deductions += d;
    findings.push({ label: `${data.sensitiveAISubmissions} sensitive data submission(s) to AI`, severity: 'high', d });
  }

  const score = Math.max(0, Math.min(100, 100 - deductions));
  return { score, findings, cepConnected: data.cepConnected };
}

function gradeFromScore(score) {
  if (score >= 90) return { label: 'EXCELLENT', color: '#22c55e' };
  if (score >= 75) return { label: 'GOOD',      color: '#84cc16' };
  if (score >= 60) return { label: 'FAIR',       color: '#f59e0b' };
  if (score >= 40) return { label: 'POOR',       color: '#f97316' };
  return                   { label: 'CRITICAL',  color: '#ef4444' };
}

async function loadPostureView() {
  const stored = await chrome.storage.local.get(['postureResult', 'firewallStats', 'aiGovernanceStats']);
  const fw  = stored.firewallStats      || {};
  const ag  = stored.aiGovernanceStats  || {};

  let extensions = [];
  try {
    const all = await chrome.management.getAll();
    extensions = all
      .filter(e => e.type === 'extension' && e.enabled && e.id !== chrome.runtime.id)
      .map(e => ({ name: e.name, score: calcExtScore(e), _installType: e.installType }));
  } catch (_) {}

  let cepConnected = false;
  try {
    const managed = await chrome.storage.managed.get(null);
    cepConnected = Object.keys(managed).length > 0;
  } catch (_) {}

  const data = {
    extensions,
    cepConnected,
    injectionAttempts:      fw.blocked            || 0,
    aiUnsanctioned:         ag.unsanctionedTools   || 0,
    sensitiveAISubmissions: ag.sensitiveSubmissions || 0
  };

  const result = calcPostureLocally(data);
  const grade  = gradeFromScore(result.score);

  const ring = document.getElementById('postureRing');
  ring.style.border     = `6px solid ${grade.color}`;
  ring.style.background = grade.color + '18';
  document.getElementById('postureScore').textContent = result.score;
  document.getElementById('postureScore').style.color = grade.color;
  document.getElementById('postureGrade').textContent = grade.label;
  document.getElementById('postureGrade').style.color = grade.color;

  const risky = extensions.filter(e => e.score >= 30).length;
  document.getElementById('postureExts').textContent    = risky;
  document.getElementById('postureBlocked').textContent = fw.blocked || 0;
  document.getElementById('postureCEP').textContent     = cepConnected ? '✓' : '✗';
  document.getElementById('postureCEP').style.color     = cepConnected ? '#22c55e' : '#ef4444';

  const trend = document.getElementById('postureTrend');
  trend.textContent = cepConnected ? '🔗 CEP Connected' : '⚠️ CEP not detected';
  trend.style.color = cepConnected ? '#22c55e' : '#f59e0b';

  const fEl = document.getElementById('postureFindings');
  if (result.findings.length === 0) {
    fEl.innerHTML = '<div class="empty">✅ No critical findings</div>';
  } else {
    fEl.innerHTML = result.findings.map(f => `
      <div class="threat-item ${f.severity === 'medium' ? 'medium' : f.severity === 'low' ? 'low' : ''}">
        <div class="threat-class">${f.severity.toUpperCase()} · -${f.d} pts</div>
        <div class="threat-label">${h(f.label)}</div>
      </div>`).join('');
  }

  const recs = buildRecs(result.findings, cepConnected);
  const rEl  = document.getElementById('postureRecs');
  rEl.innerHTML = recs.length === 0
    ? '<div class="empty">✅ No recommendations</div>'
    : recs.map(r => `
      <div class="rec-item ${r.priority}">
        <div class="rec-title">${h(r.title)}</div>
        <div class="rec-desc">${h(r.description)}</div>
        ${r.details ? `<div class="rec-desc" style="color:#94a3b8;margin-top:2px;font-size:0.75rem">${h(r.details)}</div>` : ''}
        ${r.cepRequired ? '<div class="rec-desc" style="color:#3b82f6;margin-top:4px">🔗 Requires CEP</div>' : ''}
      </div>`).join('');
}

function buildRecs(findings, cepConnected) {
  const recs = [];
  const hasCriticalExt    = findings.some(f => f.label.startsWith('Critical extension'));
  const hasHighExt        = findings.some(f => f.label.startsWith('High-risk extension'));
  const hasMediumCluster  = findings.some(f => f.label.includes('medium-risk extensions'));
  const hasSideloaded     = findings.some(f => f.label.includes('sideloaded'));
  const notCEP            = !cepConnected;
  const hasInjection      = findings.some(f => f.label.includes('injection'));
  const hasUnsanctioned   = findings.some(f => f.label.includes('unsanctioned AI tool'));
  const hasSensitiveAI    = findings.some(f => f.label.includes('sensitive data submission'));

  const criticalExtFinding  = findings.find(f => f.label.startsWith('Critical extension'));
  const injectionFinding    = findings.find(f => f.label.includes('injection'));

  if (notCEP)
    recs.push({ priority: 'critical', title: 'Enrol device in Chrome Enterprise Management', description: 'Centrally managed devices gain policy enforcement, extension control, and audit logging.', cepRequired: true });

  if (hasCriticalExt)
    recs.push({ priority: 'critical', title: 'Block critical-risk extensions via CEP allowlist', description: 'Apply ExtensionInstallBlocklist policy to remove flagged extensions org-wide.', details: criticalExtFinding?.label, cepRequired: true });

  if (hasSideloaded)
    recs.push({ priority: 'high', title: 'Prohibit developer-mode / sideloaded extensions', description: 'Set DeveloperToolsAvailability to block developer mode to prevent sideloading.', cepRequired: true });

  if (hasHighExt)
    recs.push({ priority: 'high', title: 'Restrict high-risk extension permissions', description: 'Use ExtensionSettings policy to supervise or restrict these extensions.', cepRequired: true });

  if (hasMediumCluster)
    recs.push({ priority: 'medium', title: 'Review medium-risk extension cluster', description: 'Multiple medium-risk extensions create a cumulative attack surface — audit which are necessary.' });

  if (hasInjection)
    recs.push({ priority: 'high', title: 'Enable URL filtering for injection-source domains', description: 'CEP URLBlocklist policy blocks repeated injection vectors at network level.', details: injectionFinding?.label, cepRequired: true });

  if (hasSensitiveAI)
    recs.push({ priority: 'high', title: 'Enable DLP redaction for AI submissions', description: 'Sensitive data detected in AI tool submissions — enable auto-redaction to prevent data leakage.' });

  if (hasUnsanctioned)
    recs.push({ priority: 'medium', title: 'Create AI domain allowlist in CEP', description: 'Restrict access to approved AI tools only via URLAllowlist policy.', cepRequired: true });

  return recs;
}

document.getElementById('runPostureBtn').addEventListener('click', loadPostureView);

//=============================================================================
// EXTENSIONS VIEW — Enhanced Scan + Detail
//=============================================================================
async function scanExtensions() {
  const listEl = document.getElementById('extList');
  listEl.innerHTML = '<div class="empty">Analysing…</div>';

  try {
    const all = await chrome.management.getAll();
    const results = all
      .filter(e => e.type === 'extension' && e.enabled && e.id !== chrome.runtime.id)
      .map(e => {
        const score = calcExtScore(e);
        return { ...e, score, ...extVerdict(score) };
      })
      .sort((a, b) => b.score - a.score);

    document.getElementById('extTotal').textContent = results.length;
    document.getElementById('extRisky').textContent = results.filter(r => r.score >= 30).length;

    if (results.length === 0) {
      listEl.innerHTML = '<div class="empty">No extensions found</div>';
      return;
    }

    listEl.innerHTML = results.map(ext => `
      <div class="list-item" data-extid="${h(ext.id)}" data-extscore="${ext.score}" data-extname="${h(ext.name)}" style="cursor:pointer">
        <div class="list-item-left">
          <div class="list-item-name">${h(ext.name)}</div>
          <div class="list-item-sub">${h(ext.reason)}</div>
        </div>
        <span class="badge ${ext.cls}">${ext.label} · ${ext.score}</span>
      </div>`).join('');

    listEl.querySelectorAll('.list-item').forEach(item => {
      item.addEventListener('click', () => showExtDetail(
        item.dataset.extid,
        item.dataset.extname,
        parseInt(item.dataset.extscore),
        results.find(r => r.id === item.dataset.extid)
      ));
    });

  } catch (e) {
    listEl.innerHTML = `<div class="empty">Error: ${h(e.message)}</div>`;
  }
}

function showExtDetail(id, name, score, ext) {
  const card = document.getElementById('extDetailCard');
  document.getElementById('extDetailName').textContent = name;
  const v = extVerdict(score);
  document.getElementById('extDetailBadge').textContent = `${v.label} · ${score}/100`;
  document.getElementById('extDetailBadge').className   = 'badge ' + v.cls;

  // Use explainExtScore for full breakdown
  const explanation = explainExtScore(ext || {});

  // Render dimension breakdown
  const flagsEl = document.getElementById('extDetailFlags');
  flagsEl.innerHTML = explanation.breakdown.map(dim => {
    const dimFlags = dim.flags;
    if (dim.score === 0 && dimFlags.length === 0) return '';
    return `
      <div style="margin-bottom:10px">
        <div class="threat-class" style="color:#94a3b8;margin-bottom:4px">
          ${h(dim.dimension)} · <span style="color:${riskColor(dim.score)}">${dim.score} pts</span>
        </div>
        ${dimFlags.length === 0
          ? `<div style="font-size:0.75rem;color:#64748b;padding:4px 0">No flags in this dimension</div>`
          : dimFlags.map(f => `
            <div class="threat-item ${f.severity === 'critical' ? '' : f.severity === 'medium' ? 'medium' : ''}">
              <div class="threat-label">${h(f.text)}</div>
            </div>`).join('')
        }
      </div>`;
  }).join('') || '<div class="empty" style="padding:10px">No behavioral flags</div>';

  // CEP actions
  const actionsEl = document.getElementById('extDetailActions');
  if (score >= 50) {
    actionsEl.innerHTML = `
      <button class="btn btn-sm btn-danger" onclick="alert('CEP policy: ExtensionInstallBlocklist: [\\"${h(id)}\\"]')">Block via CEP</button>
      <button class="btn btn-sm btn-ghost" onclick="alert('Policy simulated — posture score would improve by ~${Math.min(22, score > 70 ? 22 : 12)} pts')">Simulate Impact</button>`;
  } else if (score >= 30) {
    actionsEl.innerHTML = `
      <button class="btn btn-sm btn-ghost" onclick="alert('CEP policy: ExtensionSettings — restrict permissions')">Restrict via CEP</button>
      <button class="btn btn-sm btn-ghost" onclick="alert('Policy simulated — posture score would improve by ~${12} pts')">Simulate Impact</button>`;
  } else {
    actionsEl.innerHTML = '<span class="form-hint">No action required</span>';
  }

  card.style.display = 'block';
}

document.getElementById('scanExtBtn').addEventListener('click', scanExtensions);

//=============================================================================
// ③ THREATS VIEW — Injection Shield (unchanged)
//=============================================================================
const SHIELD_PATTERNS = [
  { re: /ignore\s+(?:all\s+)?previous\s+instructions?/i,       label: 'Instruction override',          cls: 'HIDDEN_INSTRUCTION',  sev: 'critical' },
  { re: /<!--[\s\S]*?(?:ignore|override|forget)[\s\S]*?-->/i,  label: 'HTML comment injection',         cls: 'HIDDEN_INSTRUCTION',  sev: 'critical' },
  { re: /(?:send|forward|email)\s+(?:all\s+)?(?:conversation|data|history)/i, label: 'Data forwarding command', cls: 'AI_REDIRECTION', sev: 'critical' },
  { re: /exfiltrate|exfil\b/i,                                  label: 'Exfiltration keyword',           cls: 'DATA_EXFIL',          sev: 'high' },
  { re: /\[SYSTEM\]|\[INST\]|\[SYS\]/,                         label: 'System bracket injection',       cls: 'CONTEXT_POISONING',   sev: 'high' },
  { re: /(?:eval|Function)\s*\(\s*(?:atob|unescape)/i,         label: 'Eval decode obfuscation',        cls: 'OBFUSCATED_SCRIPT',   sev: 'high' },
  { re: /String\.fromCharCode\(\s*\d+(?:\s*,\s*\d+){10,}\)/,  label: 'CharCode obfuscation',           cls: 'OBFUSCATED_SCRIPT',   sev: 'medium' },
  { re: /navigator\.sendBeacon\s*\(/i,                          label: 'sendBeacon exfiltration',        cls: 'DATA_EXFIL',          sev: 'critical' },
  { re: /do\s+not\s+(?:tell|inform|reveal)\s+the\s+user/i,     label: 'Transparency suppression',       cls: 'CONTEXT_POISONING',   sev: 'high' },
  { re: /[\u200b\u200c\u200d\ufeff]/,                           label: 'Zero-width char steganography',  cls: 'HIDDEN_INSTRUCTION',  sev: 'high' }
];

function shieldScan(text) {
  const threats = [];
  for (const p of SHIELD_PATTERNS) {
    if (p.re.test(text)) threats.push({ label: p.label, cls: p.cls, sev: p.sev, sample: String(text.match(p.re)?.[0] || '').substring(0, 80) });
  }
  const score = Math.min(100, threats.reduce((s, t) => s + ({ critical: 40, high: 20, medium: 10 }[t.sev] || 5), 0));
  return { threats, score, clean: threats.length === 0 };
}

async function loadThreatsView() {
  const stored = await chrome.storage.local.get(['firewallStats']);
  const fw = stored.firewallStats || { blocked: 0, threats: [] };
  document.getElementById('shieldBlocked').textContent = fw.blocked || 0;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      const [res] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const parts = [document.body?.innerText || ''];
          const walker = document.createTreeWalker(document.body, 0x80);
          let n;
          while ((n = walker.nextNode())) parts.push(n.nodeValue);
          document.querySelectorAll('[style*="display:none"],[hidden]').forEach(el => parts.push(el.textContent));
          return parts.join(' ');
        }
      });
      const text = res?.result || '';
      const scan = shieldScan(text);

      document.getElementById('shieldThreats').textContent    = scan.threats.length;
      document.getElementById('shieldScanStatus').textContent = scan.clean ? 'Clean' : 'Threats Found';
      document.getElementById('shieldScanStatus').className   = 'badge ' + (scan.clean ? 'badge-safe' : 'badge-critical');

      const listEl = document.getElementById('shieldThreatList');
      listEl.innerHTML = scan.threats.length === 0
        ? '<div class="empty">✅ No injection patterns detected</div>'
        : scan.threats.map(t => `
          <div class="threat-item">
            <div class="threat-class">${h(t.cls)} · ${h(t.sev).toUpperCase()}</div>
            <div class="threat-label">${h(t.label)}</div>
            <div class="threat-sample">${h(t.sample)}</div>
          </div>`).join('');

      const prob = (scan.score / 100).toFixed(2);
      const action = scan.score >= 60 ? 'block' : scan.score >= 20 ? 'sanitize' : 'allow';
      const actionColor = { block: '#ef4444', sanitize: '#f59e0b', allow: '#22c55e' }[action];
      document.getElementById('shieldExposure').innerHTML = `
        <div class="stat-grid-3" style="margin:0">
          <div class="stat"><div class="stat-value" style="color:${actionColor}">${scan.score}%</div><div class="stat-label">Risk Score</div></div>
          <div class="stat"><div class="stat-value" style="color:${actionColor}">${prob}</div><div class="stat-label">Malicious Prob</div></div>
          <div class="stat"><div class="stat-value" style="color:${actionColor};font-size:1rem;text-transform:uppercase">${action}</div><div class="stat-label">Action</div></div>
        </div>`;
    }
  } catch (e) {
    document.getElementById('shieldScanStatus').textContent = 'Error';
    document.getElementById('shieldScanStatus').className   = 'badge badge-medium';
  }
}

document.getElementById('rescanPageBtn').addEventListener('click', loadThreatsView);
bindToggle('hiddenScanToggle', 'hiddenScan');
bindToggle('firewallToggle',   'firewallEnabled');
bindToggle('sanitizeToggle',   'sanitizeEnabled');

//=============================================================================
// ④ GOVERNANCE VIEW — AI Governance + PII (unchanged)
//=============================================================================
const AI_DOMAINS = {
  'chat.openai.com':       { name: 'ChatGPT',     risk: 'medium', sanctioned: false },
  'openai.com':            { name: 'OpenAI',       risk: 'medium', sanctioned: false },
  'claude.ai':             { name: 'Claude',       risk: 'medium', sanctioned: false },
  'gemini.google.com':     { name: 'Gemini',       risk: 'low',    sanctioned: true  },
  'copilot.microsoft.com': { name: 'Copilot',      risk: 'low',    sanctioned: true  },
  'perplexity.ai':         { name: 'Perplexity',   risk: 'medium', sanctioned: false },
  'character.ai':          { name: 'Character.AI', risk: 'high',   sanctioned: false }
};

const PII_PATS = {
  Email:         /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  SSN:           /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
  'Credit Card': /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  Phone:         /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  'API Key':     /(AKIA|AIza|ghp_|sk-)[a-zA-Z0-9_-]{16,}/g,
  JWT:           /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g
};

async function loadGovernanceView() {
  const stored   = await chrome.storage.local.get(['aiGovernanceStats', 'govAuditLog']);
  const stats    = stored.aiGovernanceStats || {};
  const auditLog = stored.govAuditLog || [];

  document.getElementById('govBlocked').textContent      = stats.blocked || 0;
  document.getElementById('govRedacted').textContent     = stats.redacted || 0;
  document.getElementById('govUnsanctioned').textContent = stats.unsanctionedTools || 0;

  const domainEl = document.getElementById('govDomainList');
  if (auditLog.length === 0) {
    domainEl.innerHTML = '<div class="empty">No AI usage recorded. Governance triggers on AI site visits.</div>';
  } else {
    const counts = {};
    auditLog.forEach(e => { counts[e.domain] = (counts[e.domain] || 0) + 1; });
    domainEl.innerHTML = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([domain, count]) => {
        const info     = AI_DOMAINS[domain] || { name: domain, risk: 'unknown', sanctioned: false };
        const badgeCls = info.sanctioned ? 'badge-safe' : info.risk === 'high' ? 'badge-critical' : 'badge-medium';
        const label    = info.sanctioned ? 'Sanctioned' : info.risk === 'high' ? 'Prohibited' : 'Unsanctioned';
        return `<div class="list-item">
          <div class="list-item-left">
            <div class="list-item-name">${h(info.name)}</div>
            <div class="list-item-sub">${count} event(s) · ${h(domain)}</div>
          </div>
          <span class="badge ${badgeCls}">${label}</span>
        </div>`;
      }).join('');
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      const [res] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => document.body?.innerText || ''
      });
      const text = res?.result || '';
      const piiFindings = [];
      let piiCount = 0, secretCount = 0;
      for (const [type, pattern] of Object.entries(PII_PATS)) {
        const matches = text.match(pattern);
        if (matches) {
          const isSecret = ['API Key', 'JWT'].includes(type);
          piiFindings.push({ type, count: matches.length, isSecret, sample: matches[0].substring(0, 40) });
          isSecret ? (secretCount += matches.length) : (piiCount += matches.length);
        }
      }
      document.getElementById('piiFound').textContent     = piiCount;
      document.getElementById('secretsFound').textContent = secretCount;
      const piiEl = document.getElementById('piiList');
      piiEl.innerHTML = piiFindings.length === 0
        ? '<div class="empty">No PII detected</div>'
        : piiFindings.map(f => `
          <div class="threat-item ${f.isSecret ? '' : 'medium'}">
            <div class="threat-class">${h(f.type)} · ${f.count} match(es)</div>
            <div class="threat-sample">${h(f.sample)}…</div>
          </div>`).join('');
    }
  } catch (_) {}
}

document.getElementById('govScanBtn').addEventListener('click', loadGovernanceView);
bindToggle('autoRedactToggle',        'autoRedact');
bindToggle('blockUnsanctionedToggle', 'blockUnsanctioned');
bindToggle('dlpToggle',               'dlpEnabled');

//=============================================================================
// ⑤ HEATMAP VIEW (unchanged)
//=============================================================================
const MOCK_DEPTS = [
  { name: 'Marketing',   userCount: 45, highRiskExtensions: 19, aiSensitiveSubmissions: 8,  injectionAttempts: 2, policyViolations: 3 },
  { name: 'Engineering', userCount: 80, highRiskExtensions: 12, aiSensitiveSubmissions: 22, injectionAttempts: 5, policyViolations: 1 },
  { name: 'Finance',     userCount: 30, highRiskExtensions: 2,  aiSensitiveSubmissions: 15, injectionAttempts: 0, policyViolations: 5 },
  { name: 'HR',          userCount: 20, highRiskExtensions: 4,  aiSensitiveSubmissions: 10, injectionAttempts: 1, policyViolations: 2 },
  { name: 'Legal',       userCount: 15, highRiskExtensions: 1,  aiSensitiveSubmissions:  5, injectionAttempts: 0, policyViolations: 1 },
  { name: 'Sales',       userCount: 60, highRiskExtensions: 20, aiSensitiveSubmissions: 18, injectionAttempts: 3, policyViolations: 2 },
  { name: 'Support',     userCount: 35, highRiskExtensions: 8,  aiSensitiveSubmissions:  6, injectionAttempts: 1, policyViolations: 0 }
];

function calcDeptRisk(dept) {
  const u         = dept.userCount || 1;
  const extScore  = Math.min(100, (dept.highRiskExtensions / u) * 200);
  const aiScore   = Math.min(100, (dept.aiSensitiveSubmissions / u) * 300);
  const injScore  = Math.min(100, dept.injectionAttempts * 20);
  const compScore = Math.min(100, dept.policyViolations * 15);
  const composite = Math.round(extScore * .35 + aiScore * .30 + injScore * .20 + compScore * .15);
  return { name: dept.name, score: composite, userCount: u, highRiskExtensionRate: dept.highRiskExtensions / u };
}

function loadHeatmap() {
  const assessed = MOCK_DEPTS.map(calcDeptRisk).sort((a, b) => b.score - a.score);
  const orgAvg   = Math.round(assessed.reduce((s, d) => s + d.score, 0) / assessed.length);
  const hot      = assessed.filter(d => d.score >= 60).length;

  document.getElementById('heatmapOrgAvg').textContent   = orgAvg;
  document.getElementById('heatmapHotDepts').textContent = hot;

  const chartEl = document.getElementById('heatmapChart');
  chartEl.innerHTML = assessed.map(d => {
    const color = riskColor(d.score);
    return `<div class="heatmap-row">
      <div class="dept-name">${h(d.name)}</div>
      <div class="risk-bar-track">
        <div class="risk-bar-fill" style="width:${d.score}%;background:${color}"></div>
      </div>
      <div class="risk-score" style="color:${color}">${d.score}</div>
    </div>`;
  }).join('');

  const recs      = [];
  const avgExtRate = assessed.reduce((s, d) => s + d.highRiskExtensionRate, 0) / assessed.length;
  assessed.forEach(d => {
    const anomalyRatio = avgExtRate > 0 ? (d.highRiskExtensionRate / avgExtRate).toFixed(1) : 1;
    if (d.score >= 60) {
      recs.push({
        priority: d.score >= 80 ? 'critical' : 'high',
        title: `Harden policies for ${d.name}`,
        description: `Risk score ${d.score}/100. ${anomalyRatio}x org average extension risk rate.`
      });
    }
  });

  const recEl = document.getElementById('policyRecList');
  recEl.innerHTML = recs.length === 0
    ? '<div class="empty">All departments within acceptable risk range</div>'
    : recs.map(r => `
      <div class="rec-item ${r.priority}">
        <div class="rec-title">${h(r.title)}</div>
        <div class="rec-desc">${h(r.description)}</div>
        <div class="rec-actions">
          <button class="btn btn-sm btn-primary" onclick="alert('Policy queued for CEP sync')">Apply via CEP</button>
          <button class="btn btn-sm btn-ghost"   onclick="alert('Simulating impact…')">Simulate</button>
          <button class="btn btn-sm btn-ghost"   onclick="alert('Change rolled back')">Rollback</button>
        </div>
      </div>`).join('');
}

document.getElementById('loadHeatmapBtn').addEventListener('click', loadHeatmap);

//=============================================================================
// ⑥ SIMULATOR VIEW (unchanged)
//=============================================================================
const SCENARIOS = [
  {
    id: 'phishing', icon: '🎣', name: 'AI-Generated Phishing', desc: 'LLM-crafted spear-phishing attack hits browser',
    steps: [
      { phase: 'threat',     label: 'Attacker crafts hyper-personalised phishing email via LLM' },
      { phase: 'threat',     label: 'User clicks link — malicious page loads' },
      { phase: 'detected',   label: 'PromptArmor scans page for injection patterns' },
      { phase: 'cep_action', label: 'Safe Browsing (CEP) flags domain reputation' },
      { phase: 'blocked',    label: 'URL Filter policy blocks navigation entirely' },
      { phase: 'resolved',   label: 'Threat logged; admin alerted via CEP reporting' }
    ],
    withCEP: 'Navigation blocked before page loaded. Zero credential exposure.',
    withoutCEP: 'User credential theft successful — no policy enforcement active.'
  },
  {
    id: 'injection', icon: '💉', name: 'Indirect Prompt Injection', desc: 'Hidden DOM instructions hijack an AI assistant',
    steps: [
      { phase: 'threat',     label: 'Attacker embeds hidden text: "Ignore previous instructions…"' },
      { phase: 'threat',     label: 'AI Copilot reads page content including hidden elements' },
      { phase: 'detected',   label: 'PromptArmor scans DOM — role override matched' },
      { phase: 'blocked',    label: 'Malicious content stripped before reaching AI model' },
      { phase: 'cep_action', label: 'Domain added to CEP threat blocklist automatically' }
    ],
    withCEP: 'Injected content removed. AI receives sanitised text only. No data exposure.',
    withoutCEP: 'AI follows injected instructions — sensitive data exfiltrated to attacker.'
  },
  {
    id: 'extension', icon: '🧩', name: 'Malicious Extension', desc: 'Trojanised extension silently harvests user data',
    steps: [
      { phase: 'threat',     label: 'User installs "helpful" extension from unofficial source' },
      { phase: 'threat',     label: 'Extension requests broad host permissions silently' },
      { phase: 'detected',   label: 'Behavioral Engine flags suspicious background network calls' },
      { phase: 'detected',   label: 'PromptArmor scores extension: CRITICAL (85/100)' },
      { phase: 'cep_action', label: 'CEP extension blocklist policy prevents install' },
      { phase: 'blocked',    label: 'Extension quarantined, user notified' }
    ],
    withCEP: 'Extension blocked at install by policy. No data exposure.',
    withoutCEP: 'Extension runs unchecked — clipboard, passwords, and browsing history stolen.'
  },
  {
    id: 'exfil', icon: '📤', name: 'AI Data Exfiltration', desc: 'Confidential doc pasted into unsanctioned AI tool',
    steps: [
      { phase: 'threat',     label: 'User pastes confidential document into unsanctioned AI tool' },
      { phase: 'detected',   label: 'PII Redactor detects SSN, card numbers in clipboard' },
      { phase: 'detected',   label: 'AI Governance classifies site as unsanctioned' },
      { phase: 'blocked',    label: 'Submission blocked — data redacted before send' },
      { phase: 'cep_action', label: 'DLP policy triggers — incident created in CEP console' },
      { phase: 'resolved',   label: 'Admin receives real-time alert with full context' }
    ],
    withCEP: 'PII redacted, submission blocked. DLP enforced. Incident logged.',
    withoutCEP: 'Full document content sent to external AI. Compliance violation. Likely breach.'
  },
  {
    id: 'jailbreak', icon: '🔓', name: 'LLM Jailbreak Attempt', desc: 'Prompt attempts to bypass AI safety guardrails',
    steps: [
      { phase: 'threat',     label: 'Jailbreak prompt submitted: "DAN mode activated…"' },
      { phase: 'detected',   label: 'Injection Firewall scans prompt in real-time' },
      { phase: 'detected',   label: '6 jailbreak patterns matched (boundary + role manipulation)' },
      { phase: 'blocked',    label: 'Prompt blocked before reaching LLM provider' },
      { phase: 'cep_action', label: 'Risky AI usage flagged in CEP audit log' },
      { phase: 'resolved',   label: 'User redirected to acceptable use policy page' }
    ],
    withCEP: 'Prompt blocked at firewall layer. AI never receives the request.',
    withoutCEP: 'Jailbreak succeeds — AI generates harmful / restricted content.'
  }
];

let simRunning = false;

function renderScenarios() {
  if (document.getElementById('scenarioList').children.length > 0) return;
  document.getElementById('scenarioList').innerHTML = SCENARIOS.map(s => `
    <div class="scenario-card" data-id="${s.id}">
      <div class="scenario-icon">${s.icon}</div>
      <div class="scenario-name">${h(s.name)}</div>
      <div class="scenario-desc">${h(s.desc)}</div>
    </div>`).join('');

  document.querySelectorAll('.scenario-card').forEach(card => {
    card.addEventListener('click', () => { if (!simRunning) runSim(card.dataset.id); });
  });
}

async function runSim(scenarioId) {
  const scenario = SCENARIOS.find(s => s.id === scenarioId);
  if (!scenario) return;
  simRunning = true;
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.toggle('running', c.dataset.id === scenarioId));

  const runningEl = document.getElementById('simRunning');
  const outcomeEl = document.getElementById('simOutcome');
  runningEl.style.display = 'block';
  outcomeEl.style.display = 'none';
  document.getElementById('simTitle').textContent  = scenario.icon + ' ' + scenario.name;
  document.getElementById('simStatus').textContent = 'Running';
  document.getElementById('simStatus').className   = 'badge badge-info';

  const stepsEl = document.getElementById('simSteps');
  stepsEl.innerHTML = scenario.steps.map((s, i) => `
    <div class="sim-step" id="simStep-${i}">
      <div class="step-dot ${s.phase}"></div>
      <span>${h(s.label)}</span>
    </div>`).join('');

  for (let i = 0; i < scenario.steps.length; i++) {
    await delay(700);
    document.getElementById('simStep-' + i).classList.add('active');
  }

  await delay(500);
  document.getElementById('simStatus').textContent     = 'Complete';
  document.getElementById('simStatus').className       = 'badge badge-safe';
  document.getElementById('simWithCEP').textContent    = scenario.withCEP;
  document.getElementById('simWithoutCEP').textContent = scenario.withoutCEP;
  outcomeEl.style.display = 'block';
  simRunning = false;
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('running'));
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

//=============================================================================
// ⑦ SETTINGS VIEW (unchanged)
//=============================================================================
async function loadSettingsView() {
  const stored = await chrome.storage.local.get(['aiConfig']);
  const config = stored.aiConfig || { provider: 'gemini-nano', geminiApiKey: '', ollamaEndpoint: 'http://localhost:11434', gemmaModel: 'gemma2:2b' };

  document.querySelectorAll('.provider-card').forEach(card => {
    card.classList.toggle('selected', card.dataset.provider === config.provider);
  });
  document.getElementById('apiSettings').style.display    = config.provider === 'gemini-api'   ? 'block' : 'none';
  document.getElementById('ollamaSettings').style.display = config.provider === 'gemma-ollama' ? 'block' : 'none';
  if (config.geminiApiKey) document.getElementById('geminiApiKey').value = config.geminiApiKey;
  document.getElementById('ollamaEndpoint').value = config.ollamaEndpoint || 'http://localhost:11434';
  document.getElementById('gemmaModel').value     = config.gemmaModel     || 'gemma2:2b';

  checkNanoStatus();
  if (config.geminiApiKey) {
    document.getElementById('apiStatus').textContent = 'Configured';
    document.getElementById('apiStatus').className   = 'provider-pill pill-ready';
  }
  checkOllamaStatus(config.ollamaEndpoint || 'http://localhost:11434');
}

async function checkNanoStatus() {
  try {
    if (typeof window.ai?.languageModel !== 'undefined') {
      const caps  = await window.ai.languageModel.capabilities();
      const ready = caps.available === 'readily';
      document.getElementById('nanoStatus').textContent = ready ? 'Ready' : 'Not Available';
      document.getElementById('nanoStatus').className   = 'provider-pill ' + (ready ? 'pill-ready' : 'pill-off');
      return;
    }
  } catch (_) {}
  document.getElementById('nanoStatus').textContent = 'Not Available';
  document.getElementById('nanoStatus').className   = 'provider-pill pill-off';
}

async function checkOllamaStatus(endpoint) {
  try {
    const res = await fetch(`${endpoint}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data    = await res.json();
      const hasGemma = (data.models || []).some(m => m.name.includes('gemma'));
      document.getElementById('ollamaStatus').textContent = hasGemma ? 'Ready' : 'No Gemma Model';
      document.getElementById('ollamaStatus').className   = 'provider-pill ' + (hasGemma ? 'pill-ready' : 'pill-setup');
      return;
    }
  } catch (_) {}
  document.getElementById('ollamaStatus').textContent = 'Offline';
  document.getElementById('ollamaStatus').className   = 'provider-pill pill-off';
}

document.querySelectorAll('.provider-card').forEach(card => {
  card.addEventListener('click', async () => {
    const stored = await chrome.storage.local.get(['aiConfig']);
    const config = stored.aiConfig || {};
    config.provider = card.dataset.provider;
    await chrome.storage.local.set({ aiConfig: config });
    loadSettingsView();
  });
});

document.getElementById('saveApiKey').addEventListener('click', async () => {
  const key      = document.getElementById('geminiApiKey').value.trim();
  const statusEl = document.getElementById('apiKeyStatus');
  if (!key) { statusEl.textContent = 'Enter an API key'; statusEl.className = 'form-hint status-err'; return; }
  statusEl.textContent = 'Verifying…'; statusEl.className = 'form-hint';
  try {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const stored = await chrome.storage.local.get(['aiConfig']); const config = stored.aiConfig || {};
      config.geminiApiKey = key;
      await chrome.storage.local.set({ aiConfig: config });
      statusEl.textContent = '✓ Verified and saved!'; statusEl.className = 'form-hint status-ok';
      document.getElementById('apiStatus').textContent = 'Configured';
      document.getElementById('apiStatus').className   = 'provider-pill pill-ready';
    } else {
      statusEl.textContent = '✗ Invalid API key'; statusEl.className = 'form-hint status-err';
    }
  } catch (_) {
    statusEl.textContent = '✗ Network error'; statusEl.className = 'form-hint status-err';
  }
});

document.getElementById('saveOllama').addEventListener('click', async () => {
  const endpoint = document.getElementById('ollamaEndpoint').value.trim();
  const model    = document.getElementById('gemmaModel').value;
  const statusEl = document.getElementById('ollamaStatus2');
  statusEl.textContent = 'Testing…'; statusEl.className = 'form-hint';
  try {
    const res = await fetch(`${endpoint}/api/tags`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const stored = await chrome.storage.local.get(['aiConfig']); const config = stored.aiConfig || {};
      config.ollamaEndpoint = endpoint; config.gemmaModel = model;
      await chrome.storage.local.set({ aiConfig: config });
      const data  = await res.json();
      const count = (data.models || []).length;
      statusEl.textContent = `✓ Connected · ${count} models available`; statusEl.className = 'form-hint status-ok';
      checkOllamaStatus(endpoint);
    } else {
      statusEl.textContent = '✗ Ollama not reachable'; statusEl.className = 'form-hint status-err';
    }
  } catch (_) {
    statusEl.textContent = '✗ Cannot connect to Ollama'; statusEl.className = 'form-hint status-err';
  }
});

bindToggle('aiToggle',       'aiEnabled');
bindToggle('detailedToggle', 'detailedReports');

//=============================================================================
// INIT
//=============================================================================
document.addEventListener('DOMContentLoaded', () => {
  loadPostureView();
  chrome.storage.local.get([
    'hiddenScan','firewallEnabled','sanitizeEnabled','autoRedact',
    'blockUnsanctioned','dlpEnabled','aiEnabled','detailedReports'
  ], result => {
    if (result.hiddenScan        !== false) setToggle('hiddenScanToggle',        true);
    if (result.firewallEnabled   !== false) setToggle('firewallToggle',           true);
    if (result.sanitizeEnabled   !== false) setToggle('sanitizeToggle',           true);
    if (result.autoRedact        !== false) setToggle('autoRedactToggle',         true);
    if (result.blockUnsanctioned !== false) setToggle('blockUnsanctionedToggle',  true);
    if (result.dlpEnabled        !== false) setToggle('dlpToggle',                true);
    if (result.aiEnabled         !== false) setToggle('aiToggle',                 true);
    if (result.detailedReports)             setToggle('detailedToggle',           true);
  });
});

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'PROMPTARMOR_UPDATE') {
    const activeView = document.querySelector('.nav-item.active')?.dataset.view;
    if (activeView === 'posture')    loadPostureView();
    if (activeView === 'threats')    loadThreatsView();
    if (activeView === 'governance') loadGovernanceView();
  }
});

chrome.tabs.onActivated.addListener(() => {
  const active = document.querySelector('.nav-item.active')?.dataset.view;
  if (active === 'posture')    loadPostureView();
  if (active === 'threats')    loadThreatsView();
  if (active === 'governance') loadGovernanceView();
});