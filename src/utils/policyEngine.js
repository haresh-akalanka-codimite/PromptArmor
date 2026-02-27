// PromptArmor - Adaptive Policy Recommendation Engine
// Continuously evaluates risk trends and suggests CEP policy changes

const POLICY_TYPES = {
  EXTENSION_BLOCK:    'extension_block',
  EXTENSION_RESTRICT: 'extension_restrict',
  URL_BLOCK:          'url_block',
  AI_DOMAIN_RULE:     'ai_domain_rule',
  PERMISSION_HARDEN:  'permission_harden',
  DEPT_POLICY:        'dept_policy'
};

const PRIORITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

/**
 * Analyze collected state data and generate policy recommendations
 */
function generateRecommendations(state = {}) {
  const recs = [];
  const extensions     = state.extensions     || [];
  const departments    = state.departments    || [];
  const aiUsage        = state.aiUsage        || {};
  const injectionStats = state.injectionStats || {};
  const trends         = state.trends         || {};

  // ── Extensions ────────────────────────────────────────────────────────────
  const criticalExts = extensions.filter(e => e.score >= 50);
  const highRiskExts = extensions.filter(e => e.score >= 30 && e.score < 50);

  criticalExts.forEach(ext => {
    recs.push({
      id: `ext-block-${ext.id}`,
      type: POLICY_TYPES.EXTENSION_BLOCK,
      priority: PRIORITY.CRITICAL,
      title: `Block extension: ${ext.name}`,
      description: `Risk score ${ext.score}/100. Permissions include high-risk capabilities.`,
      impact: 'Prevents data exfil, surveillance, and network interception.',
      cepPolicy: { ExtensionInstallBlocklist: [ext.id] },
      cepRequired: true,
      canSimulate: true
    });
  });

  highRiskExts.forEach(ext => {
    recs.push({
      id: `ext-restrict-${ext.id}`,
      type: POLICY_TYPES.EXTENSION_RESTRICT,
      priority: PRIORITY.HIGH,
      title: `Restrict extension: ${ext.name}`,
      description: `Risk score ${ext.score}/100. Consider allowlisting only for specific departments.`,
      impact: 'Reduces attack surface without blocking productivity.',
      cepPolicy: { ExtensionSettings: { [ext.id]: { installation_mode: 'force_installed_and_supervised' } } },
      cepRequired: true,
      canSimulate: true
    });
  });

  // ── Department anomalies ──────────────────────────────────────────────────
  departments.forEach(dept => {
    if (dept.highRiskExtensionRate > 0.3) {
      recs.push({
        id: `dept-ext-${dept.name}`,
        type: POLICY_TYPES.DEPT_POLICY,
        priority: PRIORITY.HIGH,
        title: `Tighten extension policy for ${dept.name}`,
        description: `${(dept.highRiskExtensionRate * 100).toFixed(0)}% of users have high-risk extensions — ${dept.anomalyRatio}x org average.`,
        impact: 'Reduces department-level risk vector.',
        cepPolicy: { dept: dept.name, action: 'harden_extension_policy' },
        cepRequired: true,
        canSimulate: true
      });
    }

    if (dept.aiUsageRiskScore > 70) {
      recs.push({
        id: `dept-ai-${dept.name}`,
        type: POLICY_TYPES.AI_DOMAIN_RULE,
        priority: PRIORITY.MEDIUM,
        title: `Restrict AI tool access for ${dept.name}`,
        description: `High-risk AI usage pattern detected. Unsanctioned tools in use.`,
        impact: 'Prevents shadow AI / data leakage.',
        cepPolicy: { dept: dept.name, action: 'apply_ai_allowlist' },
        cepRequired: true,
        canSimulate: true
      });
    }
  });

  // ── Injection trends ──────────────────────────────────────────────────────
  if ((injectionStats.weekly || 0) > 5) {
    recs.push({
      id: 'url-block-injection-domains',
      type: POLICY_TYPES.URL_BLOCK,
      priority: PRIORITY.HIGH,
      title: `Block ${injectionStats.topDomains?.length || 'unknown'} injection-source domains`,
      description: `${injectionStats.weekly} injection attempts this week from known domains.`,
      impact: 'Stops repeated injection vectors at the network level.',
      cepPolicy: { URLBlocklist: injectionStats.topDomains || [] },
      cepRequired: true,
      canSimulate: false
    });
  }

  // ── Permission hardening ──────────────────────────────────────────────────
  if ((trends.permissionEscalation || 0) > 2) {
    recs.push({
      id: 'permission-harden-global',
      type: POLICY_TYPES.PERMISSION_HARDEN,
      priority: PRIORITY.MEDIUM,
      title: 'Harden extension permission grants',
      description: `${trends.permissionEscalation} extensions recently gained new permissions.`,
      impact: 'Prevents silent permission escalation after install.',
      cepPolicy: { ExtensionManifestV2Availability: 'disable_for_new_installs' },
      cepRequired: true,
      canSimulate: false
    });
  }

  // ── AI governance ─────────────────────────────────────────────────────────
  const sanctionedDomains = aiUsage.sanctionedDomains || [];
  const unsanctioned = (aiUsage.detectedDomains || []).filter(d => !sanctionedDomains.includes(d));
  if (unsanctioned.length > 0) {
    recs.push({
      id: 'ai-domain-allowlist',
      type: POLICY_TYPES.AI_DOMAIN_RULE,
      priority: PRIORITY.HIGH,
      title: `Create AI domain allowlist (${unsanctioned.length} unsanctioned)`,
      description: `Detected: ${unsanctioned.slice(0, 3).join(', ')}${unsanctioned.length > 3 ? '...' : ''}`,
      impact: 'Enforces approved AI tool usage only.',
      cepPolicy: { URLAllowlist: sanctionedDomains, URLBlocklist: unsanctioned },
      cepRequired: true,
      canSimulate: true
    });
  }

  return recs.sort((a, b) => priorityRank(a.priority) - priorityRank(b.priority));
}

function priorityRank(p) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[p] ?? 4;
}

/**
 * Simulate the impact of applying a recommendation
 */
function simulateImpact(recommendation, currentState) {
  const before = currentState.postureScore || 70;
  let delta = 0;

  switch (recommendation.type) {
    case POLICY_TYPES.EXTENSION_BLOCK:    delta = 15; break;
    case POLICY_TYPES.EXTENSION_RESTRICT: delta = 8;  break;
    case POLICY_TYPES.URL_BLOCK:          delta = 10; break;
    case POLICY_TYPES.AI_DOMAIN_RULE:     delta = 7;  break;
    case POLICY_TYPES.PERMISSION_HARDEN:  delta = 5;  break;
    case POLICY_TYPES.DEPT_POLICY:        delta = 6;  break;
    default:                              delta = 3;
  }

  return {
    scoreBefore: before,
    scoreAfter: Math.min(100, before + delta),
    delta,
    affectedUsers: currentState.totalUsers || 0,
    rollbackAvailable: true,
    estimatedApplyTime: '< 2 minutes via CEP'
  };
}

/**
 * Apply a recommendation (writes to storage for background to act on)
 */
async function applyRecommendation(recommendation) {
  const applied = await chrome.storage.local.get(['appliedPolicies']);
  const list = applied.appliedPolicies || [];

  list.push({
    ...recommendation,
    appliedAt: Date.now(),
    status: 'pending_cep_sync'
  });

  await chrome.storage.local.set({ appliedPolicies: list });

  return { success: true, message: 'Queued for CEP sync. Changes will apply within 2 minutes.' };
}

/**
 * Rollback a previously applied recommendation
 */
async function rollbackRecommendation(recommendationId) {
  const stored = await chrome.storage.local.get(['appliedPolicies']);
  const list = (stored.appliedPolicies || []).filter(p => p.id !== recommendationId);
  await chrome.storage.local.set({ appliedPolicies: list });
  return { success: true, message: 'Policy rolled back.' };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateRecommendations,
    simulateImpact,
    applyRecommendation,
    rollbackRecommendation,
    POLICY_TYPES,
    PRIORITY
  };
}
