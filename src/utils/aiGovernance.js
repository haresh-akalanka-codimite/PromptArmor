// PromptArmor - AI Usage Governance Layer
// Monitors AI tool usage, detects shadow AI, enforces data governance

const AI_RISK_CATEGORIES = {
  SANCTIONED:      'sanctioned',
  CONDITIONALLY_APPROVED: 'conditional',
  UNSANCTIONED:    'unsanctioned',
  PROHIBITED:      'prohibited'
};

// Default sanctioned AI domains (org-configurable)
const DEFAULT_SANCTIONED_DOMAINS = [
  'copilot.microsoft.com',
  'bing.com',
  'github.com/copilot',
  'gemini.google.com',
  'workspace.google.com'
];

// Known AI tools by domain
const KNOWN_AI_DOMAINS = {
  // Sanctioned by default
  'copilot.microsoft.com':  { name: 'Microsoft Copilot',  risk: 'low',    sanctioned: true },
  'bing.com':               { name: 'Bing AI',             risk: 'low',    sanctioned: true },
  'gemini.google.com':      { name: 'Google Gemini',       risk: 'low',    sanctioned: true },
  // Conditional
  'chat.openai.com':        { name: 'ChatGPT',             risk: 'medium', sanctioned: false },
  'openai.com':             { name: 'OpenAI',               risk: 'medium', sanctioned: false },
  'claude.ai':              { name: 'Claude',               risk: 'medium', sanctioned: false },
  'anthropic.com':          { name: 'Anthropic',            risk: 'medium', sanctioned: false },
  // Often unsanctioned
  'perplexity.ai':          { name: 'Perplexity',           risk: 'medium', sanctioned: false },
  'you.com':                { name: 'You.com',              risk: 'medium', sanctioned: false },
  'character.ai':           { name: 'Character.AI',         risk: 'high',   sanctioned: false },
  'huggingface.co':         { name: 'Hugging Face',         risk: 'medium', sanctioned: false },
  // Shadow AI / risky
  'janitorai.com':          { name: 'Janitor AI',           risk: 'high',   sanctioned: false },
  'poe.com':                { name: 'Poe (Quora AI)',       risk: 'medium', sanctioned: false }
};

// Prompt patterns indicating sensitive data submission
const SENSITIVE_PROMPT_PATTERNS = [
  { re: /\b(?:ssn|social\s*security)\b/i,                          label: 'SSN reference',          severity: 'critical' },
  { re: /\b(?:password|passwd|api[\s_-]?key|secret[\s_-]?key)\b/i, label: 'Credential data',        severity: 'critical' },
  { re: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/,                     label: 'SSN pattern',             severity: 'critical' },
  { re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/,       label: 'Credit card number',     severity: 'critical' },
  { re: /(?:confidential|internal\s*only|do\s*not\s*share)/i,      label: 'Confidential marker',    severity: 'high' },
  { re: /(?:patient|medical|diagnosis|prescription)/i,              label: 'Health data (HIPAA)',    severity: 'high' },
  { re: /(?:revenue|profit|acquisition|merger|M&A)/i,              label: 'Financial/M&A data',     severity: 'high' },
  { re: /(?:employee\s*id|payroll|salary|compensation)/i,           label: 'HR sensitive data',     severity: 'medium' },
  { re: /(?:source\s*code|proprietary|trade\s*secret)/i,           label: 'IP / source code',       severity: 'high' }
];

// Risky prompt patterns (jailbreak / policy evasion)
const RISKY_PROMPT_PATTERNS = [
  { re: /ignore.*(?:safety|policy|guidelines)/i,                    label: 'Safety bypass attempt',  severity: 'high' },
  { re: /in\s*(?:DAN|jailbreak|unrestricted)\s*mode/i,             label: 'Jailbreak mode request', severity: 'high' },
  { re: /pretend\s+(?:you\s+have\s+no\s+)?restrictions/i,          label: 'Restriction removal',    severity: 'medium' },
  { re: /write\s+(?:malware|virus|ransomware|exploit)/i,           label: 'Malware generation',      severity: 'critical' },
  { re: /(?:phish(?:ing)?|scam)\s+(?:email|template)/i,            label: 'Phishing content request',severity: 'critical' }
];

/**
 * Classify a domain's governance status
 */
function classifyDomain(domain, sanctionedList = DEFAULT_SANCTIONED_DOMAINS) {
  const known = KNOWN_AI_DOMAINS[domain];
  const isSanctioned = sanctionedList.includes(domain) || known?.sanctioned;

  if (!known) {
    // Unknown domains detected as AI via URL patterns get classified as unsanctioned
    const aiIndicators = ['chat', 'ai', 'gpt', 'llm', 'copilot', 'assistant', 'bot'];
    const likelyAI = aiIndicators.some(kw => domain.includes(kw));
    return {
      domain,
      name: domain,
      category: likelyAI ? AI_RISK_CATEGORIES.UNSANCTIONED : null,
      risk: likelyAI ? 'medium' : 'unknown',
      known: false
    };
  }

  return {
    domain,
    name: known.name,
    category: isSanctioned
      ? AI_RISK_CATEGORIES.SANCTIONED
      : known.risk === 'high'
        ? AI_RISK_CATEGORIES.PROHIBITED
        : AI_RISK_CATEGORIES.CONDITIONALLY_APPROVED,
    risk: known.risk,
    known: true
  };
}

/**
 * Scan a prompt/text submission for sensitive data
 */
function scanPromptSensitivity(text) {
  const findings = [];

  for (const { re, label, severity } of SENSITIVE_PROMPT_PATTERNS) {
    if (re.test(text)) {
      findings.push({ label, severity, type: 'sensitive_data' });
    }
  }

  for (const { re, label, severity } of RISKY_PROMPT_PATTERNS) {
    if (re.test(text)) {
      findings.push({ label, severity, type: 'policy_violation' });
    }
  }

  const maxSeverity = findings.some(f => f.severity === 'critical') ? 'critical'
                    : findings.some(f => f.severity === 'high')     ? 'high'
                    : findings.some(f => f.severity === 'medium')   ? 'medium'
                    : 'none';

  const sensitivityScore = Math.min(100, findings.reduce((s, f) => {
    return s + ({ critical: 40, high: 20, medium: 10, low: 5 }[f.severity] || 0);
  }, 0));

  return {
    findings,
    maxSeverity,
    sensitivityScore,
    shouldBlock: maxSeverity === 'critical',
    shouldRedact: ['critical', 'high'].includes(maxSeverity),
    dataTypes: findings.filter(f => f.type === 'sensitive_data').map(f => f.label)
  };
}

/**
 * Process a navigation/submission event through governance rules
 */
function governanceCheck(event) {
  const { domain, promptText, submissionType } = event;

  const domainResult = classifyDomain(domain);
  const promptResult = promptText ? scanPromptSensitivity(promptText) : null;

  const governed = domainResult.category !== null;
  const blocked = dominated(domainResult, promptResult);
  const requiresRedaction = promptResult?.shouldRedact || false;

  return {
    domain,
    domainClassification: domainResult,
    promptAnalysis: promptResult,
    governed,
    blocked,
    requiresRedaction,
    action: blocked ? 'block'
                    : requiresRedaction ? 'redact_and_allow'
                    : 'allow',
    auditEntry: {
      timestamp: Date.now(),
      domain,
      category: domainResult.category,
      sensitivityScore: promptResult?.sensitivityScore || 0,
      action: blocked ? 'blocked' : requiresRedaction ? 'redacted' : 'allowed'
    }
  };
}

function dominated(domainResult, promptResult) {
  if (domainResult.category === AI_RISK_CATEGORIES.PROHIBITED) return true;
  if (promptResult?.shouldBlock && domainResult.category !== AI_RISK_CATEGORIES.SANCTIONED) return true;
  return false;
}

/**
 * Aggregate governance statistics from audit log
 */
function buildGovernanceStats(auditLog = []) {
  const total               = auditLog.length;
  const blocked             = auditLog.filter(e => e.action === 'blocked').length;
  const redacted            = auditLog.filter(e => e.action === 'redacted').length;
  const unsanctionedTools   = new Set(
    auditLog.filter(e => e.category === AI_RISK_CATEGORIES.UNSANCTIONED).map(e => e.domain)
  ).size;
  const sensitiveSubmissions = auditLog.filter(e => (e.sensitivityScore || 0) >= 40).length;
  const topDomains          = topN(auditLog.map(e => e.domain), 5);

  return {
    total,
    blocked,
    redacted,
    unsanctionedTools,
    sensitiveSubmissions,
    topDomains,
    complianceRate: total > 0 ? +((1 - (blocked + redacted) / total) * 100).toFixed(1) : 100
  };
}

function topN(arr, n) {
  const counts = {};
  arr.forEach(v => { counts[v] = (counts[v] || 0) + 1; });
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([domain, count]) => ({ domain, count }));
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    classifyDomain,
    scanPromptSensitivity,
    governanceCheck,
    buildGovernanceStats,
    AI_RISK_CATEGORIES,
    KNOWN_AI_DOMAINS,
    DEFAULT_SANCTIONED_DOMAINS
  };
}
