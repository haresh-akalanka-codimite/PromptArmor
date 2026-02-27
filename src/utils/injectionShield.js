// PromptArmor - Enhanced Injection & Context Manipulation Shield
// Detects hidden instructions, DOM manipulation, obfuscated scripts, AI redirection

const THREAT_CLASSES = {
  HIDDEN_INSTRUCTION:   'hidden_instruction',
  DOM_MANIPULATION:     'dom_manipulation',
  AI_REDIRECTION:       'ai_redirection',
  OBFUSCATED_SCRIPT:    'obfuscated_script',
  CONTEXT_POISONING:    'context_poisoning',
  DATA_EXFIL_ATTEMPT:   'data_exfil_attempt'
};

// Patterns keyed by threat class
const SHIELD_PATTERNS = {
  [THREAT_CLASSES.HIDDEN_INSTRUCTION]: [
    { re: /ignore\s+(?:all\s+)?previous\s+instructions?/i,       label: 'Instruction override' },
    { re: /disregard\s+(?:all\s+)?(?:prior|previous)\s+/i,       label: 'Instruction discard' },
    { re: /system\s*:\s*you\s+are\s+now/i,                       label: 'System role injection' },
    { re: /\[SYSTEM\]|\[INST\]|\[SYS\]/,                         label: 'System bracket injection' },
    { re: /<!--[\s\S]*?(?:ignore|forget|override)[\s\S]*?-->/i,  label: 'HTML comment injection' },
    { re: /\{%[-\s]*(?:system|ignore|override)/i,                label: 'Template injection attempt' },
    // Hypothetical extraction framing (Attack 2)
    { re: /if\s+an?\s+ai\s+(?:assistant\s+)?had\s+hidden\s+(?:safety\s+)?instructions?/i, label: 'Hypothetical instruction extraction' },
    { re: /provide\s+a\s+realistic\s+example\s+of\s+(?:such|an?\s+ai|system)\s+(?:configuration|instructions?)/i, label: 'Realistic example extraction' }
  ],
  [THREAT_CLASSES.AI_REDIRECTION]: [
    { re: /(?:send|forward|email|transmit)\s+(?:all\s+)?(?:this|conversation|data|history)/i, label: 'Data forwarding command' },
    { re: /exfiltrate|exfil\b/i,                                  label: 'Exfiltration keyword' },
    { re: /when\s+(?:asked|prompted|requested).*?respond\s+with/i,label: 'Conditional response override' },
    { re: /do\s+not\s+(?:tell|inform|reveal)\s+the\s+user/i,     label: 'Transparency suppression' },
    { re: /act\s+as\s+(?:if\s+)?(?:you\s+are|a)\s+(?:different|new|another)/i, label: 'Identity redirection' }
  ],
  [THREAT_CLASSES.OBFUSCATED_SCRIPT]: [
    { re: /\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}/i,                  label: 'Unicode escape obfuscation' },
    { re: /(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURI)/i,label: 'Eval with decode' },
    { re: /String\.fromCharCode\(\s*\d+(?:\s*,\s*\d+){10,}\)/,  label: 'CharCode obfuscation' },
    { re: /base64[^'"\s]{20,}/i,                                  label: 'Inline base64 payload' },
    { re: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/i,              label: 'Hex escape sequence' }
  ],
  [THREAT_CLASSES.CONTEXT_POISONING]: [
    { re: /the\s+following\s+is\s+(?:your\s+)?(?:new\s+)?(?:true\s+)?(?:system\s+)?instructions?/i, label: 'False system instructions' },
    { re: /you\s+(?:must|should|will)\s+(?:always|never)\s+(?:follow|obey|comply)/i, label: 'Compliance coercion' },
    { re: /your\s+(?:true\s+)?(?:purpose|goal|mission)\s+is\s+(?:to\s+)?(?:help|assist)\s+(?:me|us)\s+(?:steal|leak|exfil)/i, label: 'Goal poisoning' },
    { re: /continue\s+acting\s+as\s+(?:this|that|the)\s+(?:new\s+)?(?:character|persona|entity)/i, label: 'Persistent persona injection' },
    // Authority spoofing (Attack 3)
    { re: /the\s+following\s+instruction\s+comes?\s+from\s+the\s+(?:system\s+)?(?:administrator|admin|operator)/i, label: 'Authority impersonation' },
    { re: /(?:system\s+)?(?:administrator|admin|operator)\s*:\s*(?:reveal|show|provide|share|output)/i, label: 'Admin command spoofing' },
    { re: /for\s+(?:audit|compliance|security)\s+purposes?\s*,?\s*(?:reveal|show|provide|share|output)/i, label: 'Audit pretext extraction' },
    // Policy reframing (Attack 5)
    { re: /reinterpret\s+(?:your|the)\s+(?:safety|security|content)\s+(?:policies?|guidelines?|rules?)/i, label: 'Safety policy reframing' },
    { re: /transparency\s+(?:requires?|means?|demands?)\s+(?:sharing|revealing|disclosing)\s+internal/i, label: 'Transparency pretext injection' },
    { re: /(?:safety|security)\s+(?:policies?|guidelines?)\s+as\s+transparency\s+(?:policies?|guidelines?)/i, label: 'Policy equivalence manipulation' }
  ],
  [THREAT_CLASSES.DATA_EXFIL_ATTEMPT]: [
    { re: /https?:\/\/[^\s"'<>]*?(?:webhook|exfil|collect|track|log)\.[^\s"'<>]{3,}/i, label: 'Exfil webhook URL' },
    { re: /fetch\s*\(\s*['"][^'"]*(?:attacker|evil|malicious)[^'"]*['"]/i, label: 'Malicious fetch call' },
    { re: /new\s+Image\s*\(\s*\)[\s\S]{0,50}\.src\s*=/i,        label: 'Image beacon exfil' },
    { re: /navigator\.sendBeacon\s*\(/i,                          label: 'sendBeacon exfiltration' }
  ]
};

/**
 * Classify a single finding's risk level
 */
function classifyRisk(threatClass, matchCount) {
  const classRisk = {
    [THREAT_CLASSES.HIDDEN_INSTRUCTION]:  3,
    [THREAT_CLASSES.AI_REDIRECTION]:      3,
    [THREAT_CLASSES.OBFUSCATED_SCRIPT]:   2,
    [THREAT_CLASSES.CONTEXT_POISONING]:   3,
    [THREAT_CLASSES.DATA_EXFIL_ATTEMPT]:  3,
    [THREAT_CLASSES.DOM_MANIPULATION]:    2
  };
  const baseRisk = (classRisk[threatClass] || 1) * matchCount;
  if (baseRisk >= 6) return 'critical';
  if (baseRisk >= 3) return 'high';
  if (baseRisk >= 1) return 'medium';
  return 'low';
}

/**
 * Scan a block of text for all injection/manipulation patterns
 */
function shieldScan(text) {
  if (!text || typeof text !== 'string') {
    return { clean: true, threats: [], score: 0, maliciousProbability: 0 };
  }

  const threats = [];

  for (const [threatClass, patterns] of Object.entries(SHIELD_PATTERNS)) {
    for (const { re, label } of patterns) {
      const matches = text.match(re);
      if (matches) {
        threats.push({
          class: threatClass,
          label,
          sample: matches[0].substring(0, 120),
          severity: classifyRisk(threatClass, 1)
        });
      }
    }
  }

  // Detect hidden text heuristics (zero-width chars, tiny font tags)
  if (/[\u200b\u200c\u200d\ufeff]/.test(text)) {
    threats.push({
      class: THREAT_CLASSES.HIDDEN_INSTRUCTION,
      label: 'Zero-width character steganography',
      sample: '[zero-width characters detected]',
      severity: 'high'
    });
  }

  const score = Math.min(100, threats.reduce((sum, t) => {
    return sum + ({ critical: 40, high: 20, medium: 10, low: 5 }[t.severity] || 0);
  }, 0));

  return {
    clean: threats.length === 0,
    threats,
    score,
    maliciousProbability: score / 100,
    threatClasses: [...new Set(threats.map(t => t.class))]
  };
}

/**
 * Deep DOM scan — checks hidden elements, comments, data-* attributes, inline styles
 */
function domShieldScan(domDocument) {
  if (!domDocument) return shieldScan('');

  const parts = [];

  // Comments
  const iter = domDocument.createTreeWalker(domDocument.body, 0x80 /* NodeFilter.SHOW_COMMENT */);
  let node;
  while ((node = iter.nextNode())) parts.push(node.nodeValue);

  // Hidden elements
  domDocument.querySelectorAll('[style*="display:none"],[style*="display: none"],[hidden]').forEach(el => {
    parts.push(el.textContent);
  });

  // data-* attributes that may carry instructions
  domDocument.querySelectorAll('[data-prompt],[data-instruction],[data-system]').forEach(el => {
    parts.push(el.dataset.prompt || el.dataset.instruction || el.dataset.system);
  });

  // Tiny / invisible text (font-size: 0)
  domDocument.querySelectorAll('[style*="font-size:0"],[style*="font-size: 0"],[style*="color:transparent"]').forEach(el => {
    parts.push(el.textContent);
  });

  return shieldScan(parts.join(' '));
}

/**
 * Calculate overall Malicious Intent Probability and exposure level
 */
function assessExposure(scanResult) {
  const { threats, score } = scanResult;

  const dataExfilThreats = threats.filter(t => t.class === THREAT_CLASSES.DATA_EXFIL_ATTEMPT);
  const redirectionThreats = threats.filter(t => t.class === THREAT_CLASSES.AI_REDIRECTION);

  return {
    maliciousIntentProbability: score / 100,
    dataExposureRisk:           dataExfilThreats.length > 0 ? 'high' : score > 30 ? 'medium' : 'low',
    executionRisk:              score >= 60 ? 'high' : score >= 20 ? 'medium' : 'low',
    aiRedirectionRisk:          redirectionThreats.length > 0 ? 'high' : 'low',
    recommendedAction:          score >= 60 ? 'block'
                                            : score >= 20 ? 'sanitize'
                                            : 'allow'
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    shieldScan,
    domShieldScan,
    assessExposure,
    classifyRisk,
    THREAT_CLASSES,
    SHIELD_PATTERNS
  };
}
