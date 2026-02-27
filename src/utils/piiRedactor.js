// PromptArmor - Enhanced PII/Secret Redaction
// Uses Gemini's contextual understanding to identify sensitive data

/**
 * Standard regex patterns for common PII
 */
const STANDARD_PATTERNS = {
  email: {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    placeholder: '[EMAIL]'
  },
  ssn: {
    regex: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
    placeholder: '[SSN]'
  },
  creditCard: {
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    placeholder: '[CREDIT_CARD]'
  },
  phone: {
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    placeholder: '[PHONE]'
  },
  ipv4: {
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    placeholder: '[IP_ADDRESS]'
  },
  ipv6: {
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    placeholder: '[IP_ADDRESS]'
  }
};

/**
 * Secret/credential patterns
 */
const SECRET_PATTERNS = {
  awsKey: {
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    placeholder: '[AWS_KEY]'
  },
  awsSecret: {
    regex: /\b[A-Za-z0-9/+=]{40}\b/g,
    placeholder: '[AWS_SECRET]',
    contextRequired: ['aws', 'secret', 'key']
  },
  githubToken: {
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
    placeholder: '[GITHUB_TOKEN]'
  },
  slackToken: {
    regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    placeholder: '[SLACK_TOKEN]'
  },
  genericApiKey: {
    regex: /\b(api[_-]?key|apikey|api[_-]?secret)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})/gi,
    placeholder: '[API_KEY]'
  },
  bearerToken: {
    regex: /\bBearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/gi,
    placeholder: '[BEARER_TOKEN]'
  },
  jwtToken: {
    regex: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    placeholder: '[JWT_TOKEN]'
  },
  privateKey: {
    regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
    placeholder: '[PRIVATE_KEY]'
  },
  connectionString: {
    regex: /\b(mongodb|postgresql|mysql|redis):\/\/[^\s'",]+/gi,
    placeholder: '[CONNECTION_STRING]'
  },
  password: {
    regex: /\b(password|passwd|pwd)['":\s]*[=:]\s*['"]?([^\s'"]{6,})/gi,
    placeholder: '[PASSWORD]'
  }
};

/**
 * Apply standard regex-based redaction
 */
function applyRegexRedaction(text) {
  if (!text) return { text: '', redactions: [] };
  
  let result = String(text);
  const redactions = [];
  
  // Apply standard patterns
  for (const [type, config] of Object.entries(STANDARD_PATTERNS)) {
    const matches = result.match(config.regex);
    if (matches) {
      redactions.push({ type, count: matches.length });
      result = result.replace(config.regex, config.placeholder);
    }
  }
  
  // Apply secret patterns
  for (const [type, config] of Object.entries(SECRET_PATTERNS)) {
    const matches = result.match(config.regex);
    if (matches) {
      redactions.push({ type, count: matches.length, severity: 'high' });
      result = result.replace(config.regex, config.placeholder);
    }
  }
  
  return { text: result, redactions };
}

/**
 * Use Gemini Nano to identify contextual PII that regex misses
 */
async function identifyContextualPII(text) {
  if (!text || text.length < 10) return [];
  
  const prompt = `Identify any sensitive personal information in this text that should be redacted.
Look for: names, addresses, dates of birth, account numbers, medical info, financial details.
Do NOT flag generic words - only actual PII.

Text: "${text.substring(0, 3000)}"

List each PII found as: TYPE: "exact text"
If none found, respond: NONE`;

  try {
    if (typeof window !== 'undefined' && window.ai?.languageModel) {
      const session = await window.ai.languageModel.create();
      const response = await session.prompt(prompt);
      session.destroy();
      
      // Parse AI response for PII matches
      const findings = [];
      const lines = response.split('\n');
      for (const line of lines) {
        const match = line.match(/(\w+):\s*"([^"]+)"/);
        if (match) {
          findings.push({ type: match[1], value: match[2] });
        }
      }
      return findings;
    }
  } catch (e) {
    console.error('AI PII detection failed:', e);
  }
  
  return [];
}

/**
 * Full PII redaction pipeline
 */
async function redactAllPII(text, useAI = true) {
  // Step 1: Apply regex patterns
  const { text: regexRedacted, redactions } = applyRegexRedaction(text);
  
  // Step 2: Use AI for contextual detection (if enabled)
  if (useAI) {
    const contextualPII = await identifyContextualPII(regexRedacted);
    
    let finalText = regexRedacted;
    for (const pii of contextualPII) {
      if (pii.value && pii.value.length > 2) {
        finalText = finalText.replace(
          new RegExp(escapeRegex(pii.value), 'gi'),
          `[${pii.type.toUpperCase()}]`
        );
        redactions.push({ type: pii.type, count: 1, source: 'ai' });
      }
    }
    
    return { text: finalText, redactions };
  }
  
  return { text: regexRedacted, redactions };
}

/**
 * Escape special regex characters
 */
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Quick check if text likely contains secrets
 */
function containsSecrets(text) {
  if (!text) return false;
  
  for (const config of Object.values(SECRET_PATTERNS)) {
    if (config.regex.test(text)) {
      config.regex.lastIndex = 0; // Reset regex state
      return true;
    }
  }
  return false;
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    applyRegexRedaction,
    identifyContextualPII,
    redactAllPII,
    containsSecrets,
    STANDARD_PATTERNS,
    SECRET_PATTERNS
  };
}
