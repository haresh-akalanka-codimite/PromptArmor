// PromptArmor - Extension Risk Scoring
// Analyzes installed extensions for high-risk behavior

/**
 * High-risk permission categories
 */
const RISK_PERMISSIONS = {
  critical: {
    permissions: ['debugger', 'proxy', 'vpnProvider', 'webRequest', 'webRequestBlocking'],
    weight: 30
  },
  high: {
    permissions: ['cookies', 'history', 'bookmarks', 'downloads', 'nativeMessaging', 'management'],
    weight: 20
  },
  medium: {
    permissions: ['tabs', 'storage', 'clipboardRead', 'clipboardWrite', 'geolocation'],
    weight: 10
  },
  low: {
    permissions: ['activeTab', 'notifications', 'contextMenus', 'alarms'],
    weight: 5
  }
};

/**
 * Suspicious code patterns in extensions
 */
const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/gi, risk: 25, name: 'eval() usage' },
  { pattern: /new\s+Function\s*\(/gi, risk: 25, name: 'Dynamic Function creation' },
  { pattern: /document\.write/gi, risk: 15, name: 'document.write' },
  { pattern: /innerHTML\s*=/gi, risk: 10, name: 'innerHTML assignment' },
  { pattern: /chrome\.webRequest\.onBeforeRequest/gi, risk: 20, name: 'Request interception' },
  { pattern: /XMLHttpRequest|fetch\s*\(/gi, risk: 5, name: 'Network requests' },
  { pattern: /btoa|atob/gi, risk: 10, name: 'Base64 encoding' },
  { pattern: /localStorage|sessionStorage/gi, risk: 5, name: 'Storage access' },
  { pattern: /\.execCommand/gi, risk: 15, name: 'execCommand usage' },
  { pattern: /window\.open/gi, risk: 10, name: 'Popup creation' },
  { pattern: /crypto\.subtle/gi, risk: 15, name: 'Crypto API usage' },
  { pattern: /password|passwd|secret|token|api.?key/gi, risk: 20, name: 'Credential handling' },
  { pattern: /webhook\.site|requestbin|ngrok/gi, risk: 30, name: 'Known exfil endpoints' }
];

/**
 * Calculate permission risk score for an extension
 */
function calculatePermissionRisk(permissions = [], hostPermissions = []) {
  let score = 0;
  const flaggedPermissions = [];

  // Check standard permissions
  for (const [level, config] of Object.entries(RISK_PERMISSIONS)) {
    for (const perm of config.permissions) {
      if (permissions.includes(perm)) {
        score += config.weight;
        flaggedPermissions.push({ permission: perm, level, weight: config.weight });
      }
    }
  }

  // Check host permissions
  if (hostPermissions.includes('<all_urls>') || hostPermissions.includes('*://*/*')) {
    score += 25;
    flaggedPermissions.push({ permission: '<all_urls>', level: 'critical', weight: 25 });
  } else if (hostPermissions.length > 10) {
    score += 15;
    flaggedPermissions.push({ permission: `${hostPermissions.length} hosts`, level: 'high', weight: 15 });
  }

  return { score, flaggedPermissions };
}

/**
 * Analyze extension source code for suspicious patterns
 */
function analyzeSourceCode(sourceCode) {
  if (!sourceCode) return { score: 0, findings: [] };

  let score = 0;
  const findings = [];

  for (const { pattern, risk, name } of SUSPICIOUS_PATTERNS) {
    const matches = sourceCode.match(pattern);
    if (matches) {
      score += risk;
      findings.push({
        pattern: name,
        count: matches.length,
        risk,
        sample: matches[0].substring(0, 50)
      });
    }
  }

  return { score, findings };
}

/**
 * Get risk level from score
 */
function getRiskLevel(score) {
  if (score >= 80) return { level: 'CRITICAL', color: '#dc2626' };
  if (score >= 50) return { level: 'HIGH', color: '#ea580c' };
  if (score >= 30) return { level: 'MEDIUM', color: '#eab308' };
  if (score >= 10) return { level: 'LOW', color: '#22c55e' };
  return { level: 'MINIMAL', color: '#16a34a' };
}

/**
 * Analyze an extension using Gemini Nano for deeper insights
 */
async function analyzeExtensionWithAI(extension, sourceCode) {
  const prompt = `Analyze this Chrome extension for security risks:

Name: ${extension.name}
Permissions: ${JSON.stringify(extension.permissions)}
Host Permissions: ${JSON.stringify(extension.hostPermissions)}

Code patterns found:
${sourceCode ? sourceCode.substring(0, 2000) : 'No source available'}

Rate the risk 1-10 and explain concerns in 2-3 sentences. Format: RISK: X/10 - Explanation`;

  try {
    if (typeof self !== 'undefined' && self.ai?.languageModel) {
      const session = await self.ai.languageModel.create();
      const response = await session.prompt(prompt);
      session.destroy();
      return response;
    }
  } catch (e) {
    console.error('AI analysis failed:', e);
  }
  
  return null;
}

/**
 * Get all installed extensions and analyze them
 */
async function analyzeInstalledExtensions() {
  const results = [];
  
  try {
    const extensions = await chrome.management.getAll();
    
    for (const ext of extensions) {
      if (ext.type !== 'extension' || !ext.enabled) continue;
      if (ext.id === chrome.runtime.id) continue; // Skip self
      
      const permissionRisk = calculatePermissionRisk(
        ext.permissions || [],
        ext.hostPermissions || []
      );
      
      const totalScore = permissionRisk.score;
      const riskInfo = getRiskLevel(totalScore);
      
      results.push({
        id: ext.id,
        name: ext.name,
        version: ext.version,
        enabled: ext.enabled,
        score: totalScore,
        ...riskInfo,
        permissions: permissionRisk.flaggedPermissions,
        description: ext.description?.substring(0, 100)
      });
    }
    
    // Sort by risk score descending
    results.sort((a, b) => b.score - a.score);
    
  } catch (error) {
    console.error('Error analyzing extensions:', error);
  }
  
  return results;
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    calculatePermissionRisk,
    analyzeSourceCode,
    getRiskLevel,
    analyzeExtensionWithAI,
    analyzeInstalledExtensions,
    RISK_PERMISSIONS,
    SUSPICIOUS_PATTERNS
  };
}
