// PromptArmor - Departmental Risk Heatmap
// Visualises risk distribution across departments / user groups

const RISK_LEVELS = {
  CRITICAL: { label: 'Critical', color: '#ef4444', threshold: 80 },
  HIGH:     { label: 'High',     color: '#f97316', threshold: 60 },
  MEDIUM:   { label: 'Medium',   color: '#f59e0b', threshold: 40 },
  LOW:      { label: 'Low',      color: '#22c55e', threshold: 0  }
};

/**
 * Calculate risk metrics for a single department
 */
function calcDepartmentRisk(dept) {
  const users                = dept.userCount           || 1;
  const highRiskExtensions   = dept.highRiskExtensions  || 0;
  const aiSensitiveSubmissions = dept.aiSensitiveSubmissions || 0;
  const injectionAttempts    = dept.injectionAttempts   || 0;
  const policyViolations     = dept.policyViolations    || 0;

  // Normalise each dimension to 0-100
  const extensionScore = Math.min(100, (highRiskExtensions / users) * 200);
  const aiUsageScore   = Math.min(100, (aiSensitiveSubmissions / users) * 300);
  const injectionScore = Math.min(100, injectionAttempts * 20);
  const complianceScore= Math.min(100, policyViolations * 15);

  // Weighted composite
  const compositeRisk = Math.min(100,
    extensionScore  * 0.35 +
    aiUsageScore    * 0.30 +
    injectionScore  * 0.20 +
    complianceScore * 0.15
  );

  return {
    name: dept.name,
    userCount: users,
    compositeRisk: Math.round(compositeRisk),
    dimensions: {
      extensionExposure:    Math.round(extensionScore),
      aiUsageRisk:          Math.round(aiUsageScore),
      injectionExposure:    Math.round(injectionScore),
      policyCompliance:     Math.round(complianceScore)
    },
    riskLevel: getRiskLevel(compositeRisk),
    highRiskExtensionRate: highRiskExtensions / users,
    anomalyRatio: 1.0 // populated later during org-wide analysis
  };
}

function getRiskLevel(score) {
  if (score >= RISK_LEVELS.CRITICAL.threshold) return RISK_LEVELS.CRITICAL;
  if (score >= RISK_LEVELS.HIGH.threshold)     return RISK_LEVELS.HIGH;
  if (score >= RISK_LEVELS.MEDIUM.threshold)   return RISK_LEVELS.MEDIUM;
  return RISK_LEVELS.LOW;
}

/**
 * Build an organisation-wide heatmap from department data
 * Computes anomaly ratios relative to org average
 */
function buildHeatmap(departments = []) {
  if (departments.length === 0) return { departments: [], orgAverage: 0, hotDepartments: [] };

  const assessed = departments.map(calcDepartmentRisk);

  const orgAvgExtRate = assessed.reduce((s, d) => s + d.highRiskExtensionRate, 0) / assessed.length;

  // Annotate anomaly ratios
  assessed.forEach(d => {
    d.anomalyRatio = orgAvgExtRate > 0
      ? +(d.highRiskExtensionRate / orgAvgExtRate).toFixed(2)
      : 1.0;
  });

  const orgAverage = Math.round(assessed.reduce((s, d) => s + d.compositeRisk, 0) / assessed.length);

  const hotDepartments = assessed
    .filter(d => d.compositeRisk >= RISK_LEVELS.HIGH.threshold)
    .sort((a, b) => b.compositeRisk - a.compositeRisk);

  return {
    departments: assessed.sort((a, b) => b.compositeRisk - a.compositeRisk),
    orgAverage,
    hotDepartments,
    topRiskDimension: getTopRiskDimension(assessed),
    timestamp: Date.now()
  };
}

function getTopRiskDimension(assessed) {
  const dims = ['extensionExposure', 'aiUsageRisk', 'injectionExposure', 'policyCompliance'];
  const totals = {};
  dims.forEach(d => {
    totals[d] = assessed.reduce((s, dept) => s + (dept.dimensions[d] || 0), 0);
  });
  return Object.entries(totals).sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Generate a simple ASCII/text summary suitable for an executive report
 */
function buildExecutiveSummary(heatmap) {
  const { departments, orgAverage, hotDepartments } = heatmap;
  const lines = [
    `Browser Security Risk Distribution — ${new Date().toLocaleDateString()}`,
    `Org Average Risk Score: ${orgAverage}/100`,
    `Departments Assessed:   ${departments.length}`,
    `High/Critical Risk:     ${hotDepartments.length}`,
    '',
    'Top Risk Departments:'
  ];
  hotDepartments.slice(0, 5).forEach(d => {
    lines.push(`  • ${d.name.padEnd(20)} ${d.riskLevel.label.padEnd(10)} ${d.compositeRisk}/100`);
  });
  return lines.join('\n');
}

/**
 * Mock data generator for demo / simulation
 */
function generateMockDepartments() {
  return [
    { name: 'Marketing',    userCount: 45, highRiskExtensions: 19, aiSensitiveSubmissions: 8,  injectionAttempts: 2, policyViolations: 3 },
    { name: 'Engineering',  userCount: 80, highRiskExtensions: 12, aiSensitiveSubmissions: 22, injectionAttempts: 5, policyViolations: 1 },
    { name: 'Finance',      userCount: 30, highRiskExtensions: 2,  aiSensitiveSubmissions: 15, injectionAttempts: 0, policyViolations: 5 },
    { name: 'HR',           userCount: 20, highRiskExtensions: 4,  aiSensitiveSubmissions: 10, injectionAttempts: 1, policyViolations: 2 },
    { name: 'Legal',        userCount: 15, highRiskExtensions: 1,  aiSensitiveSubmissions:  5, injectionAttempts: 0, policyViolations: 1 },
    { name: 'Sales',        userCount: 60, highRiskExtensions: 20, aiSensitiveSubmissions: 18, injectionAttempts: 3, policyViolations: 2 },
    { name: 'Support',      userCount: 35, highRiskExtensions: 8,  aiSensitiveSubmissions:  6, injectionAttempts: 1, policyViolations: 0 }
  ];
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    calcDepartmentRisk,
    buildHeatmap,
    buildExecutiveSummary,
    generateMockDepartments,
    getRiskLevel,
    RISK_LEVELS
  };
}
