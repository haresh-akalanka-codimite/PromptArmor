// PromptArmor - Trust Score Calculator

/**
 * Calculate trust score based on various signals
 * Score range: 0-100 (higher = safer)
 */
function calculateTrustScore(data = {}) {
  const { verdict = 'UNKNOWN', dnrBlocked = 0, flags = 0, whitelisted = false } = data;
  
  // Start at 100
  let score = 100;
  
  // If whitelisted, always return high score
  if (whitelisted) {
    return { score: 95, level: 'SAFE', color: '#22c55e' };
  }
  
  // Deductions based on signals
  if (verdict === 'HIGH' || verdict === 'YES') {
    score -= 70; // Major deduction for AI detection
  }
  
  if (dnrBlocked > 0) {
    score -= Math.min(dnrBlocked * 15, 30); // DNR blocks: max -30
  }
  
  if (flags > 0) {
    score -= Math.min(flags * 5, 20); // Repeated flags: max -20
  }
  
  // Clamp score
  score = Math.max(0, Math.min(100, score));
  
  // Determine level and color
  let level, color;
  if (score >= 80) {
    level = 'SAFE';
    color = '#22c55e'; // green
  } else if (score >= 50) {
    level = 'CAUTION';
    color = '#eab308'; // yellow
  } else {
    level = 'DANGER';
    color = '#ef4444'; // red
  }
  
  return { score, level, color };
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { calculateTrustScore };
}
