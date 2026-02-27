/**
 * @jest-environment jsdom
 */

// Trust Score Tests
require('./setupMocks');

// Import the module
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(
  path.join(__dirname, '../src/utils/trustScore.js'),
  'utf8'
);

const moduleExports = {};
const context = {
  module: { exports: moduleExports },
  exports: moduleExports
};

vm.runInNewContext(source, context);

const { calculateTrustScore } = context.module.exports;

describe('Trust Score', () => {
  describe('calculateTrustScore', () => {
    test('should return 100 for clean verdict', () => {
      const result = calculateTrustScore({ verdict: 'NO', flags: 0 });
      expect(result.score).toBe(100);
      expect(result.level).toBe('SAFE');
      expect(result.color).toBe('#22c55e');
    });

    test('should return 95 for whitelisted origin', () => {
      const result = calculateTrustScore({ verdict: 'YES', whitelisted: true });
      expect(result.score).toBe(95);
      expect(result.level).toBe('SAFE');
    });

    test('should deduct 70 points for suspicious verdict', () => {
      const result = calculateTrustScore({ verdict: 'YES', flags: 0 });
      expect(result.score).toBe(30);
      expect(result.level).toBe('DANGER');
    });

    test('should deduct points for flags', () => {
      const result = calculateTrustScore({ verdict: 'NO', flags: 3 });
      expect(result.score).toBe(85); // 100 - 15
    });

    test('should cap flag deductions at 20 points', () => {
      const result = calculateTrustScore({ verdict: 'NO', flags: 10 });
      expect(result.score).toBe(80); // 100 - max 20
    });

    test('should return DANGER for low scores', () => {
      const result = calculateTrustScore({ verdict: 'YES', flags: 3, dnrBlocked: 2 });
      expect(result.level).toBe('DANGER');
      expect(result.color).toBe('#ef4444');
    });

    test('should handle undefined input with defaults', () => {
      const result = calculateTrustScore();
      expect(result.score).toBe(100);
    });

    test('should handle empty object', () => {
      const result = calculateTrustScore({});
      expect(result.score).toBe(100);
    });

    test('should deduct for DNR blocks', () => {
      const result = calculateTrustScore({ verdict: 'NO', dnrBlocked: 2 });
      expect(result.score).toBe(70); // 100 - 30
    });

    test('should return CAUTION for medium scores', () => {
      const result = calculateTrustScore({ verdict: 'NO', dnrBlocked: 2, flags: 2 });
      expect(result.level).toBe('CAUTION');
      expect(result.color).toBe('#eab308');
    });
  });
});
