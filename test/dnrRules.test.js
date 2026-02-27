// DNR Rules Tests
const fs = require('fs');
const path = require('path');

describe('DNR Rules', () => {
  let rules;

  beforeAll(() => {
    const rulesPath = path.join(__dirname, '../src/rules/rules.json');
    const rulesContent = fs.readFileSync(rulesPath, 'utf8');
    rules = JSON.parse(rulesContent);
  });

  test('should have valid JSON structure', () => {
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBeGreaterThan(0);
  });

  test('all rules should have required fields', () => {
    rules.forEach(rule => {
      expect(rule).toHaveProperty('id');
      expect(rule).toHaveProperty('priority');
      expect(rule).toHaveProperty('action');
      expect(rule).toHaveProperty('condition');
    });
  });

  test('all rules should have block action', () => {
    rules.forEach(rule => {
      expect(rule.action.type).toBe('block');
    });
  });

  test('rules should have unique IDs', () => {
    const ids = rules.map(r => r.id);
    const uniqueIds = [...new Set(ids)];
    expect(ids.length).toBe(uniqueIds.length);
  });

  test('should block webhook.site', () => {
    const webhookRule = rules.find(r => 
      r.condition.urlFilter && r.condition.urlFilter.includes('webhook.site')
    );
    expect(webhookRule).toBeTruthy();
    expect(webhookRule.action.type).toBe('block');
  });

  test('should block requestbin', () => {
    const requestbinRule = rules.find(r =>
      r.condition.urlFilter && r.condition.urlFilter.includes('requestbin')
    );
    expect(requestbinRule).toBeTruthy();
  });

  test('should block ngrok endpoints', () => {
    const ngrokRule = rules.find(r =>
      r.condition.urlFilter && r.condition.urlFilter.includes('ngrok')
    );
    expect(ngrokRule).toBeTruthy();
  });

  test('should block sensitive query parameters', () => {
    const queryRule = rules.find(r =>
      r.condition.regexFilter && 
      r.condition.regexFilter.includes('password') &&
      r.condition.regexFilter.includes('ssn')
    );
    expect(queryRule).toBeTruthy();
  });

  test('rules should target appropriate resource types', () => {
    rules.forEach(rule => {
      expect(rule.condition.resourceTypes).toBeDefined();
      expect(rule.condition.resourceTypes).toContain('xmlhttprequest');
    });
  });
});
