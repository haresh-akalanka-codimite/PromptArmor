/**
 * @jest-environment node
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadBackgroundContext(storageGetValue = {}) {
  const code = fs.readFileSync(path.join(__dirname, '../src/background/background.js'), 'utf8');

  const context = {
    console: { log: jest.fn(), error: jest.fn() },
    URL,
    fetch: jest.fn(),
    Date,
    setTimeout,
    clearTimeout,
    self: {},
    btoa: str => Buffer.from(str, 'binary').toString('base64'),
    atob: b64 => Buffer.from(b64, 'base64').toString('binary'),
    chrome: {
      storage: {
        local: {
          get: jest.fn().mockImplementation(async key => {
            if (key === null) return storageGetValue;
            if (Array.isArray(key)) {
              const out = {};
              key.forEach(k => { if (k in storageGetValue) out[k] = storageGetValue[k]; });
              return out;
            }
            return storageGetValue;
          }),
          set: jest.fn().mockResolvedValue()
        }
      },
      downloads: {
        onCreated: { addListener: jest.fn() },
        cancel: jest.fn().mockResolvedValue()
      },
      alarms: {
        create: jest.fn().mockResolvedValue(),
        clear: jest.fn().mockResolvedValue(),
        onAlarm: { addListener: jest.fn() }
      },
      runtime: {
        id: 'promptarmor-test-id',
        onMessage: { addListener: jest.fn() },
        onInstalled: { addListener: jest.fn() },
        onStartup: { addListener: jest.fn() },
        sendMessage: jest.fn().mockResolvedValue(),
        getManifest: jest.fn(() => ({ version: '2.0.0', name: 'PromptArmor' }))
      },
      tabs: { sendMessage: jest.fn().mockResolvedValue() },
      sidePanel: { setPanelBehavior: jest.fn().mockResolvedValue() }
    }
  };

  vm.createContext(context);
  vm.runInContext(code, context);
  return context;
}

describe('background download risk assessment', () => {
  it('blocks when chrome flags the download as dangerous', () => {
    const ctx = loadBackgroundContext();
    const result = ctx.assessDownloadRisk({
      filename: 'notes.txt',
      mime: 'text/plain',
      danger: 'dangerous',
      url: 'https://example.com/notes.txt'
    });

    expect(result.action).toBe('block');
    expect(result.reasons).toContain('chrome-danger:dangerous');
  });

  it('warns on suspicious extension without danger verdict', () => {
    const ctx = loadBackgroundContext();
    const result = ctx.assessDownloadRisk({
      filename: 'payload.exe',
      mime: 'application/octet-stream',
      danger: 'safe',
      url: 'https://example.com/payload.exe'
    });

    expect(result.action).toBe('warn');
    expect(result.reasons).toContain('risky-extension:.exe');
  });

  it('allows low-risk downloads', () => {
    const ctx = loadBackgroundContext();
    const result = ctx.assessDownloadRisk({
      filename: 'report.pdf',
      mime: 'application/pdf',
      danger: 'safe',
      url: 'https://example.com/report.pdf'
    });

    expect(result.action).toBe('allow');
    expect(result.score).toBe(0);
  });
});

describe('daily report pipeline', () => {
  it('skips when daily report is disabled', async () => {
    const ctx = loadBackgroundContext({ dailyReportConfig: { enabled: false } });
    const result = await ctx.runDailyReportPipeline('manual');
    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('disabled');
  });

  it('skips when firestore project id is missing', async () => {
    const ctx = loadBackgroundContext({ dailyReportConfig: { enabled: true, publicKeyPem: 'x', firestoreApiKey: 'k' } });
    const result = await ctx.runDailyReportPipeline('manual');
    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('missing-firestore-project-id');
  });

  it('skips when firestore api key is missing', async () => {
    const ctx = loadBackgroundContext({ dailyReportConfig: { enabled: true, publicKeyPem: 'x', firestoreProjectId: 'p' } });
    const result = await ctx.runDailyReportPipeline('manual');
    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('missing-firestore-api-key');
  });

  it('builds report payload with metadata', () => {
    const ctx = loadBackgroundContext();
    const payload = ctx.buildDailyReportPayload({ visitHistory: [] }, 'alarm');
    expect(payload.reportType).toBe('promptarmor.daily.full');
    expect(payload.extension.id).toBe('promptarmor-test-id');
    expect(payload.trigger).toBe('alarm');
  });


  it('builds a json file envelope before encryption', () => {
    const ctx = loadBackgroundContext();
    const payload = ctx.buildDailyReportPayload({ visitHistory: [] }, 'manual');
    const reportFile = ctx.buildDailyReportJsonFile(payload);
    expect(reportFile.fileName.endsWith('.json')).toBe(true);
    expect(reportFile.contentType).toBe('application/json');
    expect(reportFile.content).toContain('"reportType": "promptarmor.daily.full"');
  });
});
