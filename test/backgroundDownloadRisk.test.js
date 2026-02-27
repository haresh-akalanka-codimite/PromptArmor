/**
 * @jest-environment node
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadBackgroundContext() {
  const code = fs.readFileSync(path.join(__dirname, '../src/background/background.js'), 'utf8');

  const context = {
    console: { log: jest.fn(), error: jest.fn() },
    URL,
    fetch: jest.fn(),
    Date,
    setTimeout,
    clearTimeout,
    self: {},
    chrome: {
      storage: {
        local: {
          get: jest.fn().mockResolvedValue({}),
          set: jest.fn().mockResolvedValue()
        }
      },
      downloads: {
        onCreated: { addListener: jest.fn() },
        cancel: jest.fn().mockResolvedValue()
      },
      runtime: {
        onMessage: { addListener: jest.fn() },
        onInstalled: { addListener: jest.fn() },
        sendMessage: jest.fn().mockResolvedValue()
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
