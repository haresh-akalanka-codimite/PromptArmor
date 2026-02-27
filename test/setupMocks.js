// Test Setup - Chrome API Mocks

// Mock chrome APIs
global.chrome = {
  runtime: {
    onMessage: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    sendMessage: jest.fn().mockResolvedValue({}),
    onInstalled: {
      addListener: jest.fn()
    }
  },
  storage: {
    local: {
      get: jest.fn().mockResolvedValue({}),
      set: jest.fn().mockResolvedValue({})
    }
  },
  tabs: {
    query: jest.fn().mockResolvedValue([{ id: 1, url: 'https://example.com' }]),
    sendMessage: jest.fn().mockResolvedValue({}),
    onActivated: {
      addListener: jest.fn()
    }
  },
  sidePanel: {
    setPanelBehavior: jest.fn().mockResolvedValue({}),
    open: jest.fn().mockResolvedValue({})
  },
  declarativeNetRequest: {
    updateDynamicRules: jest.fn().mockResolvedValue({})
  }
};

// Mock window.ai for Gemini Nano
global.window = global.window || {};
global.window.ai = {
  languageModel: {
    create: jest.fn().mockResolvedValue({
      prompt: jest.fn().mockResolvedValue('NO'),
      destroy: jest.fn()
    })
  }
};

// Mock self.ai for service worker
global.self = global.self || {};
global.self.ai = {
  languageModel: {
    create: jest.fn().mockResolvedValue({
      prompt: jest.fn().mockResolvedValue('NO'),
      destroy: jest.fn()
    })
  }
};

// Mock console to reduce noise
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
};

// Export a reset function for tests to use
module.exports = {
  resetMocks: () => {
    jest.clearAllMocks();
  }
};
