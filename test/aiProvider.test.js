/**
 * @jest-environment jsdom
 */

// PromptArmor - AI Provider Tests
// Tests for multi-provider AI integration

describe('AI Provider Module', () => {
  let aiProvider;
  
  beforeEach(() => {
    jest.resetModules();
    
    // Mock chrome storage
    global.chrome = {
      storage: {
        local: {
          get: jest.fn().mockResolvedValue({}),
          set: jest.fn().mockResolvedValue()
        }
      }
    };
    
    // Mock fetch
    global.fetch = jest.fn();
    
    aiProvider = require('../src/utils/aiProvider.js');
  });

  describe('AI_PROVIDERS constants', () => {
    it('should export GEMINI_NANO provider', () => {
      expect(aiProvider.AI_PROVIDERS.GEMINI_NANO).toBe('gemini-nano');
    });
    
    it('should export GEMINI_API provider', () => {
      expect(aiProvider.AI_PROVIDERS.GEMINI_API).toBe('gemini-api');
    });
    
    it('should export GEMMA_OLLAMA provider', () => {
      expect(aiProvider.AI_PROVIDERS.GEMMA_OLLAMA).toBe('gemma-ollama');
    });
  });

  describe('loadConfig', () => {
    it('should return default config when storage is empty', async () => {
      chrome.storage.local.get.mockResolvedValue({});
      
      const config = await aiProvider.loadConfig();
      
      expect(config.provider).toBe('gemini-nano');
      expect(config.geminiApiKey).toBe('');
      expect(config.ollamaEndpoint).toBe('http://localhost:11434');
    });
    
    it('should merge stored config with defaults', async () => {
      chrome.storage.local.get.mockResolvedValue({
        aiConfig: { provider: 'gemini-api', geminiApiKey: 'test-key' }
      });
      
      const config = await aiProvider.loadConfig();
      
      expect(config.provider).toBe('gemini-api');
      expect(config.geminiApiKey).toBe('test-key');
    });
  });

  describe('saveConfig', () => {
    it('should save config to chrome storage', async () => {
      await aiProvider.saveConfig({ provider: 'gemma-ollama' });
      
      expect(chrome.storage.local.set).toHaveBeenCalledWith(
        expect.objectContaining({
          aiConfig: expect.objectContaining({ provider: 'gemma-ollama' })
        })
      );
    });
  });

  describe('verifyGeminiAPIKey', () => {
    it('should return true for valid API key', async () => {
      fetch.mockResolvedValue({ ok: true });
      
      const valid = await aiProvider.verifyGeminiAPIKey('valid-key');
      
      expect(valid).toBe(true);
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('generativelanguage.googleapis.com')
      );
    });
    
    it('should return false for invalid API key', async () => {
      fetch.mockResolvedValue({ ok: false });
      
      const valid = await aiProvider.verifyGeminiAPIKey('invalid-key');
      
      expect(valid).toBe(false);
    });
    
    it('should return false on network error', async () => {
      fetch.mockRejectedValue(new Error('Network error'));
      
      const valid = await aiProvider.verifyGeminiAPIKey('any-key');
      
      expect(valid).toBe(false);
    });
  });

  describe('isOllamaAvailable', () => {
    it('should return true when Ollama is running with Gemma', async () => {
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ models: [{ name: 'gemma2:2b' }] })
      });
      
      const available = await aiProvider.isOllamaAvailable();
      
      expect(available).toBe(true);
    });
    
    it('should return false when Ollama has no Gemma models', async () => {
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ models: [{ name: 'llama:7b' }] })
      });
      
      const available = await aiProvider.isOllamaAvailable();
      
      expect(available).toBe(false);
    });
    
    it('should return false when Ollama is not running', async () => {
      fetch.mockRejectedValue(new Error('Connection refused'));
      
      const available = await aiProvider.isOllamaAvailable();
      
      expect(available).toBe(false);
    });
  });

  describe('listOllamaModels', () => {
    it('should return list of model names', async () => {
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ 
          models: [
            { name: 'gemma2:2b' },
            { name: 'gemma:7b' },
            { name: 'llama:13b' }
          ] 
        })
      });
      
      const models = await aiProvider.listOllamaModels();
      
      expect(models).toContain('gemma2:2b');
      expect(models).toContain('gemma:7b');
      expect(models).toContain('llama:13b');
    });
    
    it('should return empty array on error', async () => {
      fetch.mockRejectedValue(new Error('Connection refused'));
      
      const models = await aiProvider.listOllamaModels();
      
      expect(models).toEqual([]);
    });
  });

  describe('checkAvailableProviders', () => {
    it('should always include all three providers', async () => {
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ models: [] })
      });
      
      const providers = await aiProvider.checkAvailableProviders();
      
      expect(providers.length).toBe(3);
      expect(providers.map(p => p.id)).toContain('gemini-nano');
      expect(providers.map(p => p.id)).toContain('gemini-api');
      expect(providers.map(p => p.id)).toContain('gemma-ollama');
    });
  });

  describe('analyzeText', () => {
    it('should fall back to YES (fail-closed) on error', async () => {
      // Configure to use Gemini API but with no API key
      chrome.storage.local.get.mockResolvedValue({
        aiConfig: { provider: 'gemini-api', geminiApiKey: '' }
      });
      
      const result = await aiProvider.analyzeText('test text');
      
      // Should fail-closed (treat as suspicious)
      expect(result).toBe('YES');
    });
    
    it('should use Gemini API when configured', async () => {
      chrome.storage.local.get.mockResolvedValue({
        aiConfig: { provider: 'gemini-api', geminiApiKey: 'test-key' }
      });
      
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          candidates: [{
            content: { parts: [{ text: 'NO' }] }
          }]
        })
      });
      
      const result = await aiProvider.analyzeText('safe text');
      
      expect(result).toBe('NO');
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('generativelanguage.googleapis.com'),
        expect.any(Object)
      );
    });
    
    it('should use Ollama when configured', async () => {
      chrome.storage.local.get.mockResolvedValue({
        aiConfig: { 
          provider: 'gemma-ollama',
          ollamaEndpoint: 'http://localhost:11434',
          gemmaModel: 'gemma2:2b'
        }
      });
      
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ response: 'YES' })
      });
      
      const result = await aiProvider.analyzeText('suspicious text');
      
      expect(result).toBe('YES');
      expect(fetch).toHaveBeenCalledWith(
        'http://localhost:11434/api/generate',
        expect.any(Object)
      );
    });
  });

  describe('getDetailedAnalysis', () => {
    it('should get detailed analysis from Gemini API', async () => {
      chrome.storage.local.get.mockResolvedValue({
        aiConfig: { provider: 'gemini-api', geminiApiKey: 'test-key' }
      });
      
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          candidates: [{
            content: { parts: [{ text: 'VERDICT: SAFE\nCONFIDENCE: HIGH' }] }
          }]
        })
      });
      
      const result = await aiProvider.getDetailedAnalysis('test text');
      
      expect(result).toContain('SAFE');
    });
  });
});

describe('AI Provider Security', () => {
  beforeEach(() => {
    jest.resetModules();
    
    global.chrome = {
      storage: {
        local: {
          get: jest.fn().mockResolvedValue({}),
          set: jest.fn().mockResolvedValue()
        }
      }
    };
    
    global.fetch = jest.fn();
  });

  it('should not expose API key in logs', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    
    const aiProvider = require('../src/utils/aiProvider.js');
    
    global.chrome.storage.local.get.mockResolvedValue({
      aiConfig: { provider: 'gemini-api', geminiApiKey: 'secret-api-key-12345' }
    });
    
    fetch.mockRejectedValue(new Error('Network error'));
    
    await aiProvider.analyzeText('test');
    
    // Check console.error was not called with the API key
    if (consoleSpy.mock.calls.length > 0) {
      const allLogs = JSON.stringify(consoleSpy.mock.calls);
      expect(allLogs).not.toContain('secret-api-key-12345');
    }
    
    consoleSpy.mockRestore();
  });

  it('should truncate text before sending to API', async () => {
    const aiProvider = require('../src/utils/aiProvider.js');
    
    global.chrome.storage.local.get.mockResolvedValue({
      aiConfig: { provider: 'gemini-api', geminiApiKey: 'test-key' }
    });
    
    fetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        candidates: [{ content: { parts: [{ text: 'NO' }] } }]
      })
    });
    
    const longText = 'x'.repeat(20000);
    await aiProvider.analyzeText(longText);
    
    const requestBody = JSON.parse(fetch.mock.calls[0][1].body);
    const sentText = requestBody.contents[0].parts[0].text;
    
    // Should be truncated (10000 chars + prompt text)
    expect(sentText.length).toBeLessThan(15000);
  });
});
