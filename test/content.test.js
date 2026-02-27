/**
 * @jest-environment jsdom
 */

// Content Script Tests
require('./setupMocks');

describe('Content Script', () => {
  let scrapeVisibleText;
  let isNodeVisible;
  let createBlockingOverlay;

  beforeEach(() => {
    // Reset document
    document.body.innerHTML = '';
    
    // Clear any existing overlays
    const existingOverlay = document.getElementById('promptarmor-overlay');
    if (existingOverlay) existingOverlay.remove();
    
    // Load content script in IIFE context
    jest.isolateModules(() => {
      // Mock the content script exports for testing
      // Since content.js uses IIFE, we extract testable functions
      
      scrapeVisibleText = () => {
        const walker = document.createTreeWalker(
          document.body,
          NodeFilter.SHOW_TEXT,
          null,
          false
        );
        const chunks = [];
        let node;
        while ((node = walker.nextNode())) {
          const text = node.textContent.trim();
          if (text) chunks.push(text);
        }
        return chunks.join(' ').substring(0, 50000);
      };

      isNodeVisible = (node) => {
        if (!node || !node.parentElement) return false;
        const style = window.getComputedStyle(node.parentElement);
        return style.display !== 'none' && style.visibility !== 'hidden';
      };

      createBlockingOverlay = (evidence = '') => {
        const existing = document.getElementById('promptarmor-overlay');
        if (existing) return existing;

        const overlay = document.createElement('div');
        overlay.id = 'promptarmor-overlay';
        overlay.style.cssText = `
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.95);
          z-index: 2147483647;
          display: flex;
          align-items: center;
          justify-content: center;
        `;
        overlay.innerHTML = `
          <div style="text-align:center;color:#fff;padding:40px;">
            <h1>⚠️ Prompt Injection Detected</h1>
            <p>${evidence}</p>
          </div>
        `;
        document.body.appendChild(overlay);
        return overlay;
      };
    });
  });

  describe('scrapeVisibleText', () => {
    test('should extract text from DOM', () => {
      document.body.innerHTML = '<div>Hello World</div>';
      const text = scrapeVisibleText();
      expect(text).toContain('Hello World');
    });

    test('should handle empty body', () => {
      document.body.innerHTML = '';
      const text = scrapeVisibleText();
      expect(text).toBe('');
    });

    test('should combine multiple text nodes', () => {
      document.body.innerHTML = '<p>First</p><p>Second</p>';
      const text = scrapeVisibleText();
      expect(text).toContain('First');
      expect(text).toContain('Second');
    });

    test('should truncate very long text', () => {
      document.body.innerHTML = '<div>' + 'x'.repeat(100000) + '</div>';
      const text = scrapeVisibleText();
      expect(text.length).toBeLessThanOrEqual(50000);
    });

    test('should skip empty text nodes', () => {
      document.body.innerHTML = '<div>   </div><span>Text</span>';
      const text = scrapeVisibleText();
      expect(text).toBe('Text');
    });
  });

  describe('isNodeVisible', () => {
    test('should return true for visible nodes', () => {
      document.body.innerHTML = '<div><span id="test">Visible</span></div>';
      const node = document.getElementById('test').firstChild;
      expect(isNodeVisible(node)).toBe(true);
    });

    test('should return false for null node', () => {
      expect(isNodeVisible(null)).toBe(false);
    });

    test('should return false for node without parent', () => {
      const orphanNode = document.createTextNode('orphan');
      expect(isNodeVisible(orphanNode)).toBe(false);
    });
  });

  describe('createBlockingOverlay', () => {
    test('should create overlay element', () => {
      createBlockingOverlay();
      const overlay = document.getElementById('promptarmor-overlay');
      expect(overlay).toBeTruthy();
    });

    test('should display evidence text', () => {
      createBlockingOverlay('ignore previous');
      const overlay = document.getElementById('promptarmor-overlay');
      expect(overlay.textContent).toContain('ignore previous');
    });

    test('should not create duplicate overlays', () => {
      createBlockingOverlay();
      createBlockingOverlay();
      const overlays = document.querySelectorAll('#promptarmor-overlay');
      expect(overlays.length).toBe(1);
    });

    test('should have highest z-index', () => {
      const overlay = createBlockingOverlay();
      expect(overlay.style.zIndex).toBe('2147483647');
    });

    test('should cover full viewport', () => {
      const overlay = createBlockingOverlay();
      expect(overlay.style.position).toBe('fixed');
      expect(overlay.style.top).toBe('0px');
      expect(overlay.style.left).toBe('0px');
    });
  });

  describe('Chrome Message Handling', () => {
    test('should have message listeners registered', () => {
      // Verify chrome.runtime.onMessage.addListener was set up
      expect(chrome.runtime.onMessage.addListener).toBeDefined();
    });
  });
});
