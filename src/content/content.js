// PromptArmor - Content Script

(function() {
  'use strict';

  const MAX_TEXT_LENGTH = 100000;
  let isBlocked = false;
  let originalWindowAI = null;
  let isContextValid = true;
  let protectionEnabled = true; // local cache of enabled state

  // Load initial enabled state from storage
  chrome.storage.local.get(['settings'], (result) => {
    if (chrome.runtime.lastError) return;
    protectionEnabled = result.settings?.enabled !== false;
  });

  function checkContext() {
    try {
      return isContextValid && !!chrome.runtime?.id;
    } catch (e) {
      isContextValid = false;
      return false;
    }
  }

  function safeSendMessage(message) {
    if (!checkContext()) {
      try { observer.disconnect(); } catch(e) {}
      clearTimeout(window._promptArmorDebounce);
      return;
    }
    try {
      chrome.runtime.sendMessage(message).catch(() => {});
    } catch (e) {
      if (e.message?.includes('Extension context invalidated')) {
        isContextValid = false;
        try { observer.disconnect(); } catch(e2) {}
        clearTimeout(window._promptArmorDebounce);
      }
    }
  }

  function isNodeVisible(node) {
    if (!node || !node.parentElement) return false;
    const parent = node.parentElement;
    const tagName = parent.tagName?.toLowerCase();
    if (['script', 'style', 'noscript', 'template', 'svg', 'path'].includes(tagName)) return false;
    try {
      const style = window.getComputedStyle(parent);
      if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    } catch (e) {}
    if (parent.getAttribute?.('aria-hidden') === 'true') return false;
    return true;
  }

  function scrapeVisibleText() {
    if (!document.body) return '';
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const textParts = [];
    let totalLength = 0, node;
    while ((node = walker.nextNode()) && totalLength < MAX_TEXT_LENGTH) {
      if (isNodeVisible(node)) {
        const text = node.textContent?.trim();
        if (text) { textParts.push(text); totalLength += text.length; }
      }
    }
    return textParts.join(' ').substring(0, MAX_TEXT_LENGTH);
  }

  function scrapeAllText() {
    if (!document.body) return '';
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const textParts = [];
    let totalLength = 0, node;
    while ((node = walker.nextNode()) && totalLength < MAX_TEXT_LENGTH) {
      const tagName = node.parentElement?.tagName?.toLowerCase();
      if (['script', 'style', 'noscript', 'template'].includes(tagName)) continue;
      const text = node.textContent?.trim();
      if (text) { textParts.push(text); totalLength += text.length; }
    }
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let match;
    while ((match = commentRegex.exec(document.body.innerHTML)) !== null) {
      textParts.push(match[1]);
    }
    return textParts.join(' ').substring(0, MAX_TEXT_LENGTH);
  }

  function sendForAnalysis() {
    if (!protectionEnabled) return; // GATE: respect toggle
    if (!checkContext()) return;
    const text = scrapeAllText();
    if (text.length < 10) return;
    safeSendMessage({
      type: 'PROMPTARMOR_SCRAPE',
      text,
      url: window.location.href,
      origin: window.location.origin
    });
  }

  function createBlockingOverlay(evidence) {
    if (document.getElementById('promptarmor-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'promptarmor-overlay';
    overlay.innerHTML = `
      <style>
        #promptarmor-overlay {
          position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.85); z-index: 2147483647;
          display: flex; align-items: center; justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        #promptarmor-dialog {
          background: #1f2937; border-radius: 12px; padding: 32px;
          max-width: 500px; text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,0.5);
        }
        #promptarmor-dialog h2 { color: #ef4444; margin: 0 0 16px; font-size: 24px; }
        #promptarmor-dialog p  { color: #d1d5db; margin: 0 0 24px; line-height: 1.6; }
        #promptarmor-evidence {
          background: #374151; border-radius: 8px; padding: 12px; margin-bottom: 24px;
          font-family: monospace; font-size: 12px; color: #9ca3af;
          max-height: 100px; overflow: auto; text-align: left;
        }
        #promptarmor-buttons { display: flex; gap: 12px; justify-content: center; }
        #promptarmor-buttons button {
          padding: 12px 24px; border-radius: 8px; border: none;
          font-size: 14px; font-weight: 600; cursor: pointer; transition: transform 0.1s;
        }
        #promptarmor-buttons button:hover { transform: scale(1.02); }
        #promptarmor-dismiss   { background: #374151; color: #fff; }
        #promptarmor-whitelist { background: #3b82f6; color: #fff; }
      </style>
      <div id="promptarmor-dialog">
        <h2>⚠️ High Risk Detected</h2>
        <p>This page contains content that may attempt to manipulate AI behavior or steal your data.</p>
        <div id="promptarmor-evidence">${evidence || 'Suspicious content detected'}</div>
        <div id="promptarmor-buttons">
          <button id="promptarmor-dismiss">Dismiss Warning</button>
          <button id="promptarmor-whitelist">Trust This Site</button>
        </div>
      </div>`;
    document.documentElement.appendChild(overlay);
    document.getElementById('promptarmor-dismiss').addEventListener('click', removeOverlay);
    document.getElementById('promptarmor-whitelist').addEventListener('click', () => {
      safeSendMessage({ type: 'PROMPTARMOR_WHITELIST', origin: window.location.origin });
      removeOverlay();
    });
  }

  function removeOverlay() {
    document.getElementById('promptarmor-overlay')?.remove();
    restoreWindowAI();
    isBlocked = false;
  }

  function blockWindowAI() {
    if (isBlocked) return;
    isBlocked = true;
    try {
      if (window.ai) {
        originalWindowAI = window.ai;
        window.ai = new Proxy({}, {
          get() { throw new Error('Blocked by PromptArmor: This page has been flagged as risky'); }
        });
      }
    } catch (e) {}
  }

  function restoreWindowAI() {
    if (originalWindowAI) { window.ai = originalWindowAI; originalWindowAI = null; }
  }

  if (checkContext()) {
    chrome.runtime.onMessage.addListener((message) => {
      if (!checkContext()) return;

      // Popup sent a toggle update — sync local state immediately
      if (message.type === 'PROMPTARMOR_SET_ENABLED') {
        protectionEnabled = message.enabled;
        if (!protectionEnabled) removeOverlay(); // remove block if user disables
        return;
      }

      if (message.type === 'PROMPTARMOR_RESCAN') {
        sendForAnalysis();
        return;
      }

      if (message.type === 'PROMPTARMOR_BLOCK') {
        if (!protectionEnabled) return; // don't block if protection is off
        try {
          chrome.storage.local.get(['whitelist_' + window.location.origin], (result) => {
            if (chrome.runtime.lastError) return;
            if (result['whitelist_' + window.location.origin]) return;
            blockWindowAI();
            createBlockingOverlay(message.evidence);
          });
        } catch (e) {}
      }

      if (message.type === 'PROMPTARMOR_UNBLOCK') {
        removeOverlay();
      }

      if (message.type === 'PROMPTARMOR_DEVICE_STATUS') {
        if (message.isNew) {
          showNewDeviceToast(message.hash);
        }
        return;
      }
    });
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(sendForAnalysis, 100);
  } else {
    window.addEventListener('DOMContentLoaded', () => setTimeout(sendForAnalysis, 100));
  }

  const observer = new MutationObserver(() => {
    clearTimeout(window._promptArmorDebounce);
    window._promptArmorDebounce = setTimeout(sendForAnalysis, 1000);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }

  // ── Paste Secret Detection ─────────────────────────────────────────────────
  //
  // Detects when a user pastes credentials, .env files, or tokens into
  // chat interfaces (ChatGPT, Claude, Gemini, social media, etc.)

  const PASTE_SECRET_PATTERNS = [
    { name: 'Private Key',       re: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },
    { name: 'AWS Access Key',    re: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/ },
    { name: 'GitHub Token',      re: /\b(ghp_|github_pat_)[a-zA-Z0-9_]{20,}\b/ },
    { name: 'Slack Token',       re: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/ },
    { name: 'JWT Token',         re: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/ },
    { name: 'Bearer Token',      re: /\bBearer\s+[a-zA-Z0-9_\-]{20,}\b/ },
    { name: 'Password Field',    re: /\b(password|passwd|pwd)\s*[=:]\s*\S{6,}/i },
    { name: 'API Key',           re: /\b(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{20,}/i },
    { name: 'Connection String', re: /\b(mongodb|postgresql|mysql|redis):\/\/[^\s'"]+/ }
  ];

  // No \b word boundaries — underscores are \w so \bPRIVATE\b would NOT match
  // GOOGLE_PRIVATE_KEY. Substring match instead.
  const ENV_SENSITIVE_KEYS = /(SECRET|PASSWORD|TOKEN|PASS|PRIVATE|CREDENTIAL|DATABASE|APIKEY|AUTH|OAUTH|STRIPE|TWILIO|SENDGRID|FIREBASE|SUPABASE)/i;
  const ENV_LINE_RE = /^[A-Z_][A-Z0-9_]*\s*=\s*.+$/gm;

  function detectSecretsInPaste(text) {
    if (!text || text.length < 8) return [];
    const found = [];
    for (const { name, re } of PASTE_SECRET_PATTERNS) {
      if (re.test(text)) found.push(name);
    }
    const envLines = text.match(ENV_LINE_RE) || [];
    const hasSensitiveKey = envLines.some(line => ENV_SENSITIVE_KEYS.test(line.split('=')[0]));
    if (hasSensitiveKey || envLines.length >= 4) found.push('.env / Config File');
    return found;
  }

  // Redact secrets while keeping non-sensitive content intact.
  // Key names are preserved; only the secret values are replaced.
  function sanitizePastedText(text) {
    let r = text;

    // Full PEM block (RSA or EC private key)
    r = r.replace(
      /-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----/g,
      '[PRIVATE_KEY_REDACTED]'
    );
    // AWS key ID
    r = r.replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g, '[AWS_KEY_REDACTED]');
    // GitHub token
    r = r.replace(/\b(?:ghp_|github_pat_)[a-zA-Z0-9_]{20,}\b/g, '[GITHUB_TOKEN_REDACTED]');
    // Slack token
    r = r.replace(/\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g, '[SLACK_TOKEN_REDACTED]');
    // JWT
    r = r.replace(/\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[JWT_REDACTED]');
    // Bearer — keep prefix, redact value
    r = r.replace(/(\bBearer\s+)[a-zA-Z0-9_\-]{20,}\b/g, '$1[TOKEN_REDACTED]');
    // Password field — keep key name, redact value
    r = r.replace(/(\b(?:password|passwd|pwd)\s*[=:]\s*)\S{6,}/gi, '$1[PASSWORD_REDACTED]');
    // API key — keep key name, redact value
    r = r.replace(/(\b(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?)[a-zA-Z0-9_\-]{20,}/gi, '$1[API_KEY_REDACTED]');
    // Connection string — keep protocol, redact credentials/host
    r = r.replace(/\b((?:mongodb|postgresql|mysql|redis):\/\/)[^\s'"]+/gi, '$1[CONNECTION_REDACTED]');

    // .env lines: for each KEY=value line, if key name contains a sensitive keyword,
    // keep the key name but replace the value with [REDACTED]
    r = r.replace(/^([A-Z_][A-Z0-9_]*\s*=\s*)(.+)$/gm, (match, keyPart, _value) => {
      const keyName = keyPart.split('=')[0].trim();
      return ENV_SENSITIVE_KEYS.test(keyName) ? keyPart + '[REDACTED]' : match;
    });

    return r;
  }

  // Write sanitized text back into a contenteditable or input/textarea element.
  // Restores the pre-paste state first, then inserts the new text so the result
  // is: (content before paste) + (sanitized clipboard text).
  function applyToElement(el, sanitizedText) {
    if (el.isContentEditable) {
      // Restore pre-paste HTML so we don't double-apply
      el.innerHTML = el._paPreHTML || '';
      el.focus();
      // Position cursor at end, then insert via execCommand (preserves undo stack)
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      if (!document.execCommand('insertText', false, sanitizedText)) {
        // Fallback for editors that block execCommand
        el.textContent = (el.textContent || '') + sanitizedText;
        el.dispatchEvent(new InputEvent('input', { bubbles: true, data: sanitizedText }));
      }
    } else {
      el.value = (el._paPrePasteValue || '') + sanitizedText;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  // Restore element to its state before the paste happened.
  function clearPaste(el) {
    if (el.isContentEditable) {
      el.innerHTML = el._paPreHTML || '';
      el.dispatchEvent(new InputEvent('input', { bubbles: true }));
    } else {
      el.value = el._paPrePasteValue || '';
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  function showPasteWarningToast(detections, targetElement, pastedText) {
    document.getElementById('promptarmor-paste-toast')?.remove();

    const toast = document.createElement('div');
    toast.id = 'promptarmor-paste-toast';
    toast.innerHTML = `
      <style>
        #promptarmor-paste-toast {
          position: fixed; top: 16px; right: 16px; z-index: 2147483647;
          background: #1f2937; border: 2px solid #ef4444; border-radius: 12px;
          padding: 16px 20px; max-width: 380px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          animation: pa-slidein 0.25s ease;
        }
        @keyframes pa-slidein {
          from { transform: translateX(400px); opacity: 0; }
          to   { transform: translateX(0);     opacity: 1; }
        }
        #promptarmor-paste-toast .pa-title {
          color: #ef4444; font-weight: 700; font-size: 14px; margin-bottom: 6px;
        }
        #promptarmor-paste-toast .pa-body {
          color: #d1d5db; font-size: 13px; margin-bottom: 10px; line-height: 1.4;
        }
        #promptarmor-paste-toast .pa-tags {
          display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px;
        }
        #promptarmor-paste-toast .pa-tag {
          background: #374151; color: #fbbf24;
          font-size: 11px; font-family: monospace; padding: 2px 8px; border-radius: 4px;
        }
        #promptarmor-paste-toast .pa-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        #promptarmor-paste-toast button {
          padding: 6px 14px; border-radius: 6px; border: none;
          font-size: 12px; font-weight: 600; cursor: pointer;
        }
        #pa-paste-sanitize { background: #f59e0b; color: #000; }
        #pa-paste-clear    { background: #ef4444; color: #fff; }
        #pa-paste-dismiss  { background: #374151; color: #d1d5db; }
      </style>
      <div class="pa-title">🔐 PromptArmor: Secret Detected in Paste</div>
      <div class="pa-body">Sensitive data detected. Sanitize replaces secrets with placeholders; Clear removes the paste entirely.</div>
      <div class="pa-tags">${detections.map(d => `<span class="pa-tag">${d}</span>`).join('')}</div>
      <div class="pa-actions">
        <button id="pa-paste-sanitize">Sanitize</button>
        <button id="pa-paste-clear">Clear Paste</button>
        <button id="pa-paste-dismiss">Dismiss</button>
      </div>`;

    document.documentElement.appendChild(toast);
    const autoDismiss = setTimeout(() => toast.remove(), 15000);
    const dismiss = () => { clearTimeout(autoDismiss); toast.remove(); };

    document.getElementById('pa-paste-dismiss').addEventListener('click', dismiss);

    document.getElementById('pa-paste-clear').addEventListener('click', () => {
      if (targetElement) clearPaste(targetElement);
      dismiss();
    });

    document.getElementById('pa-paste-sanitize').addEventListener('click', () => {
      if (targetElement && pastedText) {
        applyToElement(targetElement, sanitizePastedText(pastedText));
      }
      dismiss();
    });
  }

  document.addEventListener('paste', (event) => {
    if (!protectionEnabled) return;
    if (!checkContext()) return;

    const target = event.target;
    const isEditable = target.isContentEditable ||
      target.tagName === 'TEXTAREA' ||
      (target.tagName === 'INPUT' && target.type !== 'password');

    if (!isEditable) return;

    const text = event.clipboardData?.getData('text') || '';
    if (!text || text.length < 8) return;

    // Snapshot pre-paste state — used by clearPaste() and applyToElement()
    if (target.isContentEditable) {
      target._paPreHTML = target.innerHTML;
    } else {
      target._paPrePasteValue = target.value;
    }

    const detections = detectSecretsInPaste(text);
    if (detections.length === 0) return;

    showPasteWarningToast(detections, target, text);
    safeSendMessage({
      type: 'PROMPTARMOR_PASTE_WARN',
      detections,
      url: window.location.href,
      origin: window.location.origin
    });
  }, true); // capture phase — runs before site handlers

  // ── Device Fingerprinting ─────────────────────────────────────────────────
  // generateFingerprint() is defined in deviceFingerprint.js (injected before
  // this file by manifest.json). Called once on page load; result sent to the
  // background worker which handles registration / new-device detection.

  function showNewDeviceToast(hash) {
    document.getElementById('promptarmor-device-toast')?.remove();
    const shortHash = hash ? hash.substring(0, 8) : '?';

    const toast = document.createElement('div');
    toast.id = 'promptarmor-device-toast';
    toast.innerHTML = `
      <style>
        #promptarmor-device-toast {
          position: fixed; bottom: 20px; right: 16px; z-index: 2147483647;
          background: #1f2937; border: 2px solid #3b82f6; border-radius: 12px;
          padding: 16px 20px; max-width: 360px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          animation: pa-dt-slidein 0.3s ease;
        }
        @keyframes pa-dt-slidein {
          from { transform: translateY(80px); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
        #promptarmor-device-toast .pa-dt-title {
          color: #3b82f6; font-weight: 700; font-size: 14px; margin-bottom: 6px;
        }
        #promptarmor-device-toast .pa-dt-body {
          color: #d1d5db; font-size: 12px; margin-bottom: 8px; line-height: 1.4;
        }
        #promptarmor-device-toast .pa-dt-hash {
          font-family: monospace; font-size: 11px; color: #6b7280;
          background: #374151; padding: 3px 8px; border-radius: 4px;
          display: inline-block; margin-bottom: 12px;
        }
        #promptarmor-device-toast .pa-dt-actions { display: flex; gap: 8px; }
        #promptarmor-device-toast button {
          padding: 6px 14px; border-radius: 6px; border: none;
          font-size: 12px; font-weight: 600; cursor: pointer;
        }
        #pa-dt-register { background: #3b82f6; color: #fff; }
        #pa-dt-dismiss  { background: #374151; color: #d1d5db; }
      </style>
      <div class="pa-dt-title">📱 New Device Detected</div>
      <div class="pa-dt-body">This browser/device profile hasn't been seen before. Register it as trusted if this is you.</div>
      <div class="pa-dt-hash">ID: ${shortHash}…</div>
      <div class="pa-dt-actions">
        <button id="pa-dt-register">Register Device</button>
        <button id="pa-dt-dismiss">Dismiss</button>
      </div>`;

    document.documentElement.appendChild(toast);
    const autoDismiss = setTimeout(() => toast.remove(), 20000);
    const dismiss = () => { clearTimeout(autoDismiss); toast.remove(); };

    document.getElementById('pa-dt-dismiss').addEventListener('click', dismiss);
    document.getElementById('pa-dt-register').addEventListener('click', () => {
      safeSendMessage({ type: 'PROMPTARMOR_REGISTER_DEVICE', hash });
      dismiss();
    });
  }

  // Send fingerprint to background once per page load
  if (typeof generateFingerprint === 'function') {
    generateFingerprint().then(fp => {
      if (!checkContext()) return;
      safeSendMessage({
        type:       'PROMPTARMOR_FINGERPRINT',
        hash:       fp.hash,
        components: fp.components
      });
    }).catch(e => console.warn('PromptArmor: fingerprint error', e));
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { scrapeVisibleText, isNodeVisible, createBlockingOverlay, removeOverlay, blockWindowAI, restoreWindowAI };
  }
})();