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

    // Use full DOM text (including hidden/comments) so Gemini/API analysis can
    // catch indirect/hidden prompt injections that are not visibly rendered.
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
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(17, 24, 39, 0.18);
          z-index: 2147483647;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          box-sizing: border-box;
          padding: 16px;
        }
        #promptarmor-dialog {
          box-sizing: border-box;
          position: relative;
          width: min(450px, calc(100vw - 32px));
          min-height: 346px;
          background: #ffffff;
          box-shadow: 0 9px 7px rgba(0, 0, 0, 0.1);
          border-radius: 16px;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 20px;
          padding: 40px;
          text-align: center;
        }
        #promptarmor-icon {
          width: 60px;
          height: 60px;
          border-radius: 999px;
          background: #fecaca;
          border: 7px solid #fee2e2;
          display: flex;
          align-items: center;
          justify-content: center;
          color: #a20000;
        }
        #promptarmor-title {
          width: 100%;
          margin: 0;
          color: #1f2937;
          font-weight: 700;
          font-size: 20px;
          line-height: 1.2;
          letter-spacing: 0.005em;
        }
        #promptarmor-message {
          width: 100%;
          margin: 0;
          color: #6b7280;
          font-weight: 400;
          font-size: 16px;
          line-height: 1.5;
          letter-spacing: 0.005em;
        }
        #promptarmor-buttons {
          width: 100%;
          display: flex;
          gap: 40px;
          justify-content: center;
        }
        #promptarmor-buttons button {
          width: 142px;
          height: 36px;
          border-radius: 8px;
          border: 1px solid #e5e7eb;
          background: #ffffff;
          color: #1f2937;
          font-size: 14px;
          line-height: 20px;
          font-weight: 500;
          letter-spacing: 0.005em;
          cursor: pointer;
        }
        #promptarmor-evidence {
          max-width: 100%;
          color: #9ca3af;
          font-size: 12px;
          line-height: 1.4;
          word-break: break-word;
        }
      </style>
      <div id="promptarmor-dialog" role="alertdialog" aria-labelledby="promptarmor-title" aria-describedby="promptarmor-message">
        <div id="promptarmor-icon" aria-hidden="true">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 8V12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <path d="M12 16H12.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <path d="M10.29 3.85999L1.81999 18C1.64453 18.304 1.55157 18.6485 1.55029 18.9994C1.54901 19.3504 1.63946 19.6955 1.8127 20.0008C1.98594 20.306 2.23599 20.5608 2.538 20.7397C2.84001 20.9187 3.18358 21.0156 3.53499 21.02H20.465C20.8164 21.0156 21.16 20.9187 21.462 20.7397C21.764 20.5608 22.014 20.306 22.1873 20.0008C22.3605 19.6955 22.451 19.3504 22.4497 18.9994C22.4484 18.6485 22.3555 18.304 22.18 18L13.71 3.85999C13.5301 3.5642 13.277 3.31992 12.9751 3.15027C12.6732 2.98061 12.3327 2.89136 11.9864 2.89136C11.6402 2.89136 11.2997 2.98061 10.9978 3.15027C10.6959 3.31992 10.4428 3.5642 10.2629 3.85999H10.29Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <h2 id="promptarmor-title">High Risk Detected</h2>
        <p id="promptarmor-message">This page may attempt to manipulate AI behavior or access sensitive data. This has been reported to your administrator. Click Proceed to trust this site or Abort to close this tab.</p>
        <div id="promptarmor-buttons">
          <button id="promptarmor-whitelist">Proceed</button>
          <button id="promptarmor-dismiss">Abort</button>
        </div>
        <div id="promptarmor-evidence">${evidence || 'Suspicious content detected'}</div>
      </div>`;
    document.documentElement.appendChild(overlay);

    document.getElementById('promptarmor-dismiss').addEventListener('click', () => {
      // Record that user chose to abort and close this tab
      safeSendMessage({
        type:    'PROMPTARMOR_USER_ACTION',
        action:  'dismiss',
        context: 'injection',
        url:     window.location.href,
        origin:  window.location.origin
      });
      safeSendMessage({ type: 'PROMPTARMOR_CLOSE_TAB' });
      // Fallback for contexts where background tab-close is unavailable
      setTimeout(() => {
        try { window.close(); } catch (e) {}
      }, 50);
    });

    document.getElementById('promptarmor-whitelist').addEventListener('click', () => {
      safeSendMessage({ type: 'PROMPTARMOR_WHITELIST', origin: window.location.origin });
      // Record that user chose to trust this site despite the injection alert
      safeSendMessage({
        type:    'PROMPTARMOR_USER_ACTION',
        action:  'trust',
        context: 'injection',
        url:     window.location.href,
        origin:  window.location.origin
      });
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
    // PEM private key — real newlines or JSON \n-escaped
    { name: 'Private Key',
      re: /-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----/ },
    // Service-account / Firebase JSON
    { name: 'Service Account JSON',
      re: /"type"\s*:\s*"service_account"/ },
    { name: 'AWS Access Key',
      re: /(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/ },
    { name: 'GitHub Token',
      re: /(?:ghp_|github_pat_)[a-zA-Z0-9_]{20,}/ },
    { name: 'Slack Token',
      re: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
    { name: 'JWT Token',
      re: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/ },
    { name: 'Bearer Token',
      re: /Bearer\s+[a-zA-Z0-9_\-]{20,}/ },
    { name: 'Password Field',
      re: /(?:password|passwd|pwd)\s*[=:]\s*\S{4,}/i },
    { name: 'API Key',
      re: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:"]+\s*['"]?[a-zA-Z0-9_\-]{16,}/i },
    { name: 'Connection String',
      re: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s'"]+/ }
  ];

  // No \b word boundaries — underscores are \w so \bPRIVATE\b would NOT match
  // GOOGLE_PRIVATE_KEY. Substring match instead.
  const ENV_SENSITIVE_KEYS = /(SECRET|PASSWORD|TOKEN|PASS|PRIVATE|CREDENTIAL|DATABASE|APIKEY|AUTH|OAUTH|STRIPE|TWILIO|SENDGRID|FIREBASE|SUPABASE)/i;
  const ENV_LINE_RE = /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*.*$/gm;

  function detectSecretsInPaste(text) {
    if (!text || text.length < 8) return [];
    const found = [];
    for (const { name, re } of PASTE_SECRET_PATTERNS) {
      if (re.test(text)) found.push(name);
    }
    const envLines = text.match(ENV_LINE_RE) || [];
    const hasSensitiveKey = envLines.some(line => ENV_SENSITIVE_KEYS.test(line.split('=')[0]));
    if (hasSensitiveKey || envLines.length >= 4) {
      if (!found.includes('.env / Config File')) found.push('.env / Config File');
    }
    return found;
  }


  function redactEnvLine(line, forceRedact = false) {
    const m = line.match(/^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)([\s\S]*)$/);
    if (!m) return line;
    const [, prefix, key, sep, valueRaw] = m;
    const value = String(valueRaw || '').trim();

    const valueLooksSensitive =
      value.length >= 20 ||
      /(?:BEGIN\s+PRIVATE\s+KEY|Bearer\s+[A-Za-z0-9_\-]+|eyJ[A-Za-z0-9_\-]+\.)/i.test(value) ||
      /(?:mongodb|postgresql|mysql|redis):\/\//i.test(value);

    if (forceRedact || ENV_SENSITIVE_KEYS.test(key) || valueLooksSensitive) {
      return `${prefix}${key}${sep}[REDACTED]`;
    }

    return line;
  }

  // Redact secrets while keeping non-sensitive content intact.
  // Key names are preserved; only the secret values are replaced.
  function sanitizePastedText(text) {
    let r = text;

    // Full PEM block (RSA, EC, or plain PRIVATE KEY — also matches JSON \n-escaped form)
    r = r.replace(
      /-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----/g,
      '[PRIVATE_KEY_REDACTED]'
    );
    // PEM block when embedded in JSON strings (literal \n escapes instead of real newlines)
    r = r.replace(
      /-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----(?:\\n|\\r\\n|[^-])*-----END\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----/g,
      '[PRIVATE_KEY_REDACTED]'
    );
    // AWS key ID
    r = r.replace(/(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, '[AWS_KEY_REDACTED]');
    // GitHub token
    r = r.replace(/(?:ghp_|github_pat_)[a-zA-Z0-9_]{20,}/g, '[GITHUB_TOKEN_REDACTED]');
    // Slack token
    r = r.replace(/xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, '[SLACK_TOKEN_REDACTED]');
    // JWT
    r = r.replace(/eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[JWT_REDACTED]');
    // Bearer — keep prefix, redact value
    r = r.replace(/(Bearer\s+)[a-zA-Z0-9_\-]{20,}/g, '$1[TOKEN_REDACTED]');
    // Password field (KEY=value or KEY: value or "key": "value") — keep key, redact value
    r = r.replace(/((?:password|passwd|pwd)\s*(?:[=:]\s*|":\s*"))\S{4,}/gi, '$1[PASSWORD_REDACTED]');
    // API key — keep key name, redact value
    r = r.replace(/((?:api[_-]?key|apikey|api[_-]?secret)\s*(?:[=:]\s*|":\s*")['"]?)[a-zA-Z0-9_\-]{16,}/gi, '$1[API_KEY_REDACTED]');
    // Connection string — keep protocol, redact credentials/host
    r = r.replace(/((?:mongodb|postgresql|mysql|redis):\/\/)[^\s'"]+/gi, '$1[CONNECTION_REDACTED]');

    // Service-account / Firebase JSON: redact the value of known sensitive JSON keys
    // Matches: "private_key": "...", "client_email": "...", "client_id": "...", etc.
    r = r.replace(
      /("(?:private_key|private_key_id|client_secret|client_id|auth_token|refresh_token|access_token)"\s*:\s*")[^"]+(")/gi,
      '$1[REDACTED]$2'
    );

    const envLines = r.match(ENV_LINE_RE) || [];
    const shouldForceEnvRedact = envLines.length >= 3;

    // .env handling: if it looks like an env file, redact ALL values.
    // Otherwise, redact sensitive keys and suspiciously token-like values.
    r = r.replace(ENV_LINE_RE, line => redactEnvLine(line, shouldForceEnvRedact));

    return r;
  }

  // Insert text into a focused editable element at the current cursor position.
  // Called after event.preventDefault() blocked the original paste, so the
  // clipboard content never touched the editor DOM.
  function reinsertText(el, text) {
    try {
      el.focus();
      if (el.isContentEditable) {
        // execCommand works with ProseMirror, CodeMirror, Quill, etc.
        if (!document.execCommand('insertText', false, text)) {
          // Fallback: insert at the current Selection range
          const sel = window.getSelection();
          if (sel && sel.rangeCount > 0) {
            const range = sel.getRangeAt(0);
            range.deleteContents();
            range.insertNode(document.createTextNode(text));
            range.collapse(false);
            sel.removeAllRanges();
            sel.addRange(range);
          } else {
            el.textContent += text;
          }
          el.dispatchEvent(new InputEvent('input', {
            bubbles: true, data: text, inputType: 'insertText'
          }));
        }
      } else {
        // <textarea> or <input>: insert at the cursor position
        const start = el.selectionStart != null ? el.selectionStart : el.value.length;
        const end   = el.selectionEnd   != null ? el.selectionEnd   : el.value.length;
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + text.length;
        el.dispatchEvent(new Event('input', { bubbles: true }));
      }
    } catch (e) {
      // Last-resort: just append
      try { el.textContent += text; } catch (_) {}
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
          padding: 16px 20px; max-width: 400px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          animation: pa-slidein 0.25s ease;
        }
        @keyframes pa-slidein {
          from { transform: translateX(420px); opacity: 0; }
          to   { transform: translateX(0);     opacity: 1; }
        }
        #promptarmor-paste-toast .pa-title {
          color: #ef4444; font-weight: 700; font-size: 14px; margin-bottom: 6px;
        }
        #promptarmor-paste-toast .pa-body {
          color: #d1d5db; font-size: 12px; margin-bottom: 10px; line-height: 1.5;
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
          padding: 7px 14px; border-radius: 6px; border: none;
          font-size: 12px; font-weight: 600; cursor: pointer;
        }
        #pa-paste-sanitize { background: #f59e0b; color: #000; }
        #pa-paste-clear    { background: #ef4444; color: #fff; }
        #pa-paste-allow    { background: #374151; color: #d1d5db; }
      </style>
      <div class="pa-title">🔐 PromptArmor: Secret Detected — Paste Blocked</div>
      <div class="pa-body">
        The paste was <strong style="color:#ef4444">blocked</strong> before it reached the editor.
        Choose how to proceed:
      </div>
      <div class="pa-tags">${detections.map(d => `<span class="pa-tag">${d}</span>`).join('')}</div>
      <div class="pa-actions">
        <button id="pa-paste-sanitize">Sanitize &amp; Insert</button>
        <button id="pa-paste-clear">Discard</button>
        <button id="pa-paste-allow">Allow Anyway</button>
      </div>`;

    document.documentElement.appendChild(toast);
    const autoDismiss = setTimeout(() => toast.remove(), 20000);
    const dismiss = () => { clearTimeout(autoDismiss); toast.remove(); };

    // "Discard" — paste was already blocked; do nothing, just close
    document.getElementById('pa-paste-clear').addEventListener('click', dismiss);

    // "Allow Anyway" — re-insert the original unmodified text
    document.getElementById('pa-paste-allow').addEventListener('click', () => {
      if (targetElement && pastedText) reinsertText(targetElement, pastedText);
      dismiss();
    });

    // "Sanitize & Insert" — re-insert with secrets redacted
    document.getElementById('pa-paste-sanitize').addEventListener('click', () => {
      if (targetElement && pastedText) {
        reinsertText(targetElement, sanitizePastedText(pastedText));
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

    const detections = detectSecretsInPaste(text);
    if (detections.length === 0) return;

    // ── Block the paste BEFORE it touches the editor DOM ──────────────────────
    // This is the critical fix: by preventing default here (capture phase,
    // before any site handler), the clipboard content never lands in the input.
    // "Clear/Discard" then requires no undo at all — the secret was never there.
    event.preventDefault();
    event.stopPropagation();

    showPasteWarningToast(detections, target, text);
    safeSendMessage({
      type: 'PROMPTARMOR_PASTE_WARN',
      detections,
      url: window.location.href,
      origin: window.location.origin
    });
  }, true); // capture phase — runs before ALL site handlers

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
