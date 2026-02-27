// PromptArmor Popup Script

let enabled = true;

async function updateUI() {
  const toggle = document.getElementById('toggle');
  const indicator = document.getElementById('statusIndicator');
  const scoreBadge = document.getElementById('scoreBadge');

  if (enabled) {
    toggle.classList.add('on');
    indicator.classList.remove('off');
  } else {
    toggle.classList.remove('on');
    indicator.classList.add('off');
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.url || tab.url.startsWith('chrome://')) {
      scoreBadge.className = 'score-badge unknown';
      scoreBadge.innerHTML = '<span>N/A</span>';
      return;
    }

    // If protection is off, show disabled state instead of verdict
    if (!enabled) {
      scoreBadge.className = 'score-badge unknown';
      scoreBadge.innerHTML = '<span>⏸ Protection Off</span>';
      return;
    }

    const url = new URL(tab.url);
    const origin = url.origin;

    const result = await chrome.storage.local.get(['verdict_' + origin]);
    const data = result['verdict_' + origin];

    if (!data || data.verdict === 'UNKNOWN') {
      scoreBadge.className = 'score-badge unknown';
      scoreBadge.innerHTML = '<span>Analyzing...</span>';
    } else if (data.whitelisted) {
      scoreBadge.className = 'score-badge safe';
      scoreBadge.innerHTML = '<span>✅ Trusted</span>';
    } else if (data.verdict === 'YES') {
      scoreBadge.className = 'score-badge danger';
      scoreBadge.innerHTML = '<span>⚠️ Suspicious</span>';
    } else {
      scoreBadge.className = 'score-badge safe';
      scoreBadge.innerHTML = '<span>✅ Safe</span>';
    }
  } catch (error) {
    scoreBadge.className = 'score-badge unknown';
    scoreBadge.innerHTML = '<span>Error</span>';
  }
}

async function toggleProtection() {
  enabled = !enabled;

  // Save to storage — background.js and content.js both read this
  await chrome.storage.local.set({ settings: { enabled } });

  // Tell the active tab's content script immediately
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && !tab.url?.startsWith('chrome://')) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'PROMPTARMOR_SET_ENABLED',
        enabled
      }).catch(() => {}); // ignore if content script not injected
    }
  } catch (e) {}

  updateUI();
}

async function openSidePanel() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.windowId) {
      await chrome.sidePanel.open({ windowId: tab.windowId });
    }
  } catch (error) {
    console.error('Error opening side panel:', error);
  }
  window.close();
}

async function rescanPage() {
  if (!enabled) return; // Don't rescan when protection is off

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || tab.url?.startsWith('chrome://')) return;

    try {
      await chrome.tabs.sendMessage(tab.id, { type: 'PROMPTARMOR_RESCAN' });
    } catch (e) {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['src/content/content.js']
      });
    }
  } catch (error) {
    console.log('Rescan not available for this page');
  }

  setTimeout(updateUI, 500);
}

async function loadSettings() {
  const result = await chrome.storage.local.get(['settings']);
  if (result.settings) {
    enabled = result.settings.enabled !== false;
  }
  updateUI();
}

// ── Visit History ─────────────────────────────────────────────────────────────

function timeAgo(timestamp) {
  const diff = Date.now() - timestamp;
  const s = Math.floor(diff / 1000);
  if (s < 60)  return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60)  return m + 'm';
  const h = Math.floor(m / 60);
  if (h < 24)  return h + 'h';
  return Math.floor(h / 24) + 'd';
}

function verdictDotClass(verdict) {
  if (verdict === 'YES')         return 'suspicious';
  if (verdict === 'NO')          return 'safe';
  if (verdict === 'WHITELISTED') return 'whitelisted';
  if (verdict === 'PASTE_WARN')  return 'paste';
  return 'unknown';
}

function formatUrl(url) {
  try {
    const u = new URL(url);
    // Show host + truncated path
    const path = u.pathname.length > 20 ? u.pathname.substring(0, 18) + '…' : u.pathname;
    return u.hostname + (path === '/' ? '' : path);
  } catch {
    return url.substring(0, 40);
  }
}

async function loadHistory() {
  const list = document.getElementById('historyList');
  const result = await chrome.storage.local.get(['visitHistory']);
  const history = result.visitHistory || [];

  if (history.length === 0) {
    list.innerHTML = '<div class="history-empty">No visits recorded yet</div>';
    return;
  }

  list.innerHTML = history.slice(0, 50).map(entry => `
    <div class="history-item" title="${entry.url}">
      <span class="history-dot ${verdictDotClass(entry.verdict)}"></span>
      <span class="history-url">${formatUrl(entry.url)}</span>
      <span class="history-time">${timeAgo(entry.timestamp)}</span>
    </div>
  `).join('');
}

async function clearHistory() {
  await chrome.storage.local.remove(['visitHistory']);
  loadHistory();
}

// ── Device Status ──────────────────────────────────────────────────────────

async function loadDeviceStatus() {
  const chip    = document.getElementById('deviceChip');
  const label   = document.getElementById('deviceLabel');
  const hashEl  = document.getElementById('deviceHash');
  const countEl = document.getElementById('deviceCount');
  const forgetBtn = document.getElementById('forgetDeviceBtn');

  try {
    const result = await chrome.storage.local.get(['registeredDevices', 'currentDeviceHash']);
    const devices     = result.registeredDevices  || {};
    const currentHash = result.currentDeviceHash  || null;
    const total       = Object.keys(devices).length;

    if (total === 0) {
      chip.textContent  = 'No devices';
      chip.className    = 'device-chip unknown';
      label.textContent = 'No device registered yet';
      hashEl.textContent = '';
      countEl.textContent = '';
      forgetBtn.style.display = 'none';
      return;
    }

    // Is the current device registered?
    if (currentHash && devices[currentHash]) {
      const dev = devices[currentHash];
      chip.textContent  = 'Trusted';
      chip.className    = 'device-chip trusted';
      label.textContent = dev.label || 'Registered Device';
      hashEl.textContent = 'ID: ' + currentHash.substring(0, 16) + '…';
      countEl.textContent = total > 1 ? total + ' devices' : '';
      forgetBtn.style.display = 'block';

      forgetBtn.onclick = async () => {
        const r = await chrome.storage.local.get(['registeredDevices']);
        const d = r.registeredDevices || {};
        delete d[currentHash];
        await chrome.storage.local.set({ registeredDevices: d });
        loadDeviceStatus();
      };
    } else if (currentHash) {
      // Seen but not yet registered (user dismissed the toast without registering)
      chip.textContent  = 'New';
      chip.className    = 'device-chip new';
      label.textContent = 'Unregistered device';
      hashEl.textContent = 'ID: ' + currentHash.substring(0, 16) + '…';
      countEl.textContent = total + ' known';
      forgetBtn.style.display = 'none';
    } else {
      // No current hash stored yet (first open before any page visit)
      chip.textContent  = 'Detecting…';
      chip.className    = 'device-chip unknown';
      label.textContent = total + ' device' + (total !== 1 ? 's' : '') + ' registered';
      hashEl.textContent = '';
      countEl.textContent = '';
      forgetBtn.style.display = 'none';
    }
  } catch (e) {
    console.error('PromptArmor: loadDeviceStatus error', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadHistory();
  loadDeviceStatus();
  document.getElementById('toggle').addEventListener('click', toggleProtection);
  document.getElementById('openPanelBtn').addEventListener('click', openSidePanel);
  document.getElementById('rescanBtn').addEventListener('click', rescanPage);
  document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'PROMPTARMOR_UPDATE') {
    updateUI();
    loadHistory();       // refresh list when a new scan completes
    loadDeviceStatus();  // refresh device chip when fingerprint is processed
  }
});