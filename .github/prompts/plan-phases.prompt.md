# PromptArmor - TDD Implementation Plan

## Overview
PromptArmor is a Chrome Extension (MV3) that prevents prompt injection attacks on AI-powered websites using Gemini Nano for local analysis.

## Current Status: ✅ Implementation Complete (v1.0.0)

### Architecture
```
src/
├── background/
│   └── background.js     # Service worker - Sentinel logic, AI analysis
├── content/
│   └── content.js        # DOM scraping, blocking overlay, MutationObserver
├── sidepanel/
│   ├── sidepanel.html    # Trust Score UI
│   └── sidepanel.js      # Side panel logic
├── popup/
│   ├── popup.html        # Extension popup
│   └── popup.js          # Popup controls
├── rules/
│   └── rules.json        # DNR blocking rules
└── utils/
    ├── aiAdapter.js      # Gemini Nano integration, PII redaction
    └── trustScore.js     # Score calculation algorithm

test/
├── setupMocks.js         # Chrome API & window.ai mocks
├── aiAdapter.test.js     # AI adapter unit tests
├── trustScore.test.js    # Trust score calculation tests
├── content.test.js       # Content script tests
└── dnrRules.test.js      # DNR rules validation tests
```

## Key Features

### 1. AI-Powered Analysis (Gemini Nano)
- Uses `window.ai.languageModel` for local, private scanning
- PII redaction before analysis (email, SSN, credit cards, phone numbers)
- Fail-closed behavior: blocks on errors or timeout
- Pattern-based fallback when AI unavailable

### 2. Content Script Protection
- Scrapes visible text from DOM
- Creates full-screen blocking overlay on threat detection
- Monitors DOM changes via MutationObserver
- Blocks access to `window.ai` when threats detected

### 3. Trust Score System
- 0-100 score based on analysis results
- Levels: SAFE (green), CAUTION (yellow), DANGER (red)
- Factors: verdict, flag count, DNR blocks, whitelist status

### 4. Declarative Net Request (DNR)
- Blocks known exfiltration endpoints (webhook.site, requestbin, ngrok)
- Blocks requests with sensitive parameters
- Real-time network protection

### 5. Side Panel UI
- Displays current page trust score
- Shows evidence snippets
- Whitelist and rescan controls

---

## Phase-by-Phase Implementation Plan (A -> J)

### Phase A - Scaffold & Manifest (MV3) ✅ COMPLETE
- [x] Created repo skeleton and folder structure
- [x] Created `manifest.json` with MV3 fields
- [x] Permissions: scripting, storage, activeTab, tabs, sidePanel, declarativeNetRequest
- Files: `manifest.json`, `package.json`, folder structure

### Phase B - Testing Environment ✅ COMPLETE
- [x] Jest & jsdom configured
- [x] Chrome API mocks in `test/setupMocks.js`
- Files: `jest.config.js`, `test/setupMocks.js`

### Phase C - Content Script (TDD) ✅ COMPLETE
- [x] Visible text scraping via TreeWalker
- [x] MutationObserver for dynamic content
- [x] Blocking overlay UI
- [x] window.ai interception
- Files: `src/content/content.js`, `test/content.test.js`

### Phase D - Sentinel Background (TDD + Gemini Nano) ✅ COMPLETE
- [x] Background service worker
- [x] AI adapter with PII redaction
- [x] Fail-closed error handling
- [x] Storage-based verdict persistence
- Files: `src/background/background.js`, `src/utils/aiAdapter.js`

### Phase E - Gatekeeper & Warning UI ✅ COMPLETE
- [x] Blocking overlay on high-risk detection
- [x] Evidence display in overlay
- [x] Whitelist functionality
- Files: `src/content/content.js` (integrated)

### Phase F - Side Panel Trust Score ✅ COMPLETE
- [x] Side panel HTML/JS
- [x] Trust score calculator
- [x] Real-time updates on storage changes
- Files: `src/sidepanel/*`, `src/utils/trustScore.js`

### Phase G - Declarative Net Request ✅ COMPLETE
- [x] DNR rules for exfiltration blocking
- [x] Blocks webhook.site, requestbin, ngrok
- [x] Blocks sensitive query parameters
- Files: `src/rules/rules.json`, `test/dnrRules.test.js`

### Phase H - Integration & E2E 🔄 IN PROGRESS
- [x] E2E harness setup
- [ ] Attack scenario test pages
- [ ] Full E2E test suite

### Phase I - CI/CD on GCP ✅ COMPLETE
- [x] Cloud Build configuration
- Files: `cloudbuild.yaml`

### Phase J - Packaging & Release 🔄 PENDING
- [ ] Security review
- [ ] Documentation
- [ ] Chrome Web Store submission

---

## Running the Extension

### Installation
```bash
npm install
```

### Run Tests
```bash
npm test
```

### Load in Chrome
1. Go to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the project folder

### Enable Gemini Nano
1. Go to `chrome://flags/#optimization-guide-on-device-model`
2. Set to "Enabled BypassPerfRequirement"
3. Go to `chrome://flags/#prompt-api-for-gemini-nano`
4. Set to "Enabled"
5. Restart Chrome

---

## Security Model

### Fail-Closed Behavior
- If AI analysis fails -> treat as suspicious
- If timeout occurs -> treat as suspicious
- If no AI available -> use pattern matching fallback

### PII Protection
- All text is redacted before sending to AI
- Patterns: email, SSN, credit cards, phone, zip codes

### Attack Patterns Detected
- "ignore previous instructions"
- "system prompt injection"
- "leak user data/email"
- "exfiltrate information"
- Zero-width character injections
- Hidden DOM elements with malicious content

---

## Version History

### v1.0.0 (Current)
- Complete rewrite with clean architecture
- Modular file structure
- Comprehensive test coverage
- Full Gemini Nano integration
- Side panel trust score display
- DNR-based network protection
