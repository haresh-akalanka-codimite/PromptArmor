# PromptArmor (scaffold)

Local scaffold for the PromptArmor Chrome extension (MV3).

Quick dev steps

```bash
# Install deps
npm ci

# Run unit tests
npm test

# Load unpacked extension in Chrome
# Open chrome://extensions, enable Developer mode, Load unpacked -> select this repository
```

Notes
- This scaffold contains placeholders for early TDD work. Implement features under `src/` and tests under `test/`.

E2E (local) - Puppeteer harness

The repository includes a local Puppeteer harness to test exfiltration behavior using a real Chromium instance and the extension.

Steps to run locally:

1. Install Puppeteer (recommended to do this locally because it's large):

```bash
npm install --save-dev puppeteer
```

2. Run the harness:

```bash
node test/e2e/run.js
```

What it does:
- Launches Chrome with this repository loaded as an unpacked extension.
- Opens the local test fixture `test/e2e/fixtures/malicious.html` which attempts to exfiltrate data to `malicious-server.com`.
- Logs network requests and page-reported status to help verify that DNR rules or extension blocking prevented exfiltration.

Notes:
- Running E2E requires a full Chromium and may prompt for permission. Close the launched browser when done.
- For CI, you can add Puppeteer to CI dependencies and run this script in a Linux runner with Chrome available.
