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


## Download Risk Protection (MV3)

PromptArmor now monitors file downloads via the Chrome Downloads API and performs layered risk checks:
- File extension risk (e.g. `.exe`, `.msi`, `.bat`, `.jar`, `.iso`).
- MIME risk (e.g. `application/x-msdownload`, PE / installer / executable MIME families).
- Chrome Safe Browsing danger signal (`dangerous`, `uncommon`, `potentially_unwanted`, etc.).
- Transport signal (`http://` download source increases risk).

Behavior:
- High risk: PromptArmor cancels the download and records a `risky_download_blocked` threat.
- Medium risk: PromptArmor records a `risky_download_warn` threat.
- Updates are emitted through runtime messages as `DOWNLOAD_RISK` verdicts.



## Daily Encrypted Report Upload (GCP-ready)

PromptArmor supports daily export of stored extension telemetry to your cloud endpoint.

Configuration key in `chrome.storage.local`:

```json
{
  "dailyReportConfig": {
    "enabled": true,
    "firestoreProjectId": "your-gcp-project-id",
    "firestoreApiKey": "your-firestore-web-api-key",
    "firestoreCollection": "promptarmorDailyReports",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
    "tenantId": "your-tenant",
    "includeAllStorage": true
  }
}
```

Behavior:
- Collects stored data daily via Chrome alarms.
- Encrypts report with AES-256-GCM.
- Wraps AES key with RSA-OAEP(SHA-256) using your public key.
- Uploads encrypted payload directly to Firestore collection documents so only your dashboard backend can decrypt with private key.


## Report backend (Firestore + GCS)

A separate production-style Node/Express backend is available at `backend/report-server` for file uploads, Firestore metadata, and signed URL retrieval. See `backend/report-server/README.md`.
