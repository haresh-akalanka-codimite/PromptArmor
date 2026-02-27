# PromptArmor Full Detailed Collection Report

## Scope of this report
This document consolidates the security intelligence, extension-related risk models, network controls, and detection artifacts currently present in the PromptArmor codebase.

It is a **code-derived report** (what has been implemented/collected in source and tests so far), not a live endpoint telemetry export.

---

## 1) Extension permissions and attack-surface coverage

### 1.1 PromptArmor extension permissions (manifest)
PromptArmor currently requests the following permissions:

- `scripting`
- `storage`
- `activeTab`
- `tabs`
- `declarativeNetRequest`
- `sidePanel`
- `management`
- `downloads`

Host permissions currently include:
- `http://localhost:11434/*`

Interpretation:
- `management` enables inspection/scoring of installed extensions.
- `downloads` enables risky download evaluation and blocking.
- `declarativeNetRequest` enables static network blocking rules.

### 1.2 Extension risk scoring tiers (permission weights)
PromptArmor’s extension scorer uses weighted tiers:

- **Critical (30 points each):** `debugger`, `proxy`, `vpnProvider`, `webRequest`, `webRequestBlocking`
- **High (20 points each):** `cookies`, `history`, `bookmarks`, `downloads`, `nativeMessaging`, `management`
- **Medium (10 points each):** `tabs`, `storage`, `clipboardRead`, `clipboardWrite`, `geolocation`
- **Low (5 points each):** `activeTab`, `notifications`, `contextMenus`, `alarms`

Additional host-permission risk:
- `<all_urls>` or `*://*/*` adds 25 points
- More than 10 hosts adds 15 points

### 1.3 Enhanced sidepanel posture dimensions
The sidepanel’s multi-factor engine adds deeper extension posture dimensions:

1. Permission tier model (`critical/high/elevated/medium/low`)
2. Host scope blast radius (`<all_urls>`, `*://*/*`, broad HTTP/HTTPS, partial wildcards)
3. Dangerous permission combinations (attack chains)
4. Metadata & provenance checks (install type, update URL trust, homepage presence)
5. Behavioral heuristics (name/description mismatch against sensitive permissions)

---

## 2) Dangerous extension combinations collected so far

The following high-impact permission combinations are currently modeled:

- `webRequest` + `cookies` (traffic interception + cookie theft)
- `webRequestBlocking` + `cookies`
- `nativeMessaging` + `history`
- `debugger` + `tabs`
- `cookies` + `browsingData`
- `proxy` + `webRequest`
- `clipboardRead` + `tabs`
- `management` + `nativeMessaging`
- `identity` + `cookies`
- `downloads` + `nativeMessaging`

These combos are score-amplified and capped to prevent unlimited score inflation.

---

## 3) Suspicious extension code-pattern list

The static source-analysis list currently includes:

- `eval(...)`
- `new Function(...)`
- `document.write`
- `innerHTML =`
- `chrome.webRequest.onBeforeRequest`
- `XMLHttpRequest` or `fetch(...)`
- `btoa` / `atob`
- `localStorage` / `sessionStorage`
- `.execCommand`
- `window.open`
- `crypto.subtle`
- credential-like keywords (`password`, `secret`, `token`, `api key` patterns)
- known exfil endpoints (`webhook.site`, `requestbin`, `ngrok`)

---

## 4) Behavioral intelligence collection

### 4.1 Behavioral flags currently tracked
- `suspicious_network_call`
- `excessive_clipboard_access`
- `update_anomaly`
- `permission_escalation`
- `developer_reputation`
- `background_exfiltration`

### 4.2 Known exfiltration domains list
- `api.segment.io`
- `dc.services.visualstudio.com`
- `webhook.site`
- `requestbin.com`
- `pipedream.net`

### 4.3 Suspicious developer identity patterns
- Randomized Gmail-like sender format (`^[a-z]{8,12}\d{3,6}@gmail.com$`)
- `no-reply` / support-on-`.xyz`
- `unknown` / `anonymous`

### 4.4 Runtime behavioral indicators modeled
- Network calls to known exfil domains
- Excessive background fetches to unknown domains
- High-frequency clipboard reads (`clipboardRead` + >20 reads)
- Permission increases vs historical baseline
- Rapid update cadence (<1 day)
- Over-broad host permissions from normal install type

### 4.5 Enforcement recommendations generated from behavior
- Force remove via blocklist policy
- Freeze permissions via extension settings policy
- Pin version / disable updates via policy

---

## 5) Network/DNR blocking indicators collected so far

The static declarative ruleset currently blocks:

1. Query exfiltration patterns involving `prompt|query|text|message|content` with sensitive words (`password|ssn|credit card|secret`)
2. Generic exfiltration phrases (`exfil`, `leak data`, `steal info`)
3. Requests to `webhook.site`
4. Requests to `requestbin`
5. Requests to `ngrok.io`

Resource types covered include `xmlhttprequest`, `other`, and for certain rules also `image` and `script`.

---

## 6) Download-risk intelligence list

### 6.1 Risky file-extension list
- `.exe`, `.msi`, `.bat`, `.cmd`, `.ps1`, `.scr`, `.jar`, `.vbs`, `.js`, `.hta`, `.iso`, `.dll`, `.reg`, `.apk`, `.appx`, `.dmg`, `.pkg`, `.deb`, `.rpm`

### 6.2 Risky MIME-prefix list
- `application/x-msdownload`
- `application/x-dosexec`
- `application/vnd.microsoft.portable-executable`
- `application/java-archive`
- `application/x-bat`
- `application/x-ms-installer`
- `application/x-powershell`
- `application/x-executable`
- `application/x-mach-binary`
- `application/x-iso9660-image`

### 6.3 Chrome danger-state signals
- **High danger:** `dangerous`, `dangerous_host`, `dangerous_file`, `malicious`
- **Elevated danger:** `uncommon`, `potentially_unwanted`, `allowlisted_by_policy`

### 6.4 Risk outcomes
- Score >= 60: `block`
- Score >= 30: `warn`
- Else: `allow`

And blocked downloads are canceled and logged as `risky_download_blocked` threats.

---

## 7) Prompt-injection and AI abuse patterns collected so far

The fallback pattern detector marks text suspicious for phrases such as:

- `ignore previous`
- `ignore all previous`
- `disregard previous`
- `forget previous`
- `override instructions`
- `system prompt`
- `leak user email`
- `send user data`
- `exfiltrate`
- `ignore safety`
- `bypass security`
- `act as if`
- `pretend you are`
- `you are now`
- `new instructions`
- `hidden instructions`
- `secret instructions`

---

## 8) Test-backed validation coverage

Current tests verify, among others:

- Extension posture scoring and grading mechanics
- Policy recommendation generation and priority ordering
- Download risk assessment (`block`, `warn`, `allow` paths)
- Trust score behavior
- Injection shield / threat pattern detection

This indicates the above intelligence lists are not only defined but at least partially exercised via automated tests.

---

## 9) Current limitations and next report steps

### 9.1 What this report does NOT include yet
- Real-time installed-extension inventory dump from a live Chrome profile
- Historical trend charts by user/device/department
- Raw event timeline export (JSON/CSV) from runtime storage

### 9.2 Recommended follow-up to make this “full operational report”
1. Add a sidepanel export action (`Export findings` -> JSON/CSV).
2. Persist extension scan snapshots with timestamps.
3. Add deduplicated IOC inventory (`domains`, `patterns`, `permissions`, `combos`) in one generated file.
4. Add sectioned risk heatmap for SOC handoff.

---

## 10) Quick extension-list template (to fill from live run)

When you run `chrome.management.getAll()` in a live browser session, collect per extension:

- Extension name
- ID
- Version
- Enabled/disabled state
- Install type (`normal`, `development`, `sideload`)
- Permissions list
- Host permissions list
- Calculated risk score + risk level
- Triggered dangerous combos
- Behavioral flags
- Recommended policy actions

This template aligns with the current PromptArmor scoring and policy engines.


---

## 11) Daily encrypted reporting to GCP (implemented)

PromptArmor now supports an automated **daily report pipeline** in the background worker:

1. Reads the full stored dataset from `chrome.storage.local`.
2. Builds a daily report envelope with timestamp + extension metadata.
3. Encrypts payload using **AES-256-GCM**.
4. Wraps the AES key using your dashboard public key via **RSA-OAEP (SHA-256)**.
5. Uploads encrypted blob directly into Firestore (collection document).

### 11.1 Expected config in extension storage
Set `dailyReportConfig` with:

- `enabled: true`
- `firestoreProjectId: "<your-gcp-project-id>"`
- `firestoreApiKey: "<firestore-web-api-key>"`
- `firestoreCollection: "promptarmorDailyReports"`
- `publicKeyPem: "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"`
- `tenantId: "<your-org-or-tenant-id>"`
- `includeAllStorage: true` (default)

### 11.2 Scheduling
- Uses Chrome alarms with one alarm name: `promptarmor_daily_report`.
- Runs every 24 hours.
- Also re-applies schedule on startup/install.

### 11.3 Manual trigger support
The background worker accepts runtime message:
- `PROMPTARMOR_RUN_DAILY_REPORT`

This can be called from popup/sidepanel/admin action for immediate upload tests.

### 11.4 Dashboard decryption model (your end goal)
On your webapp backend:

1. Read document from Firestore and extract `encryptedPayload` (`wrappedKey`, `iv`, `ciphertext`).
2. Use your RSA private key to unwrap the AES key.
3. Decrypt ciphertext with AES-GCM using provided IV.
4. Parse JSON and present to admin dashboard.

This model keeps report contents unreadable in transit/storage without your private key.
