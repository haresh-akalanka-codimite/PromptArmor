# Report Server (Node + Express, Firestore-only)

This backend is now **Firestore-only** (no GCS dependency).

It stores encrypted report JSON metadata/payload directly in Firestore documents.

> Firebase / GCP project name defaults to `Extention`.

## Why this change?

If your architecture only needs Firestore, then these are **not required**:
- `@google-cloud/storage`
- GCS bucket config (`BUCKET_NAME`)
- Signed URL generation code
- multipart file upload flow for local temp files

So the server is simplified to Firestore ingestion + read APIs.

## 1) Service account

Create service account (example: `report-uploader`) and grant:
- `Cloud Datastore User`

Download JSON key and place it as:

```txt
backend/report-server/service-account.json
```

Do not commit it.

## 2) Install and run

```bash
cd backend/report-server
npm install
cp .env.example .env
npm run start
```

Server starts on `http://localhost:5000` by default.

## 3) Environment

Use `.env` (see `.env.example`):

- `PORT=5000`
- `GOOGLE_APPLICATION_CREDENTIALS=./service-account.json`
- `GCP_PROJECT_ID=Extention`
- `FIRESTORE_COLLECTION=reports`
- `GEMINI_API_KEY=...` (required only for `/analyze`)


### Windows credential path

If your key is at:

`C:\test\PromptArmor\backend\report-server\service-account.json`

set in `.env`:

```env
GOOGLE_APPLICATION_CREDENTIALS=C:\test\PromptArmor\backend\report-server\service-account.json
```

You can also avoid file-path issues by using `GCP_SERVICE_ACCOUNT_JSON` (raw JSON string) instead of `GOOGLE_APPLICATION_CREDENTIALS`.


## 4) API endpoints

### Health
`GET /healthz`

### Ingest extension encrypted JSON
`POST /ingest-encrypted-report` (`application/json`)

Expected minimum payload:

```json
{
  "tenantId": "org-1",
  "fileName": "promptarmor-report-20260101.json",
  "encryptedPayload": {
    "algorithm": "RSA-OAEP-256/AES-256-GCM",
    "iv": "...",
    "wrappedKey": "...",
    "ciphertext": "..."
  }
}
```

### Get report by id
`GET /report/:reportId`

Returns document data from Firestore.


### Analyze text with Gemini Flash
`POST /analyze` (`application/json`)

Body:

```json
{
  "text": "Analyze this risky download URL: example.com/malware.exe"
}
```

Response:

```json
{
  "result": "VERDICT: NO\nREASON: ..."
}
```

> Keep your `GEMINI_API_KEY` only in backend `.env` and never embed it in extension/client code.

## 5) Firestore structure

Collection `reports` document fields include:
- `tenantId`
- `fileName`
- `createdAt`
- `source`
- `encryptionAlgorithm`
- `encryptedPayload.iv`
- `encryptedPayload.wrappedKey`
- `encryptedPayload.ciphertext`
