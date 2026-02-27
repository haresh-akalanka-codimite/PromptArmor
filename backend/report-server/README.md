# Report Server (Node + Express)

Production-style backend for PromptArmor reports with:

- Firestore metadata storage
- GCS file storage (private bucket)
- Signed URL generation
- Extension encrypted JSON ingest endpoint

> Firebase / GCP project name defaults to `Extention`.

## 1) GCP setup

### Create bucket
- Name: `company-security-reports`
- Region: nearest to your users
- Storage class: Standard
- Access control: Uniform
- Keep bucket private

### Create service account
Create service account `report-uploader` and assign at least:
- `Storage Object Admin`
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
- `BUCKET_NAME=company-security-reports`
- `FIRESTORE_COLLECTION=reports`
- `SIGNED_URL_TTL_MINUTES=15`

## 4) API endpoints

### Health
`GET /healthz`

### Upload file report (PDF/CSV/etc)
`POST /upload-report` (`multipart/form-data`)

Fields:
- `file`: file binary
- `userId`: user id

Flow:
1. Upload file to GCS
2. Save metadata to Firestore
3. Return `reportId`

### Ingest extension encrypted JSON
`POST /ingest-encrypted-report` (`application/json`)

Expected shape (minimum):

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

Flow:
1. Save request body JSON to GCS as file
2. Save metadata to Firestore
3. Return `reportId`

### Signed URL
`GET /report/:reportId`

Reads Firestore metadata and returns temporary signed URL from GCS.

## 5) Postman quick test

1. `POST http://localhost:5000/upload-report` with form-data:
   - `file`: choose PDF/CSV
   - `userId`: `123`
2. `GET http://localhost:5000/report/{reportId}`

## 6) Firestore structure

Collection `reports`:

- `userId` or `tenantId`
- `fileName`
- `createdAt`
- `source`
- optional file metadata

## 7) Security recommendations

- Add Firebase Auth / JWT verification middleware
- Validate user id from token (not from raw request)
- Restrict MIME types per endpoint
- Keep file-size limits (already set to 10MB)
- Configure bucket lifecycle rules
