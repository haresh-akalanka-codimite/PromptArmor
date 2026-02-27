require('dotenv').config();

const express = require('express');
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');
const { Storage }            = require('@google-cloud/storage');
const { Firestore, Timestamp } = require('@google-cloud/firestore');

const app = express();
app.use(express.json({ limit: '10mb' }));

// ── Config ────────────────────────────────────────────────────────────────────
const PORT               = Number(process.env.PORT || 5000);
const PROJECT_ID         = process.env.GCP_PROJECT_ID || 'extens-5bce0';
const CREDENTIALS        = process.env.GOOGLE_APPLICATION_CREDENTIALS || './service-account.json';
const BUCKET_NAME        = process.env.BUCKET_NAME || 'company-security-reports';
const FIRESTORE_COLLECTION = process.env.FIRESTORE_COLLECTION || 'reports';
const SIGNED_URL_TTL_MIN = Number(process.env.SIGNED_URL_TTL_MINUTES || 15);
const EXTENSION_API_KEY  = process.env.EXTENSION_API_KEY || '';

// ── CORS – allow Chrome extension origins + localhost dev ─────────────────────
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  // Allow all Chrome extensions and localhost callers
  if (
    origin.startsWith('chrome-extension://') ||
    origin.startsWith('http://localhost') ||
    origin.startsWith('http://127.0.0.1') ||
    origin === ''
  ) {
    res.setHeader('Access-Control-Allow-Origin',  origin || '*');
  }
  res.setHeader('Access-Control-Allow-Methods',  'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',  'Content-Type, X-Extension-Api-Key');
  res.setHeader('Access-Control-Max-Age',        '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── API key auth (applied to write endpoints only) ────────────────────────────
function requireApiKey(req, res, next) {
  // If no key is configured in .env, skip check (dev/local mode)
  if (!EXTENSION_API_KEY) return next();

  const provided =
    req.headers['x-extension-api-key'] ||   // preferred: header
    req.body?.extensionApiKey           ||   // fallback: body field
    '';

  if (provided !== EXTENSION_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized – invalid API key' });
  }
  next();
}

// ── GCS + Firestore clients ───────────────────────────────────────────────────
const storage   = new Storage({ projectId: PROJECT_ID, keyFilename: CREDENTIALS });
const firestore = new Firestore({ projectId: PROJECT_ID, keyFilename: CREDENTIALS });
const bucket    = storage.bucket(BUCKET_NAME);

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }   // 10 MB
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function cleanupTempFile(filePath) {
  if (!filePath) return;
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {
    console.error('cleanup error:', e.message);
  }
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/healthz', (_req, res) => {
  res.json({ ok: true, projectId: PROJECT_ID, bucket: BUCKET_NAME });
});

// ── POST /ingest-encrypted-report ─────────────────────────────────────────────
// Main endpoint used by the Chrome extension.
//
// Body (JSON):
//   tenantId          string   – org / tenant identifier (optional)
//   userEmail         string   – reporter's email (unencrypted, for Firestore indexing)
//   deviceHash        string   – device fingerprint hash  (unencrypted)
//   extensionId       string   – chrome.runtime.id
//   reportedAt        string   – ISO timestamp
//   eventCount        number   – number of security events in payload
//   fileName          string   – desired GCS filename (optional)
//   encryptedPayload  object   – { algorithm, iv, wrappedKey, ciphertext }
//   extensionApiKey   string   – auth key (can also be sent via X-Extension-Api-Key header)
//
// On success → { message, reportId, fileName }
app.post('/ingest-encrypted-report', requireApiKey, async (req, res) => {
  try {
    const {
      tenantId        = 'unknown',
      userEmail       = '',
      deviceHash      = '',
      extensionId     = '',
      reportedAt,
      eventCount,
      fileName,
      encryptedPayload
    } = req.body || {};

    // ── Validate encrypted payload ────────────────────────────────────────────
    if (
      !encryptedPayload ||
      !encryptedPayload.iv        ||
      !encryptedPayload.wrappedKey ||
      !encryptedPayload.ciphertext
    ) {
      return res.status(400).json({
        error: 'Missing encryptedPayload — iv, wrappedKey, and ciphertext are required'
      });
    }

    // ── Build GCS path ────────────────────────────────────────────────────────
    const safeTenant   = String(tenantId).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64);
    const finalFileName = (fileName && String(fileName).endsWith('.json'))
      ? String(fileName)
      : `promptarmor-report-${Date.now()}.json`;

    const objectPath = `encrypted-reports/${safeTenant}/${finalFileName}`;

    // ── Upload full request body (with encrypted payload) to GCS ─────────────
    const jsonBuffer = Buffer.from(JSON.stringify(req.body, null, 2), 'utf8');
    await bucket.file(objectPath).save(jsonBuffer, {
      contentType: 'application/json',
      resumable:   false,
      metadata: {
        metadata: {
          tenantId,
          source: 'promptarmor-extension',
          extensionId: extensionId || 'unknown'
        }
      }
    });

    // ── Save searchable metadata to Firestore ─────────────────────────────────
    // NOTE: only unencrypted fields land here — encrypted content stays in GCS.
    const docRef = await firestore.collection(FIRESTORE_COLLECTION).add({
      // identity / routing
      tenantId,
      userEmail,
      deviceHash,
      extensionId,
      // timing
      reportedAt:  reportedAt ? new Date(reportedAt) : Timestamp.now(),
      receivedAt:  Timestamp.now(),
      // content summary (for quick dashboard queries)
      eventCount:  typeof eventCount === 'number' ? eventCount : null,
      fileName:    objectPath,
      // security
      encryptionAlgorithm: encryptedPayload.algorithm || 'unknown',
      source: 'extension-encrypted-json'
    });

    console.log(`[report] stored → Firestore ${docRef.id} | GCS ${objectPath}`);

    return res.json({
      message:  'Encrypted report stored',
      reportId: docRef.id,
      fileName: objectPath
    });
  } catch (err) {
    console.error('[ingest-encrypted-report] error:', err);
    return res.status(500).json({ error: 'Ingest failed: ' + err.message });
  }
});

// ── POST /upload-report (multipart file upload) ───────────────────────────────
app.post('/upload-report', requireApiKey, upload.single('file'), async (req, res) => {
  const file   = req.file;
  const userId = String(req.body.userId || '').trim();

  if (!file || !userId) {
    cleanupTempFile(file?.path);
    return res.status(400).json({ error: 'Missing file or userId' });
  }

  try {
    const safeName    = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const gcsFileName = `reports/${userId}/report-${Date.now()}-${safeName}`;

    await bucket.upload(file.path, {
      destination: gcsFileName,
      contentType: file.mimetype || 'application/octet-stream',
      metadata: { metadata: { userId, originalName: file.originalname } }
    });

    const docRef = await firestore.collection(FIRESTORE_COLLECTION).add({
      userId,
      fileName:     gcsFileName,
      originalName: file.originalname,
      mimeType:     file.mimetype || 'application/octet-stream',
      sizeBytes:    file.size,
      createdAt:    Timestamp.now(),
      source:       'multipart-upload'
    });

    cleanupTempFile(file.path);
    return res.json({ message: 'Uploaded successfully', reportId: docRef.id, fileName: gcsFileName });
  } catch (err) {
    cleanupTempFile(file?.path);
    console.error(err);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// ── GET /report/:reportId – generate signed GCS download URL ─────────────────
app.get('/report/:reportId', async (req, res) => {
  try {
    const doc = await firestore.collection(FIRESTORE_COLLECTION).doc(req.params.reportId).get();
    if (!doc.exists) return res.status(404).json({ error: 'Report not found' });

    const { fileName } = doc.data();
    if (!fileName) return res.status(400).json({ error: 'Missing fileName in metadata' });

    const [signedUrl] = await bucket.file(fileName).getSignedUrl({
      version: 'v4',
      action:  'read',
      expires: Date.now() + SIGNED_URL_TTL_MIN * 60 * 1000
    });

    return res.json({ signedUrl, expiresInMinutes: SIGNED_URL_TTL_MIN });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to generate URL' });
  }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  if (err?.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large (max 10 MB)' });
  }
  console.error(err);
  return res.status(500).json({ error: 'Unexpected server error' });
});

app.listen(PORT, () => {
  console.log(`PromptArmor report server  →  http://localhost:${PORT}`);
  console.log(`  project  : ${PROJECT_ID}`);
  console.log(`  bucket   : ${BUCKET_NAME}`);
  console.log(`  collection: ${FIRESTORE_COLLECTION}`);
  console.log(`  api-key  : ${EXTENSION_API_KEY ? '*** set ***' : 'NOT SET (open mode)'}`);
});
