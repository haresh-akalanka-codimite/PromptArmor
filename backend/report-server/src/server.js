require('dotenv').config();

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { Storage } = require('@google-cloud/storage');
const { Firestore, Timestamp } = require('@google-cloud/firestore');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 5000);
const PROJECT_ID = process.env.GCP_PROJECT_ID || 'Extention';
const CREDENTIALS = process.env.GOOGLE_APPLICATION_CREDENTIALS || './service-account.json';
const BUCKET_NAME = process.env.BUCKET_NAME || 'company-security-reports';
const FIRESTORE_COLLECTION = process.env.FIRESTORE_COLLECTION || 'reports';
const SIGNED_URL_TTL_MINUTES = Number(process.env.SIGNED_URL_TTL_MINUTES || 15);

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }
});

const storage = new Storage({
  projectId: PROJECT_ID,
  keyFilename: CREDENTIALS
});

const firestore = new Firestore({
  projectId: PROJECT_ID,
  keyFilename: CREDENTIALS
});

const bucket = storage.bucket(BUCKET_NAME);

function cleanupTempFile(filePath) {
  if (!filePath) return;
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (err) {
    console.error('Failed to remove temp file:', err.message);
  }
}

app.get('/healthz', (_req, res) => {
  res.json({ ok: true, projectId: PROJECT_ID, bucket: BUCKET_NAME });
});

// Upload PDF/CSV/etc to GCS + Firestore metadata
app.post('/upload-report', upload.single('file'), async (req, res) => {
  const file = req.file;
  const userId = String(req.body.userId || '').trim();

  if (!file || !userId) {
    cleanupTempFile(file?.path);
    return res.status(400).json({ error: 'Missing file or userId' });
  }

  try {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const gcsFileName = `reports/${userId}/report-${Date.now()}-${safeName}`;

    await bucket.upload(file.path, {
      destination: gcsFileName,
      contentType: file.mimetype || 'application/octet-stream',
      metadata: {
        metadata: {
          userId,
          originalName: file.originalname
        }
      }
    });

    const docRef = await firestore.collection(FIRESTORE_COLLECTION).add({
      userId,
      fileName: gcsFileName,
      originalName: file.originalname,
      mimeType: file.mimetype || 'application/octet-stream',
      sizeBytes: file.size,
      createdAt: Timestamp.now(),
      source: 'multipart-upload'
    });

    cleanupTempFile(file.path);

    return res.json({
      message: 'Uploaded successfully',
      reportId: docRef.id,
      fileName: gcsFileName
    });
  } catch (err) {
    cleanupTempFile(file?.path);
    console.error(err);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// Best-method endpoint for extension JSON payloads (already encrypted client-side)
// Writes JSON file to GCS + metadata to Firestore.
app.post('/ingest-encrypted-report', async (req, res) => {
  try {
    const { tenantId = 'unknown', encryptedPayload, fileName } = req.body || {};

    if (!encryptedPayload || !encryptedPayload.iv || !encryptedPayload.wrappedKey || !encryptedPayload.ciphertext) {
      return res.status(400).json({ error: 'Missing encryptedPayload (iv, wrappedKey, ciphertext required)' });
    }

    const finalFileName = (fileName && String(fileName).endsWith('.json'))
      ? String(fileName)
      : `promptarmor-report-${Date.now()}.json`;

    const objectPath = `encrypted-reports/${tenantId}/${finalFileName}`;
    const jsonBuffer = Buffer.from(JSON.stringify(req.body, null, 2), 'utf8');

    await bucket.file(objectPath).save(jsonBuffer, {
      contentType: 'application/json',
      resumable: false,
      metadata: { metadata: { tenantId, source: 'promptarmor-extension' } }
    });

    const docRef = await firestore.collection(FIRESTORE_COLLECTION).add({
      tenantId,
      fileName: objectPath,
      createdAt: Timestamp.now(),
      source: 'extension-encrypted-json',
      encryptionAlgorithm: encryptedPayload.algorithm || 'unknown'
    });

    return res.json({
      message: 'Encrypted report stored',
      reportId: docRef.id,
      fileName: objectPath
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Ingest failed' });
  }
});

// Generate signed URL for report download
app.get('/report/:reportId', async (req, res) => {
  try {
    const reportId = req.params.reportId;
    const doc = await firestore.collection(FIRESTORE_COLLECTION).doc(reportId).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const { fileName } = doc.data();
    if (!fileName) return res.status(400).json({ error: 'Missing fileName in metadata' });

    const [signedUrl] = await bucket.file(fileName).getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + SIGNED_URL_TTL_MINUTES * 60 * 1000
    });

    return res.json({ signedUrl, expiresInMinutes: SIGNED_URL_TTL_MINUTES });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to generate URL' });
  }
});

app.use((err, _req, res, _next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large (max 10MB)' });
  }
  console.error(err);
  return res.status(500).json({ error: 'Unexpected server error' });
});

app.listen(PORT, () => {
  console.log(`Report server running on port ${PORT}`);
});
