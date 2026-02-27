require('dotenv').config();

const express = require('express');
const { Firestore, Timestamp } = require('@google-cloud/firestore');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 5000);
const PROJECT_ID = process.env.GCP_PROJECT_ID || 'Extention';
const CREDENTIALS = process.env.GOOGLE_APPLICATION_CREDENTIALS || './service-account.json';
const FIRESTORE_COLLECTION = process.env.FIRESTORE_COLLECTION || 'reports';

const firestore = new Firestore({
  projectId: PROJECT_ID,
  keyFilename: CREDENTIALS
});

app.get('/healthz', (_req, res) => {
  res.json({ ok: true, projectId: PROJECT_ID, collection: FIRESTORE_COLLECTION, storage: 'firestore-only' });
});

// Firestore-only endpoint: store encrypted report document directly.
app.post('/ingest-encrypted-report', async (req, res) => {
  try {
    const { tenantId = 'unknown', fileName, encryptedPayload } = req.body || {};

    if (!encryptedPayload || !encryptedPayload.iv || !encryptedPayload.wrappedKey || !encryptedPayload.ciphertext) {
      return res.status(400).json({ error: 'Missing encryptedPayload (iv, wrappedKey, ciphertext required)' });
    }

    const finalFileName = (fileName && String(fileName).endsWith('.json'))
      ? String(fileName)
      : `promptarmor-report-${Date.now()}.json`;

    const docRef = await firestore.collection(FIRESTORE_COLLECTION).add({
      tenantId,
      fileName: finalFileName,
      createdAt: Timestamp.now(),
      source: 'extension-encrypted-json',
      encryptionAlgorithm: encryptedPayload.algorithm || 'unknown',
      encryptedPayload: {
        iv: encryptedPayload.iv,
        wrappedKey: encryptedPayload.wrappedKey,
        ciphertext: encryptedPayload.ciphertext
      }
    });

    return res.json({
      message: 'Encrypted report stored in Firestore',
      reportId: docRef.id,
      fileName: finalFileName
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Ingest failed' });
  }
});

// Fetch stored encrypted report document by id.
app.get('/report/:reportId', async (req, res) => {
  try {
    const doc = await firestore.collection(FIRESTORE_COLLECTION).doc(req.params.reportId).get();
    if (!doc.exists) return res.status(404).json({ error: 'Report not found' });

    return res.json({ reportId: doc.id, ...doc.data() });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to read report' });
  }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
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
