require('dotenv').config();

const express = require('express');
const { Firestore, Timestamp } = require('@google-cloud/firestore');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 5000);
const PROJECT_ID = process.env.GCP_PROJECT_ID || 'Extention';
const CREDENTIALS = process.env.GOOGLE_APPLICATION_CREDENTIALS || './service-account.json';
const SERVICE_ACCOUNT_JSON = process.env.GCP_SERVICE_ACCOUNT_JSON || '';
const FIRESTORE_COLLECTION = process.env.FIRESTORE_COLLECTION || 'reports';

function buildFirestoreConfig() {
  if (SERVICE_ACCOUNT_JSON) {
    try {
      return {
        projectId: PROJECT_ID,
        credentials: JSON.parse(SERVICE_ACCOUNT_JSON)
      };
    } catch (err) {
      throw new Error('Invalid GCP_SERVICE_ACCOUNT_JSON value');
    }
  }

  return {
    projectId: PROJECT_ID,
    keyFilename: CREDENTIALS
  };
}

const firestore = new Firestore(buildFirestoreConfig());

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
    const reportId = req.params.reportId;
    const doc = await firestore.collection(FIRESTORE_COLLECTION).doc(reportId).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Report not found' });
    }

    return res.json({ reportId: doc.id, ...doc.data() });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to read report' });
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  return res.status(500).json({ error: 'Unexpected server error' });
});

app.listen(PORT, () => {
  console.log(`Report server running on port ${PORT}`);
});
