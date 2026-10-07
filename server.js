const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const STORAGE_DIR = process.env.STORAGE_DIR ? path.resolve(process.env.STORAGE_DIR) : DATA_DIR;
const UPLOAD_DIR = process.env.STORAGE_DIR ? path.join(STORAGE_DIR, 'uploads') : PUBLIC_UPLOAD_DIR;
const DATA_FILE = path.join(STORAGE_DIR, 'store.json');
const MASTER_PASSWORD = 'cat123123';
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
const ALLOWED_MIME_TYPES = new Map([
  ['image/jpeg', '.jpg'],
  ['image/png', '.png'],
  ['image/gif', '.gif'],
  ['image/webp', '.webp'],
  ['audio/webm', '.webm'],
  ['audio/ogg', '.ogg'],
  ['audio/wav', '.wav'],
  ['audio/mpeg', '.mp3'],
]);

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_UPLOAD_DIR, { recursive: true });
fs.mkdirSync(STORAGE_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify({ tickets: [], notes: [] }, null, 2));
}

function readStore() {
  const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!Array.isArray(parsed.tickets) || !Array.isArray(parsed.notes)) {
    throw new Error('Persistent store has an invalid format.');
  }
  return parsed;
}

function writeStore(store) {
  const temporaryFile = `${DATA_FILE}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(store, null, 2), 'utf8');
  fs.renameSync(temporaryFile, DATA_FILE);
}

function passwordIsValid(value) {
  if (typeof value !== 'string') return false;
  const supplied = Buffer.from(value);
  const expected = Buffer.from(MASTER_PASSWORD);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function saveAttachments(attachments) {
  if (attachments === undefined) return [];
  if (!Array.isArray(attachments)) {
    const error = new Error('Attachments must be an array.');
    error.status = 400;
    throw error;
  }

  const saved = [];
  const createdFiles = [];
  try {
    for (const attachment of attachments) {
      if (!attachment || typeof attachment.data !== 'string') {
        const error = new Error('Each attachment must include a Base64 data URL.');
        error.status = 400;
        throw error;
      }
      const match = attachment.data.match(/^data:(image\/(?:jpeg|png|gif|webp)|audio\/(?:webm|ogg|wav|mpeg));base64,([A-Za-z0-9+/]+={0,2})$/);
      if (!match) {
        const error = new Error('Attachment type or data URL is invalid.');
        error.status = 400;
        throw error;
      }

      const mimeType = match[1];
      const data = Buffer.from(match[2], 'base64');
      if (!data.length || data.length > MAX_ATTACHMENT_BYTES) {
        const error = new Error('Attachments must be between 1 byte and 10 MB.');
        error.status = 413;
        throw error;
      }

      const fileName = `${crypto.randomUUID()}${ALLOWED_MIME_TYPES.get(mimeType)}`;
      fs.writeFileSync(path.join(UPLOAD_DIR, fileName), data, { flag: 'wx' });
      createdFiles.push(fileName);
      saved.push({
        url: `/uploads/${fileName}`,
        mimeType,
        name: typeof attachment.name === 'string' ? attachment.name.slice(0, 200) : fileName,
      });
    }
    return { attachments: saved, createdFiles };
  } catch (error) {
    for (const fileName of createdFiles) {
      fs.rmSync(path.join(UPLOAD_DIR, fileName), { force: true });
    }
    throw error;
  }
}

app.use(express.json({ limit: '16mb' }));
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough: false, index: false }));

app.get('/api/tickets', (req, res, next) => {
  try {
    res.json(readStore().tickets);
  } catch (error) {
    next(error);
  }
});

app.post('/api/tickets', (req, res, next) => {
  try {
    const { moduleId, title, description = '', status = 'Open', priority = 'Medium' } = req.body || {};
    if (typeof moduleId !== 'string' || !moduleId.trim() || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ error: 'Module ID and title are required.' });
    }
    if (!['Open', 'In Progress', 'Resolved'].includes(status) ||
        !['Low', 'Medium', 'High', 'Critical'].includes(priority)) {
      return res.status(400).json({ error: 'Invalid ticket status or priority.' });
    }

    const store = readStore();
    const ticket = {
      id: crypto.randomUUID(),
      moduleId: moduleId.trim().slice(0, 100),
      title: title.trim().slice(0, 200),
      description: typeof description === 'string' ? description.trim().slice(0, 5000) : '',
      status,
      priority,
      createdAt: new Date().toISOString(),
    };
    store.tickets.push(ticket);
    writeStore(store);
    return res.status(201).json(ticket);
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/:moduleId', (req, res, next) => {
  try {
    const moduleId = req.params.moduleId;
    res.json(readStore().notes.filter((note) => note.moduleId === moduleId));
  } catch (error) {
    next(error);
  }
});

app.post('/api/notes/:moduleId', (req, res, next) => {
  let createdFiles = [];
  try {
    const { text = '' } = req.body || {};
    if (typeof text !== 'string' || text.length > 10000) {
      return res.status(400).json({ error: 'Note text must be a string of at most 10,000 characters.' });
    }
    const result = saveAttachments(req.body.attachments);
    createdFiles = result.createdFiles;
    if (!text.trim() && !result.attachments.length) {
      for (const fileName of createdFiles) fs.rmSync(path.join(UPLOAD_DIR, fileName), { force: true });
      return res.status(400).json({ error: 'Add note text or at least one attachment.' });
    }

    const store = readStore();
    const note = {
      id: crypto.randomUUID(),
      moduleId: req.params.moduleId,
      text: text.trim(),
      attachments: result.attachments,
      createdAt: new Date().toISOString(),
    };
    store.notes.push(note);
    writeStore(store);
    return res.status(201).json(note);
  } catch (error) {
    for (const fileName of createdFiles) fs.rmSync(path.join(UPLOAD_DIR, fileName), { force: true });
    return next(error);
  }
});

app.delete('/api/notes/:noteId', (req, res, next) => {
  const password = req.get('x-master-password') ?? req.body?.masterPassword;
  if (!passwordIsValid(password)) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }

  try {
    const store = readStore();
    const noteIndex = store.notes.findIndex((note) => note.id === req.params.noteId);
    if (noteIndex < 0) return res.status(404).json({ error: 'Note not found.' });

    const [note] = store.notes.splice(noteIndex, 1);
    writeStore(store);
    for (const attachment of note.attachments || []) {
      const fileName = path.basename(attachment.url || '');
      if (fileName) fs.rmSync(path.join(UPLOAD_DIR, fileName), { force: true });
    }
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/gallery', (req, res, next) => {
  try {
    const gallery = readStore().notes.flatMap((note) =>
      (note.attachments || [])
        .filter((attachment) => attachment.mimeType && attachment.mimeType.startsWith('image/'))
        .map((attachment) => ({
          ...attachment,
          noteId: note.id,
          moduleId: note.moduleId,
          createdAt: note.createdAt,
          text: note.text,
        })),
    );
    res.json(gallery);
  } catch (error) {
    next(error);
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) console.error(error);
  return res.status(status).json({ error: status >= 500 ? 'An internal server error occurred.' : error.message });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Product Testing & Audit Ticketing System listening on 0.0.0.0:${PORT}`);
});
