const express = require('express');
require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');
const multer = require('multer');
const AdmZip = require('adm-zip');
const mongoose = require('mongoose');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PUBLIC_UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
const PUBLIC_IMAGE_DIR = path.join(PUBLIC_DIR, 'images');
const STORAGE_DIR = process.env.STORAGE_DIR ? path.resolve(process.env.STORAGE_DIR) : DATA_DIR;
const UPLOAD_DIR = process.env.STORAGE_DIR ? path.join(STORAGE_DIR, 'uploads') : PUBLIC_UPLOAD_DIR;
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGODB_ATLAS_URI;
const MASTER_PASSWORD = 'cat123123';
const DEFAULT_USERNAME = 'Admin';
const DEFAULT_PASSWORD = 'admin@123#';
const DEFAULT_PRODUCT = 'SiyanoAV Total Security';
const TICKET_STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed'];
const TICKET_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SUPPORTED_PRODUCTS = [
  DEFAULT_PRODUCT,
  'Sentinel AVPro',
  'Sentinel Endpoint Protection',
  'Mobile Security',
  'Endpoint Protection',
  'Cloud Shield',
];
const PASSWORD_HASH_BYTES = 64;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILES_PER_NOTE = 8;
const MAX_BACKUP_SIZE = 250 * 1024 * 1024;
const MAX_BACKUP_CONTENT_SIZE = 500 * 1024 * 1024;
const MAX_BACKUP_ENTRIES = 5000;

for (const directory of [DATA_DIR, PUBLIC_UPLOAD_DIR, PUBLIC_IMAGE_DIR, STORAGE_DIR, UPLOAD_DIR]) {
  fs.mkdirSync(directory, { recursive: true });
}

const files = {
  users: path.join(STORAGE_DIR, 'users.json'),
  tickets: path.join(STORAGE_DIR, 'tickets.json'),
  notes: path.join(STORAGE_DIR, 'notes.json'),
  legacy: path.join(STORAGE_DIR, 'store.json'),
  secret: path.join(STORAGE_DIR, 'auth-secret'),
};

const MIME_EXTENSIONS = new Map([
  ['image/png', '.png'],
  ['image/jpeg', '.jpg'],
  ['image/webp', '.webp'],
  ['application/pdf', '.pdf'],
  ['audio/webm', '.webm'],
  ['audio/ogg', '.ogg'],
  ['audio/mp4', '.m4a'],
  ['audio/mpeg', '.mp3'],
  ['audio/wav', '.wav'],
  ['audio/x-wav', '.wav'],
]);
const EXTENSION_MIMES = new Map([...MIME_EXTENSIONS].map(([mime, extension]) => [extension, mime]));

const activityLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  statusFrom: String,
  statusTo: String,
  performedBy: { type: String, required: true },
  timestamp: { type: Date, required: true },
}, { _id: false });
const ticketSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: String,
  severity: String,
  riskRating: String,
  product: String,
  activityLog: { type: [activityLogSchema], default: [] },
}, {
  strict: false,
  versionKey: false,
  collection: 'tickets',
});
const Ticket = mongoose.models.Ticket || mongoose.model('Ticket', ticketSchema);
const migrationSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  completedAt: { type: Date, required: true },
}, { versionKey: false, collection: 'migrations' });
const Migration = mongoose.models.Migration || mongoose.model('Migration', migrationSchema);

function atomicWriteJson(filePath, value) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  try {
    fs.renameSync(temporaryPath, filePath);
  } catch (error) {
    fs.rmSync(temporaryPath, { force: true });
    throw error;
  }
}

function readJson(filePath, defaultValue) {
  if (!fs.existsSync(filePath)) return defaultValue;
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return parsed;
}

function createTicketId(existingTickets) {
  let id;
  do {
    id = `TCK-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  } while (existingTickets.some((ticket) => ticket.id === id));
  return id;
}

function normalizeTicketProducts(tickets) {
  let changed = false;
  const normalizedTickets = tickets.map((ticket) => {
    if (!ticket || typeof ticket !== 'object' || Array.isArray(ticket)) {
      const error = new Error('Ticket data must contain objects.');
      error.status = 400;
      throw error;
    }
    if (ticket.product === undefined || ticket.product === null || ticket.product === '') {
      changed = true;
      return { ...ticket, product: DEFAULT_PRODUCT };
    }
    if (!SUPPORTED_PRODUCTS.includes(ticket.product)) {
      const error = new Error(`Unsupported ticket product: ${ticket.product}`);
      error.status = 400;
      throw error;
    }
    return ticket;
  });
  return { tickets: normalizedTickets, changed };
}

function normalizeTicketActivityLogs(tickets) {
  let changed = false;
  const normalizedTickets = tickets.map((ticket) => {
    if (ticket.activityLog === undefined) {
      changed = true;
      return { ...ticket, activityLog: [] };
    }
    if (!Array.isArray(ticket.activityLog)) {
      const error = new Error('Ticket activity logs must contain arrays.');
      error.status = 400;
      throw error;
    }
    for (const event of ticket.activityLog) {
      if (!event || typeof event !== 'object' || Array.isArray(event)
        || !['status_changed', 'severity_changed', 'product_changed'].includes(event.action)
        || (event.statusFrom !== null && typeof event.statusFrom !== 'string')
        || (event.statusTo !== null && typeof event.statusTo !== 'string')
        || typeof event.performedBy !== 'string' || !event.performedBy.trim()
        || typeof event.timestamp !== 'string' || !Number.isFinite(Date.parse(event.timestamp))) {
        const error = new Error('Ticket activity log contains an invalid event.');
        error.status = 400;
        throw error;
      }
    }
    return ticket;
  });
  return { tickets: normalizedTickets, changed };
}

function appendTicketActivity(ticket, action, statusFrom, statusTo, performedBy, timestamp) {
  if (!Array.isArray(ticket.activityLog)) ticket.activityLog = [];
  ticket.activityLog.push({ action, statusFrom, statusTo, performedBy, timestamp });
}

function canonicalTicketStatus(value) {
  if (typeof value !== 'string') return null;
  return TICKET_STATUSES.find((status) => normalizedTicketStatus(status) === normalizedTicketStatus(value)) || null;
}

function canonicalTicketSeverity(value) {
  if (typeof value !== 'string') return null;
  const severity = value.trim().toLocaleUpperCase();
  return TICKET_SEVERITIES.includes(severity) ? severity : null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return {
    salt,
    passwordHash: crypto.scryptSync(password, salt, PASSWORD_HASH_BYTES).toString('hex'),
  };
}

function passwordMatches(password, user) {
  if (typeof password !== 'string' || !user || typeof user.passwordHash !== 'string') return false;
  const supplied = crypto.scryptSync(password, user.salt, PASSWORD_HASH_BYTES);
  const expected = Buffer.from(user.passwordHash, 'hex');
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function masterPasswordMatches(password) {
  if (typeof password !== 'string') return false;
  const supplied = Buffer.from(password);
  const expected = Buffer.from(MASTER_PASSWORD);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function newDefaultUsers() {
  return [{
    username: DEFAULT_USERNAME,
    role: 'admin',
    ...hashPassword(DEFAULT_PASSWORD),
    createdAt: new Date().toISOString(),
  }];
}

function legacyData() {
  try {
    const legacy = readJson(files.legacy, { tickets: [], notes: [] });
    return {
      tickets: Array.isArray(legacy.tickets) ? legacy.tickets : [],
      notes: Array.isArray(legacy.notes) ? legacy.notes : [],
    };
  } catch (error) {
    console.error(`Unable to read legacy store for migration: ${error.message}`);
    return { tickets: [], notes: [] };
  }
}

const legacy = legacyData();
let initialTickets = readJson(files.tickets, null);
let initialNotes = readJson(files.notes, null);
if (!initialTickets || !initialNotes) {
  const moduleIds = new Map();
  if (!initialTickets) {
    initialTickets = [];
    for (const ticket of legacy.tickets) {
      const converted = {
        id: createTicketId(initialTickets),
        product: DEFAULT_PRODUCT,
        title: typeof ticket.title === 'string' ? ticket.title : 'Legacy audit ticket',
        description: typeof ticket.description === 'string' ? ticket.description : '',
        status: 'Open',
        createdAt: ticket.createdAt || new Date().toISOString(),
        author: 'Legacy import',
      };
      if (typeof ticket.moduleId === 'string') moduleIds.set(ticket.moduleId, converted.id);
      initialTickets.push(converted);
    }
  }
  if (!initialNotes) {
    initialNotes = legacy.notes.flatMap((note) => {
      const ticketId = moduleIds.get(note.moduleId);
      if (!ticketId) return [];
      const attachments = Array.isArray(note.attachments) ? note.attachments.flatMap((attachment) => {
        const fileName = path.basename(attachment.url || '');
        if (!fileName || !fs.existsSync(path.join(UPLOAD_DIR, fileName))) return [];
        return [{
          fileName,
          name: typeof attachment.name === 'string' ? attachment.name : fileName,
          mimeType: attachment.mimeType || EXTENSION_MIMES.get(path.extname(fileName)) || 'application/octet-stream',
          size: fs.statSync(path.join(UPLOAD_DIR, fileName)).size,
        }];
      }) : [];
      return [{
        id: note.id || crypto.randomUUID(),
        ticketId,
        text: typeof note.text === 'string' ? note.text : '',
        attachments,
        createdAt: note.createdAt || new Date().toISOString(),
        updatedAt: note.createdAt || new Date().toISOString(),
        author: 'Legacy import',
      }];
    });
  }
  if (!fs.existsSync(files.tickets)) atomicWriteJson(files.tickets, initialTickets);
  if (!fs.existsSync(files.notes)) atomicWriteJson(files.notes, initialNotes);
}
if (!Array.isArray(initialTickets) || !Array.isArray(initialNotes)) {
  throw new Error('Tickets and notes storage must contain JSON arrays.');
}
const normalizedInitialTickets = normalizeTicketProducts(initialTickets);
const normalizedInitialActivityLogs = normalizeTicketActivityLogs(normalizedInitialTickets.tickets);
initialTickets = normalizedInitialActivityLogs.tickets;
if (normalizedInitialTickets.changed || normalizedInitialActivityLogs.changed) {
  atomicWriteJson(files.tickets, initialTickets);
}

const storedUsers = readJson(files.users, []);
let users = Array.isArray(storedUsers) ? storedUsers : [];
const storedDefaultAdmin = users.find((user) =>
  typeof user.username === 'string' && user.username.toLowerCase() === DEFAULT_USERNAME.toLowerCase(),
);
const defaultAdmin = storedDefaultAdmin && passwordMatches(DEFAULT_PASSWORD, storedDefaultAdmin)
  ? storedDefaultAdmin
  : newDefaultUsers()[0];
users = [defaultAdmin, ...users.filter((user) =>
  typeof user.username === 'string' && user.username.toLowerCase() !== DEFAULT_USERNAME.toLowerCase(),
)];
if (!Array.isArray(storedUsers) || !storedDefaultAdmin || defaultAdmin !== storedDefaultAdmin || users.length !== storedUsers.length) {
  atomicWriteJson(files.users, users);
}

let authSecret;
if (fs.existsSync(files.secret)) {
  authSecret = fs.readFileSync(files.secret);
  if (authSecret.length < 32) throw new Error('The stored auth-secret is invalid.');
} else {
  authSecret = crypto.randomBytes(48);
  fs.writeFileSync(files.secret, authSecret, { mode: 0o600, flag: 'wx' });
}

function toMongoTicket(ticket) {
  const { id, _id, ...fields } = ticket;
  return { ...fields, _id: id || _id };
}

function toApiTicket(document) {
  const ticket = document.toObject ? document.toObject() : document;
  const { _id, __v, ...fields } = ticket;
  return {
    ...fields,
    id: String(_id),
    activityLog: (fields.activityLog || []).map((event) => ({
      ...event,
      timestamp: new Date(event.timestamp).toISOString(),
    })),
  };
}

async function getTickets() {
  const documents = await Ticket.find({}).lean();
  return documents.map(toApiTicket);
}

async function initializeMongo() {
  if (!MONGODB_URI) {
    throw new Error('Set MONGODB_URI or MONGODB_ATLAS_URI to your MongoDB Atlas connection string.');
  }
  await mongoose.connect(MONGODB_URI);
  console.log('Connected to MongoDB Atlas successfully');
  try {
    await Ticket.createCollection();
  } catch (error) {
    if (error.code !== 48) throw error;
  }

  const migrationId = 'legacy-json-tickets-v1';
  if (await Migration.exists({ _id: migrationId })) return;
  if (!(await Ticket.exists({}))) {
    if (initialTickets.length) {
      await Ticket.insertMany(initialTickets.map(toMongoTicket));
    }
  }
  await Migration.create({ _id: migrationId, completedAt: new Date() });
}

function normalizedTicketStatus(value) {
  return String(value || '').trim().toLocaleLowerCase().replace(/\s+/g, ' ');
}

function queryValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((entry) => typeof entry === 'string')
    .flatMap((entry) => entry.split(','))
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function filterTickets(tickets, query) {
  const search = queryValues(query.search).join(' ').toLocaleLowerCase();
  const severity = queryValues(query.severity)[0]?.toLocaleLowerCase();
  const status = queryValues(query.status)[0]?.toLocaleLowerCase();
  const product = queryValues(query.product)[0]?.toLocaleLowerCase();
  const tags = queryValues(query.tag).map((tag) => tag.replace(/^#/, '').toLocaleLowerCase());

  return tickets.filter((ticket) => {
    if (search) {
      const searchableText = [ticket.title, ticket.description, ticket.author]
        .filter((value) => typeof value === 'string')
        .join(' ')
        .toLocaleLowerCase();
      if (!searchableText.includes(search)) return false;
    }
    if (severity && severity !== 'all') {
      const ticketSeverity = String(ticket.severity || ticket.riskRating || '').toLocaleLowerCase();
      if (ticketSeverity !== severity) return false;
    }
    if (status && status !== 'all') {
      if (normalizedTicketStatus(ticket.status) !== normalizedTicketStatus(status)) return false;
    }
    if (product && product !== 'all') {
      if (String(ticket.product || '').toLocaleLowerCase() !== product) return false;
    }
    if (tags.length) {
      const ticketTags = Array.isArray(ticket.tags)
        ? ticket.tags.map((tag) => String(tag).replace(/^#/, '').toLocaleLowerCase())
        : [];
      if (!tags.every((tag) => ticketTags.includes(tag))) return false;
    }
    return true;
  });
}

function getNotes() {
  const result = readJson(files.notes, []);
  if (!Array.isArray(result)) throw new Error('notes.json must contain an array.');
  return result;
}

function getUsers() {
  const result = readJson(files.users, []);
  if (!Array.isArray(result)) throw new Error('users.json must contain an array.');
  return result;
}

function signToken(username) {
  const payload = Buffer.from(JSON.stringify({ username })).toString('base64url');
  const signature = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra) return null;
  const expected = crypto.createHmac('sha256', authSecret).update(payload).digest();
  let supplied;
  try {
    supplied = Buffer.from(signature, 'base64url');
  } catch {
    return null;
  }
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return getUsers().find((user) => user.username === claims.username) || null;
  } catch {
    return null;
  }
}

function requireAuthentication(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer ([^\s]+)$/);
  const user = match ? verifyToken(match[1]) : null;
  if (!user) return res.status(401).json({ error: 'Please sign in to continue.' });
  req.user = { username: user.username, role: user.role || 'auditor' };
  return next();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES_PER_NOTE, fields: 2, fieldSize: 12000 },
  fileFilter(req, file, callback) {
    const mimeType = file.mimetype.toLowerCase().split(';', 1)[0];
    if (!MIME_EXTENSIONS.has(mimeType)) {
      const error = new Error('Only PNG, JPG, WEBP, PDF, and supported audio files are allowed.');
      error.status = 400;
      return callback(error);
    }
    file.normalizedMimeType = mimeType;
    return callback(null, true);
  },
});

const backupUpload = multer({
  storage: multer.diskStorage({
    destination(req, file, callback) {
      callback(null, req.backupTempDir);
    },
    filename(req, file, callback) {
      callback(null, `${crypto.randomUUID()}.zip`);
    },
  }),
  limits: { fileSize: MAX_BACKUP_SIZE, files: 1, fields: 1, fieldSize: 1000 },
  fileFilter(req, file, callback) {
    if (path.extname(file.originalname).toLowerCase() !== '.zip') {
      const error = new Error('Select a ZIP backup file.');
      error.status = 400;
      return callback(error);
    }
    return callback(null, true);
  },
});

function receiveBackupUpload(req, res, next) {
  req.backupTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-backup-'));
  backupUpload.single('backupFile')(req, res, (error) => {
    if (error) {
      try {
        fs.rmSync(req.backupTempDir, { recursive: true, force: true });
      } catch (cleanupError) {
        console.error(`Unable to clean temporary backup upload: ${cleanupError.message}`);
      }
      return next(error);
    }
    return next();
  });
}

function parseBackupArchive(archivePath) {
  let zip;
  let entries;
  try {
    zip = new AdmZip(archivePath);
    entries = zip.getEntries();
  } catch {
    const error = new Error('The uploaded file is not a valid ZIP backup.');
    error.status = 400;
    throw error;
  }

  if (entries.length > MAX_BACKUP_ENTRIES) {
    const error = new Error('The backup contains too many entries.');
    error.status = 400;
    throw error;
  }
  let totalSize = 0;
  const uploadFiles = [];
  const availableUploads = new Set();
  const normalizedUploadNames = new Set();
  const seenEntries = new Set();
  let tickets;
  let notes;
  for (const entry of entries) {
    if (entry.entryName.includes('\\') || entry.entryName.startsWith('/') || seenEntries.has(entry.entryName)) {
      const error = new Error('The backup contains an unsafe or duplicate path.');
      error.status = 400;
      throw error;
    }
    seenEntries.add(entry.entryName);
    if (entry.isDirectory) {
      if (!['data/', 'public/', 'public/uploads/'].includes(entry.entryName)) {
        const error = new Error('The backup contains an unexpected directory.');
        error.status = 400;
        throw error;
      }
      continue;
    }
    const entrySize = entry.header.size;
    if (!Number.isSafeInteger(entrySize) || entrySize < 0 || entrySize > MAX_BACKUP_CONTENT_SIZE) {
      const error = new Error('The backup contains an invalid or oversized file.');
      error.status = 400;
      throw error;
    }
    totalSize += entrySize;
    if (totalSize > MAX_BACKUP_CONTENT_SIZE) {
      const error = new Error('The uncompressed backup exceeds the allowed size.');
      error.status = 400;
      throw error;
    }
    if (entry.entryName === 'data/tickets.json' || entry.entryName === 'data/notes.json') {
      if (entrySize > 20 * 1024 * 1024) {
        const error = new Error('The backup JSON file is too large.');
        error.status = 400;
        throw error;
      }
      let parsed;
      try {
        parsed = JSON.parse(entry.getData().toString('utf8'));
      } catch {
        const error = new Error(`The backup entry ${entry.entryName} is not valid JSON.`);
        error.status = 400;
        throw error;
      }
      if (!Array.isArray(parsed)) {
        const error = new Error(`${entry.entryName} must contain a JSON array.`);
        error.status = 400;
        throw error;
      }
      if (entry.entryName === 'data/tickets.json') tickets = parsed;
      else notes = parsed;
      continue;
    }

    const uploadPrefix = 'public/uploads/';
    const fileName = entry.entryName.startsWith(uploadPrefix)
      ? entry.entryName.slice(uploadPrefix.length)
      : '';
    if (!fileName || fileName.length > 255 || fileName === '.' || fileName === '..'
      || /[\\/\x00-\x1f<>:"|?*]/.test(fileName) || /[. ]$/.test(fileName)) {
      const error = new Error('The backup contains an unexpected or unsafe file path.');
      error.status = 400;
      throw error;
    }
    const normalizedFileName = fileName.toLowerCase();
    if (normalizedUploadNames.has(normalizedFileName)) {
      const error = new Error('The backup contains duplicate attachment files.');
      error.status = 400;
      throw error;
    }
    normalizedUploadNames.add(normalizedFileName);
    availableUploads.add(fileName);
    try {
      uploadFiles.push({ fileName, data: entry.getData() });
    } catch {
      const error = new Error('The backup contains an unreadable attachment.');
      error.status = 400;
      throw error;
    }
  }

  if (!tickets || !notes) {
    const error = new Error('The ZIP must contain data/tickets.json and data/notes.json.');
    error.status = 400;
    throw error;
  }
  const normalizedProducts = normalizeTicketProducts(tickets);
  const normalizedTickets = normalizeTicketActivityLogs(normalizedProducts.tickets);
  const ticketIds = new Set();
  for (const ticket of normalizedTickets.tickets) {
    if (!ticket || typeof ticket !== 'object' || Array.isArray(ticket)
      || typeof ticket.id !== 'string' || typeof ticket.title !== 'string'
      || typeof ticket.description !== 'string' || ticketIds.has(ticket.id)) {
      const error = new Error('The backup contains invalid or duplicate ticket data.');
      error.status = 400;
      throw error;
    }
    ticketIds.add(ticket.id);
  }
  const noteIds = new Set();
  for (const note of notes) {
    if (!note || typeof note !== 'object' || Array.isArray(note)
      || typeof note.id !== 'string' || noteIds.has(note.id)
      || typeof note.ticketId !== 'string' || !ticketIds.has(note.ticketId)
      || typeof note.text !== 'string'
      || (note.attachments !== undefined && !Array.isArray(note.attachments))) {
      const error = new Error('The backup contains invalid note data.');
      error.status = 400;
      throw error;
    }
    noteIds.add(note.id);
    for (const attachment of note.attachments || []) {
      const fileName = attachment && attachment.fileName;
      if (typeof fileName !== 'string' || !/^[\da-f-]{36}\.[a-z0-9]+$/i.test(fileName)
        || !EXTENSION_MIMES.has(path.extname(fileName).toLowerCase())
        || !availableUploads.has(fileName) || typeof attachment.mimeType !== 'string'
        || EXTENSION_MIMES.get(path.extname(fileName).toLowerCase()) !== attachment.mimeType) {
        const error = new Error('The backup references a missing or invalid attachment.');
        error.status = 400;
        throw error;
      }
    }
  }
  return { tickets: normalizedTickets.tickets, notes, uploadFiles };
}

function persistUploadedFiles(filesToSave) {
  const saved = [];
  try {
    for (const file of filesToSave) {
      const mimeType = file.normalizedMimeType || file.mimetype.toLowerCase().split(';', 1)[0];
      const extension = MIME_EXTENSIONS.get(mimeType);
      if (!extension) {
        const error = new Error('Unsupported attachment type.');
        error.status = 400;
        throw error;
      }
      const fileName = `${crypto.randomUUID()}${extension}`;
      fs.writeFileSync(path.join(UPLOAD_DIR, fileName), file.buffer, { flag: 'wx' });
      saved.push({
        fileName,
        name: path.basename(file.originalname || fileName).slice(0, 200),
        mimeType,
        size: file.size,
      });
    }
    return saved;
  } catch (error) {
    removeAttachmentFiles(saved);
    throw error;
  }
}

function removeAttachmentFiles(notes) {
  for (const note of notes) {
    for (const attachment of note.attachments || []) {
      if (typeof attachment.fileName !== 'string') continue;
      const fileName = path.basename(attachment.fileName);
      if (fileName !== attachment.fileName) continue;
      fs.rmSync(path.join(UPLOAD_DIR, fileName), { force: true });
    }
  }
}

function masterPasswordFromRequest(req) {
  return req.get('x-master-password') || req.body?.masterAuthorizationPassword || req.body?.masterPassword;
}

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use('/images', express.static(PUBLIC_IMAGE_DIR, { index: false, fallthrough: false }));

app.post('/api/auth/login', (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = getUsers().find((candidate) => candidate.username.toLowerCase() === username.trim().toLowerCase());
    if (!passwordMatches(password, user)) return res.status(401).json({ error: 'Incorrect username or password.' });
    return res.json({ token: signToken(user.username), user: { username: user.username } });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/add-user', (req, res, next) => {
  try {
    const {
      username,
      newUsername = username,
      password,
      newPassword = password,
      masterAuthorizationPassword,
      masterPassword,
    } = req.body || {};
    if (!masterPasswordMatches(masterAuthorizationPassword || masterPassword)) {
      return res.status(403).json({ error: 'Invalid Master Authorization Password.' });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }
    if (newPassword.length > 200) {
      return res.status(400).json({ error: 'Password must be at most 200 characters long.' });
    }
    if (typeof newUsername !== 'string' || !/^[A-Za-z0-9_.-]{2,40}$/.test(newUsername.trim())) {
      return res.status(400).json({ error: 'Username must be 2–40 letters, numbers, dots, dashes, or underscores.' });
    }
    users = getUsers();
    if (users.some((user) => user.username.toLowerCase() === newUsername.trim().toLowerCase())) {
      return res.status(409).json({ error: 'That username already exists.' });
    }
    const user = {
      username: newUsername.trim(),
      role: 'auditor',
      ...hashPassword(newPassword),
      createdAt: new Date().toISOString(),
    };
    users.push(user);
    atomicWriteJson(files.users, users);
    return res.status(201).json({ username: user.username });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/reset', (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Invalid Master Authorization Password.' });
  }
  try {
    users = getUsers();
    const defaultAdmin = users.find((user) =>
      typeof user.username === 'string' && user.username.toLowerCase() === DEFAULT_USERNAME.toLowerCase(),
    );
    if (!defaultAdmin || !passwordMatches(DEFAULT_PASSWORD, defaultAdmin)) {
      throw new Error('Protected default administrator account is missing or invalid.');
    }
    users = [defaultAdmin];
    atomicWriteJson(files.users, users);
    authSecret = crypto.randomBytes(48);
    const temporarySecret = `${files.secret}.${process.pid}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporarySecret, authSecret, { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporarySecret, files.secret);
    return res.json({ message: 'User accounts reset to the default administrator.' });
  } catch (error) {
    return next(error);
  }
});

app.use('/api', requireAuthentication);

app.get('/api/auth/me', (req, res) => res.json({ user: req.user }));

app.get('/api/products', (req, res) => res.json(SUPPORTED_PRODUCTS));

app.get('/api/backup/export', async (req, res, next) => {
  try {
    const zip = new AdmZip();
    zip.addFile('data/tickets.json', Buffer.from(`${JSON.stringify(await getTickets(), null, 2)}\n`));
    zip.addFile('data/notes.json', fs.readFileSync(files.notes));
    for (const entry of fs.readdirSync(UPLOAD_DIR, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      zip.addFile(`public/uploads/${entry.name}`, fs.readFileSync(path.join(UPLOAD_DIR, entry.name)));
    }
    const filename = `sentinel-backup-${new Date().toISOString().slice(0, 10)}.zip`;
    res.attachment(filename);
    res.type('application/zip');
    return res.send(zip.toBuffer());
  } catch (error) {
    return next(error);
  }
});

app.post('/api/backup/import', receiveBackupUpload, async (req, res, next) => {
  let stagedUploadsDir;
  let previousUploadsDir;
  let previousUploadsMoved = false;
  let stagedUploadsInstalled = false;
  let committed = false;
  try {
    if (!req.file) {
      const error = new Error('Select a ZIP backup file to import.');
      error.status = 400;
      throw error;
    }
    if (!masterPasswordMatches(req.body?.masterPassword)) {
      return res.status(401).json({ error: 'Incorrect Master Password. Access Denied.' });
    }

    const { tickets, notes, uploadFiles } = parseBackupArchive(req.file.path);
    const backupId = crypto.randomUUID();
    stagedUploadsDir = path.join(path.dirname(UPLOAD_DIR), `.sentinel-backup-stage-${backupId}`);
    previousUploadsDir = path.join(path.dirname(UPLOAD_DIR), `.sentinel-backup-previous-${backupId}`);
    fs.mkdirSync(stagedUploadsDir);
    for (const uploadFile of uploadFiles) {
      fs.writeFileSync(path.join(stagedUploadsDir, uploadFile.fileName), uploadFile.data, { flag: 'wx' });
    }

    fs.renameSync(UPLOAD_DIR, previousUploadsDir);
    previousUploadsMoved = true;
    fs.renameSync(stagedUploadsDir, UPLOAD_DIR);
    stagedUploadsDir = null;
    stagedUploadsInstalled = true;
    const previousNotes = getNotes();
    const session = await mongoose.startSession();
    let notesReplaced = false;
    try {
      await session.withTransaction(async () => {
        await Ticket.deleteMany({}, { session });
        if (tickets.length) await Ticket.insertMany(tickets.map(toMongoTicket), { session });
        atomicWriteJson(files.notes, notes);
        notesReplaced = true;
      });
    } catch (error) {
      if (notesReplaced) {
        try {
          atomicWriteJson(files.notes, previousNotes);
        } catch (rollbackError) {
          console.error(`Unable to restore notes after failed MongoDB backup import: ${rollbackError.message}`);
        }
      }
      throw error;
    } finally {
      await session.endSession();
    }
    committed = true;

    try {
      fs.rmSync(previousUploadsDir, { recursive: true, force: true });
    } catch (cleanupError) {
      console.error(`Unable to remove previous attachment files after backup import: ${cleanupError.message}`);
    }
    return res.json({ message: 'Backup imported successfully.' });
  } catch (error) {
    if (!committed) {
      if (stagedUploadsInstalled) {
        try {
          fs.rmSync(UPLOAD_DIR, { recursive: true, force: true });
        } catch (rollbackError) {
          console.error(`Unable to remove staged attachment files after failed backup import: ${rollbackError.message}`);
        }
      }
      if (previousUploadsMoved) {
        try {
          fs.renameSync(previousUploadsDir, UPLOAD_DIR);
        } catch (rollbackError) {
          console.error(`Unable to restore attachment files after failed backup import: ${rollbackError.message}`);
        }
      }
    }
    return next(error);
  } finally {
    for (const temporaryPath of [stagedUploadsDir, req.backupTempDir]) {
      if (!temporaryPath) continue;
      try {
        fs.rmSync(temporaryPath, { recursive: true, force: true });
      } catch (cleanupError) {
        console.error(`Unable to clean backup import temporary files: ${cleanupError.message}`);
      }
    }
  }
});

app.get('/api/tickets', async (req, res, next) => {
  try {
    return res.json(filterTickets(await getTickets(), req.query));
  } catch (error) {
    return next(error);
  }
});

app.get('/api/reports/summary', async (req, res, next) => {
  try {
    const tickets = filterTickets(await getTickets(), req.query);
    const ticketIds = new Set(tickets.map((ticket) => ticket.id));
    const notes = getNotes().filter((note) => ticketIds.has(note.ticketId));
    const notesByTicket = new Map();
    for (const note of notes) {
      if (!notesByTicket.has(note.ticketId)) notesByTicket.set(note.ticketId, []);
      notesByTicket.get(note.ticketId).push(note);
    }

    const statusCounts = { open: 0, inProgress: 0, resolved: 0, closed: 0 };
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const ticket of tickets) {
      const status = normalizedTicketStatus(ticket.status || 'Open');
      if (status === 'open') statusCounts.open += 1;
      else if (status === 'in progress') statusCounts.inProgress += 1;
      else if (status === 'resolved') statusCounts.resolved += 1;
      else if (status === 'closed') statusCounts.closed += 1;

      const severity = String(ticket.severity || ticket.riskRating || '').toLocaleLowerCase();
      if (Object.hasOwn(severityCounts, severity)) severityCounts[severity] += 1;
    }

    return res.json({
      generatedAt: new Date().toISOString(),
      summary: {
        totalConcerns: tickets.length,
        ...statusCounts,
        ...severityCounts,
        evidenceNotes: notes.length,
      },
      tickets: tickets.map((ticket) => ({
        ...ticket,
        notes: notesByTicket.get(ticket.id) || [],
      })),
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets', async (req, res, next) => {
  try {
    const {
      title,
      description,
      product = DEFAULT_PRODUCT,
      severity,
      tags = [],
    } = req.body || {};
    if (typeof title !== 'string' || !title.trim() || title.length > 200) {
      return res.status(400).json({ error: 'Title of Issue is required and must be at most 200 characters.' });
    }
    if (typeof description !== 'string' || !description.trim() || description.length > 10000) {
      return res.status(400).json({ error: 'Description is required and must be at most 10,000 characters.' });
    }
    if (typeof product !== 'string' || !SUPPORTED_PRODUCTS.includes(product)) {
      return res.status(400).json({ error: 'Select a supported product category.' });
    }
    const normalizedSeverity = severity === undefined || severity === null || severity === ''
      ? null
      : canonicalTicketSeverity(severity);
    if (severity !== undefined && severity !== null && severity !== '' && !normalizedSeverity) {
      return res.status(400).json({ error: 'Select a supported ticket severity.' });
    }
    if (!Array.isArray(tags) || tags.length > 12 || tags.some((tag) => (
      typeof tag !== 'string'
      || !tag.trim().replace(/^#/, '').trim()
      || tag.trim().replace(/^#/, '').trim().length > 30
    ))) {
      return res.status(400).json({ error: 'Tags must be a list of at most 12 names, each at most 30 characters.' });
    }
    const seenTags = new Set();
    const normalizedTags = tags.reduce((normalized, tag) => {
      const value = tag.trim().replace(/^#/, '').trim();
      const key = value.toLocaleLowerCase();
      if (!seenTags.has(key)) {
        seenTags.add(key);
        normalized.push(value);
      }
      return normalized;
    }, []);
    const tickets = await getTickets();
    const createdAt = new Date().toISOString();
    const ticket = {
      id: createTicketId(tickets),
      product,
      title: title.trim(),
      description: description.trim(),
      tags: normalizedTags,
      status: 'Open',
      ...(normalizedSeverity ? { severity: normalizedSeverity, riskRating: normalizedSeverity } : {}),
      createdAt,
      author: req.user.username,
      activityLog: [],
    };
    appendTicketActivity(ticket, 'status_changed', null, ticket.status, req.user.username, createdAt);
    appendTicketActivity(ticket, 'product_changed', null, ticket.product, req.user.username, createdAt);
    if (normalizedSeverity) {
      appendTicketActivity(ticket, 'severity_changed', null, normalizedSeverity, req.user.username, createdAt);
    }
    const createdTicket = await Ticket.create(toMongoTicket(ticket));
    return res.status(201).json(toApiTicket(createdTicket));
  } catch (error) {
    return next(error);
  }
});

async function updateTicket(req, res, next) {
  try {
    const updates = req.body;
    if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
      return res.status(400).json({ error: 'Provide ticket fields to update.' });
    }
    const allowedFields = new Set(['status', 'severity', 'product']);
    const fields = Object.keys(updates);
    if (!fields.length || fields.some((field) => !allowedFields.has(field))) {
      return res.status(400).json({ error: 'Only status, severity, and product category can be updated.' });
    }
    const document = await Ticket.findById(req.params.id).lean();
    if (!document) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = toApiTicket(document);

    const timestamp = new Date().toISOString();
    const updatesToSet = {};
    const activityEvents = [];
    const recordActivity = (action, statusFrom, statusTo) => {
      activityEvents.push({
        action,
        statusFrom,
        statusTo,
        performedBy: req.user.username,
        timestamp: new Date(timestamp),
      });
    };
    if (Object.hasOwn(updates, 'status')) {
      const nextStatus = canonicalTicketStatus(updates.status);
      if (!nextStatus) {
        return res.status(400).json({ error: `Status must be one of: ${TICKET_STATUSES.join(', ')}.` });
      }
      const currentStatus = ticket.status || 'Open';
      if (normalizedTicketStatus(currentStatus) !== normalizedTicketStatus(nextStatus)) {
        recordActivity('status_changed', currentStatus, nextStatus);
        updatesToSet.status = nextStatus;
      }
    }
    if (Object.hasOwn(updates, 'severity')) {
      const nextSeverity = updates.severity === null || updates.severity === ''
        ? null
        : canonicalTicketSeverity(updates.severity);
      if (updates.severity !== null && updates.severity !== '' && !nextSeverity) {
        return res.status(400).json({ error: `Severity must be one of: ${TICKET_SEVERITIES.join(', ')}.` });
      }
      const currentSeverity = ticket.severity || ticket.riskRating || null;
      if (currentSeverity !== nextSeverity) {
        recordActivity('severity_changed', currentSeverity, nextSeverity);
        if (nextSeverity) {
          updatesToSet.severity = nextSeverity;
          updatesToSet.riskRating = nextSeverity;
        } else {
          updatesToSet.severity = null;
          updatesToSet.riskRating = null;
        }
      }
    }
    if (Object.hasOwn(updates, 'product')) {
      if (typeof updates.product !== 'string' || !SUPPORTED_PRODUCTS.includes(updates.product)) {
        return res.status(400).json({ error: 'Select a supported product category.' });
      }
      if (ticket.product !== updates.product) {
        recordActivity('product_changed', ticket.product || null, updates.product);
        updatesToSet.product = updates.product;
      }
    }
    if (!activityEvents.length && !Object.keys(updatesToSet).length) return res.json(ticket);
    const mongoUpdate = {};
    if (Object.keys(updatesToSet).length) mongoUpdate.$set = updatesToSet;
    if (activityEvents.length) mongoUpdate.$push = { activityLog: { $each: activityEvents } };
    const updatedDocument = await Ticket.findByIdAndUpdate(req.params.id, mongoUpdate, {
      new: true,
      runValidators: true,
    }).lean();
    if (!updatedDocument) return res.status(404).json({ error: 'Ticket not found.' });
    return res.json(toApiTicket(updatedDocument));
  } catch (error) {
    return next(error);
  }
}

app.patch('/api/tickets/:id', updateTicket);
app.put('/api/tickets/:id', updateTicket);

function getBulkTicketIds(value) {
  if (!Array.isArray(value) || !value.length || value.length > 500
    || value.some((id) => typeof id !== 'string' || !id.trim())) {
    const error = new Error('Provide between 1 and 500 valid ticket IDs.');
    error.status = 400;
    throw error;
  }
  return [...new Set(value.map((id) => id.trim()))];
}

app.post('/api/tickets/bulk-update', async (req, res, next) => {
  try {
    const { ids, status, severity } = req.body || {};
    const hasStatus = Object.hasOwn(req.body || {}, 'status');
    const hasSeverity = Object.hasOwn(req.body || {}, 'severity');
    if (hasStatus === hasSeverity || Object.keys(req.body || {}).some((key) => !['ids', 'status', 'severity'].includes(key))) {
      return res.status(400).json({ error: 'Provide ticket IDs and exactly one of status or severity.' });
    }
    const ticketIds = getBulkTicketIds(ids);
    const nextValue = hasStatus ? canonicalTicketStatus(status) : canonicalTicketSeverity(severity);
    if (!nextValue) {
      const field = hasStatus ? 'Status' : 'Severity';
      const values = hasStatus ? TICKET_STATUSES : TICKET_SEVERITIES;
      return res.status(400).json({ error: `${field} must be one of: ${values.join(', ')}.` });
    }

    const documents = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    if (documents.length !== ticketIds.length) {
      return res.status(404).json({ error: 'One or more selected tickets were not found.' });
    }
    const timestamp = new Date();
    const action = hasStatus ? 'bulk_status_changed' : 'bulk_severity_changed';
    const operations = documents.flatMap((document) => {
      const currentValue = hasStatus
        ? (document.status || 'Open')
        : (document.severity || document.riskRating || null);
      const changed = hasStatus
        ? normalizedTicketStatus(currentValue) !== normalizedTicketStatus(nextValue)
        : currentValue !== nextValue;
      if (!changed) return [];

      const set = hasStatus
        ? { status: nextValue }
        : { severity: nextValue, riskRating: nextValue };
      return [{
        updateOne: {
          filter: { _id: document._id },
          update: {
            $set: set,
            $push: {
              activityLog: {
                action,
                statusFrom: currentValue,
                statusTo: nextValue,
                performedBy: req.user.username,
                timestamp,
              },
            },
          },
        },
      }];
    });
    if (operations.length) await Ticket.bulkWrite(operations);
    const updatedDocuments = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    return res.json({
      updatedCount: operations.length,
      tickets: updatedDocuments.map(toApiTicket),
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets/bulk-delete', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const ticketIds = getBulkTicketIds(req.body?.ids);
    const documents = await Ticket.find({ _id: { $in: ticketIds } }).lean();
    if (documents.length !== ticketIds.length) {
      return res.status(404).json({ error: 'One or more selected tickets were not found.' });
    }

    const notes = getNotes();
    const deletedNotes = notes.filter((note) => ticketIds.includes(note.ticketId));
    const nextNotes = notes.filter((note) => !ticketIds.includes(note.ticketId));
    const session = await mongoose.startSession();
    let notesReplaced = false;
    try {
      await session.withTransaction(async () => {
        await Ticket.deleteMany({ _id: { $in: ticketIds } }, { session });
        atomicWriteJson(files.notes, nextNotes);
        notesReplaced = true;
      });
    } catch (error) {
      if (notesReplaced) {
        try {
          atomicWriteJson(files.notes, notes);
        } catch (rollbackError) {
          console.error(`Unable to restore notes after failed MongoDB bulk ticket deletion: ${rollbackError.message}`);
        }
      }
      throw error;
    } finally {
      await session.endSession();
    }
    removeAttachmentFiles(deletedNotes);
    return res.json({ deletedCount: documents.length });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/tickets/:id', async (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const ticketDocument = await Ticket.findById(req.params.id).lean();
    if (!ticketDocument) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = toApiTicket(ticketDocument);
    const notes = getNotes();
    const deletedNotes = notes.filter((note) => note.ticketId === ticket.id);
    const nextNotes = notes.filter((note) => note.ticketId !== ticket.id);
    const session = await mongoose.startSession();
    let notesReplaced = false;
    try {
      await session.withTransaction(async () => {
        await Ticket.findByIdAndDelete(ticket.id, { session });
        atomicWriteJson(files.notes, nextNotes);
        notesReplaced = true;
      });
    } catch (error) {
      if (notesReplaced) {
        try {
          atomicWriteJson(files.notes, notes);
        } catch (rollbackError) {
          console.error(`Unable to restore notes after failed MongoDB ticket deletion: ${rollbackError.message}`);
        }
      }
      throw error;
    } finally {
      await session.endSession();
    }
    removeAttachmentFiles(deletedNotes);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/counts', (req, res, next) => {
  try {
    const counts = {};
    for (const note of getNotes()) {
      counts[note.ticketId] = (counts[note.ticketId] || 0) + 1;
    }
    return res.json(counts);
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/:ticketId', async (req, res, next) => {
  try {
    if (!(await Ticket.exists({ _id: req.params.ticketId }))) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }
    return res.json(getNotes().filter((note) => note.ticketId === req.params.ticketId));
  } catch (error) {
    return next(error);
  }
});

app.post('/api/notes', upload.array('attachments', MAX_FILES_PER_NOTE), async (req, res, next) => {
  let savedAttachments = [];
  try {
    const { ticketId, text = '' } = req.body || {};
    if (typeof ticketId !== 'string' || !ticketId.trim() || !(await Ticket.exists({ _id: ticketId }))) {
      return res.status(400).json({ error: 'Select a valid ticket before adding a note.' });
    }
    if (typeof text !== 'string' || text.length > 10000) {
      return res.status(400).json({ error: 'Note text must be at most 10,000 characters.' });
    }
    savedAttachments = persistUploadedFiles(req.files || []);
    if (!text.trim() && savedAttachments.length === 0) {
      removeAttachmentFiles([{ attachments: savedAttachments }]);
      return res.status(400).json({ error: 'Add note text or at least one attachment.' });
    }
    const note = {
      id: crypto.randomUUID(),
      ticketId,
      text: text.trim(),
      attachments: savedAttachments,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      author: req.user.username,
    };
    const notes = getNotes();
    notes.push(note);
    atomicWriteJson(files.notes, notes);
    return res.status(201).json(note);
  } catch (error) {
    removeAttachmentFiles([{ attachments: savedAttachments }]);
    return next(error);
  }
});

app.put('/api/notes/:id', (req, res, next) => {
  try {
    const { text } = req.body || {};
    if (typeof text !== 'string' || text.length > 10000) {
      return res.status(400).json({ error: 'Note text must be a string of at most 10,000 characters.' });
    }
    const notes = getNotes();
    const note = notes.find((candidate) => candidate.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Note not found.' });
    note.text = text.trim();
    note.updatedAt = new Date().toISOString();
    note.updatedBy = req.user.username;
    atomicWriteJson(files.notes, notes);
    return res.json(note);
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/notes/:id', (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const notes = getNotes();
    const note = notes.find((candidate) => candidate.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'Note not found.' });
    atomicWriteJson(files.notes, notes.filter((candidate) => candidate.id !== note.id));
    removeAttachmentFiles([note]);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/uploads/:fileName', (req, res, next) => {
  try {
    const fileName = path.basename(req.params.fileName);
    if (fileName !== req.params.fileName || !/^[\da-f-]{36}\.[a-z0-9]+$/i.test(fileName)) {
      return res.status(404).json({ error: 'Attachment not found.' });
    }
    const isAttached = getNotes().some((note) =>
      (note.attachments || []).some((attachment) => attachment.fileName === fileName),
    );
    const extension = path.extname(fileName).toLowerCase();
    if (!isAttached || !EXTENSION_MIMES.has(extension)) {
      return res.status(404).json({ error: 'Attachment not found.' });
    }
    return res.sendFile(path.join(UPLOAD_DIR, fileName), {
      headers: {
        'Content-Type': EXTENSION_MIMES.get(extension),
        'Content-Disposition': 'inline',
        'X-Content-Type-Options': 'nosniff',
      },
    }, (error) => {
      if (error && !res.headersSent) next(error);
    });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/gallery', (req, res, next) => {
  try {
    const gallery = getNotes().flatMap((note) =>
      (note.attachments || [])
        .filter((attachment) => attachment.mimeType.startsWith('image/'))
        .map((attachment) => ({
          ...attachment,
          apiPath: `/api/uploads/${encodeURIComponent(attachment.fileName)}`,
          ticketId: note.ticketId,
          createdAt: note.createdAt,
          text: note.text,
        })),
    );
    return res.json(gallery);
  } catch (error) {
    return next(error);
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    if (req.path.startsWith('/api/backup/')) {
      return res.status(status).json({
        error: error.code === 'LIMIT_FILE_SIZE'
          ? 'The backup ZIP must be 250 MB or smaller.'
          : 'Backup upload limit exceeded.',
      });
    }
    return res.status(status).json({
      error: error.code === 'LIMIT_FILE_SIZE'
        ? 'Each attachment must be 10 MB or smaller.'
        : 'Attachment upload limit exceeded.',
    });
  }
  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) console.error(error);
  return res.status(status).json({ error: status >= 500 ? 'An internal server error occurred.' : error.message });
});

function startServer() {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SiyanoAV audit dashboard listening on 0.0.0.0:${PORT}`);
  });
  initializeMongo().catch((error) => {
    console.error(`Unable to connect to MongoDB Atlas at startup: ${error.message}`);
  });
}

startServer();
