const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const multer = require('multer');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PUBLIC_UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
const PUBLIC_IMAGE_DIR = path.join(PUBLIC_DIR, 'images');
const STORAGE_DIR = process.env.STORAGE_DIR ? path.resolve(process.env.STORAGE_DIR) : DATA_DIR;
const UPLOAD_DIR = process.env.STORAGE_DIR ? path.join(STORAGE_DIR, 'uploads') : PUBLIC_UPLOAD_DIR;
const MASTER_PASSWORD = 'cat123123';
const DEFAULT_USERNAME = 'Admin';
const DEFAULT_PASSWORD = 'admin@123#';
const PASSWORD_HASH_BYTES = 64;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILES_PER_NOTE = 8;

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

function atomicWriteJsonPair(firstPath, firstValue, secondPath, secondValue, oldFirst, oldSecond) {
  const firstTemp = `${firstPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const secondTemp = `${secondPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(firstTemp, `${JSON.stringify(firstValue, null, 2)}\n`, 'utf8');
  fs.writeFileSync(secondTemp, `${JSON.stringify(secondValue, null, 2)}\n`, 'utf8');
  let firstCommitted = false;
  try {
    fs.renameSync(firstTemp, firstPath);
    firstCommitted = true;
    fs.renameSync(secondTemp, secondPath);
  } catch (error) {
    fs.rmSync(firstTemp, { force: true });
    fs.rmSync(secondTemp, { force: true });
    if (firstCommitted) atomicWriteJson(firstPath, oldFirst);
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

const SAMPLE_AUDIT_CASES = [
  {
    id: 'Ticket01',
    title: 'Real-time Scanning & HIPS Disagreement',
    riskRating: 'HIGH',
    description: 'A controlled test file is blocked by real-time scanning but is still permitted by the host intrusion prevention policy, leaving enforcement inconsistent across protection layers.',
    notes: [
      'Expected: both real-time scanning and HIPS deny the controlled test artifact. Reported: scanning quarantines it, while the HIPS event records an allow decision. Evidence reference (mock): scan-hips-policy-matrix.csv.',
      'Reproduced after refreshing policy and restarting the service. Initial root-cause hypothesis: HIPS evaluates a cached trust decision before the scanner verdict is committed. Evidence reference (mock): event-sequence-ticket01.txt.',
      'Recommendation: correlate verdicts by file hash and fail closed when the protection layers disagree. Retest should confirm a single deny outcome and matching audit events. Evidence reference (mock): remediation-retest-ticket01.pdf.',
    ],
  },
  {
    id: 'Ticket02',
    title: 'Advanced Threat Shield Self-Protection Gap',
    riskRating: 'HIGH',
    description: 'A standard-user process can stop a helper component used by Advanced Threat Shield, temporarily reducing behavioral monitoring until the service recovers.',
    notes: [
      'Expected: protected components reject stop and unload requests from an untrusted standard-user process. Reported: the helper exits briefly, and monitoring resumes only after automatic recovery. Evidence reference (mock): shield-stop-attempt.log.',
      'The service control request was denied for the primary process but accepted by the helper. Root-cause hypothesis: the helper is missing the product self-protection registration. Evidence reference (mock): service-acl-review.txt.',
      'Recommendation: apply the same tamper-protection policy to the helper and alert on unexpected termination. Validate across reboot and update cycles. Evidence reference (mock): shield-hardening-checklist.pdf.',
    ],
  },
  {
    id: 'Ticket03',
    title: 'Privilege Escalation via Update Binary',
    riskRating: 'CRITICAL',
    description: 'The updater service launches a replaceable executable from a directory with insufficient write restrictions, creating a potential path to elevated code execution.',
    notes: [
      'Expected: only an administrator or signed update workflow can replace files executed by the elevated updater. Reported: the service directory permissions allow a lower-privileged account to modify the helper. Evidence reference (mock): updater-acl-capture.txt.',
      'Controlled validation confirmed the executable is loaded by the elevated service after restart; no payload was used. Root-cause hypothesis: inherited write permissions were not removed during installation. Evidence reference (mock): process-launch-trace-ticket03.etl.',
      'Recommendation: restrict directory and binary ACLs, verify the publisher signature immediately before launch, and test upgrades from a standard account. Evidence reference (mock): signed-launch-retest.pdf.',
    ],
  },
  {
    id: 'Ticket04',
    title: 'Unencrypted Telemetry Data Transmission',
    riskRating: 'MEDIUM',
    description: 'A telemetry submission path appears to permit cleartext transport in a non-production configuration, potentially exposing diagnostic metadata on untrusted networks.',
    notes: [
      'Expected: telemetry is transmitted only over authenticated TLS. Reported: a test endpoint accepted a plaintext request containing device and diagnostic metadata. Evidence reference (mock): telemetry-protocol-review.pcap.txt.',
      'Issue is reproducible with the lab transport override; production endpoint behavior still requires confirmation. Root-cause hypothesis: the fallback transport option is enabled when certificate setup fails. Evidence reference (mock): client-config-ticket04.json.',
      'Recommendation: disable plaintext fallback, fail closed on TLS errors, and confirm that telemetry contains no credentials or sensitive file content. Evidence reference (mock): tls-only-validation.pdf.',
    ],
  },
  {
    id: 'Ticket05',
    title: 'Session Timeout Bypass on Re-auth',
    riskRating: 'MEDIUM',
    description: 'Returning to the dashboard after a session expires can briefly reuse cached authorization state instead of requiring fresh authentication.',
    notes: [
      'Expected: expired sessions are rejected for every protected request and the user is redirected to sign in. Reported: a previously loaded view remains interactive until the next data refresh. Evidence reference (mock): session-expiry-repro.md.',
      'The API rejects the expired token, but the client retains selected-ticket state and shows stale content. Root-cause hypothesis: the 401 handler does not clear all cached view state. Evidence reference (mock): auth-refresh-console.txt.',
      'Recommendation: clear protected content immediately on expiry and require a new authenticated response before restoring the view. Evidence reference (mock): session-timeout-retest.pdf.',
    ],
  },
  {
    id: 'Ticket06',
    title: 'Memory Injection Vulnerability in Driver',
    riskRating: 'CRITICAL',
    description: 'A privileged driver interface appears to accept a buffer operation without adequately validating caller context and requested memory ranges.',
    notes: [
      'Expected: the driver validates request size, process context, and target memory range before handling an operation. Reported: malformed lab requests reached a privileged memory-handling path. Evidence reference (mock): driver-ioctl-boundary.txt.',
      'Testing was limited to a disposable virtual machine with benign malformed inputs. Root-cause hypothesis: a legacy IOCTL handler trusts a user-supplied length before copying data. Evidence reference (mock): driver-verifier-summary.log.',
      'Recommendation: audit all IOCTL handlers, enforce strict bounds and access checks, and add fuzz regression tests before release. Evidence reference (mock): driver-fix-validation.pdf.',
    ],
  },
  {
    id: 'Ticket07',
    title: 'Insecure Deserialization in Log Collector',
    riskRating: 'HIGH',
    description: 'The log collector accepts structured diagnostic input without a strict schema, creating risk of unsafe object construction from malformed local data.',
    notes: [
      'Expected: collector input is parsed using a constrained schema and unsupported object types are rejected. Reported: malformed nested values are accepted and passed into the processing pipeline. Evidence reference (mock): collector-parser-cases.json.',
      'No code execution was attempted. Root-cause hypothesis: a general-purpose object deserializer is used where a data-only parser is sufficient. Evidence reference (mock): collector-input-trace.txt.',
      'Recommendation: use a safe data-only parser, validate depth and field types, and cap payload size. Add malformed-input regression cases. Evidence reference (mock): parser-hardening-tests.pdf.',
    ],
  },
  {
    id: 'Ticket08',
    title: 'Weak Cryptographic Key Derivation',
    riskRating: 'MEDIUM',
    description: 'A local credential-protection path uses a low work factor or insufficiently unique salt parameters compared with current password-storage guidance.',
    notes: [
      'Expected: password-derived secrets use a modern, tunable KDF with a unique random salt and documented work parameters. Reported: the reviewed test configuration uses weaker derivation settings. Evidence reference (mock): kdf-parameter-review.csv.',
      'The finding is based on configuration review and offline timing measurements using synthetic credentials only. Root-cause hypothesis: compatibility defaults were retained after hardware capabilities improved. Evidence reference (mock): synthetic-kdf-benchmark.txt.',
      'Recommendation: migrate stored secrets safely to a stronger KDF, benchmark on supported devices, and version parameters for future upgrades. Evidence reference (mock): kdf-migration-plan.pdf.',
    ],
  },
  {
    id: 'Ticket09',
    title: 'Unauthorized Registry Modification Route',
    riskRating: 'LOW',
    description: 'A product configuration key can be modified by a broader local group than intended, although no direct security-control bypass was confirmed.',
    notes: [
      'Expected: security-sensitive configuration keys are writable only by the service and administrators. Reported: one non-sensitive test key inherits a broad local write ACL. Evidence reference (mock): registry-acl-audit.txt.',
      'The reviewed key did not alter protection behavior in the test build. Root-cause hypothesis: installer permissions were copied from a general application settings template. Evidence reference (mock): installer-permissions-diff.csv.',
      'Recommendation: narrow the ACL to required principals and add an installation verification test. Reassess if the key becomes security-sensitive in a later release. Evidence reference (mock): registry-acl-retest.pdf.',
    ],
  },
  {
    id: 'Ticket10',
    title: 'Improper Certificate Validation on Sync',
    riskRating: 'HIGH',
    description: 'The synchronization client may accept an untrusted certificate under a fallback condition, weakening server identity checks for policy updates.',
    notes: [
      'Expected: sync fails if the peer certificate chain, hostname, or validity check fails. Reported: the test client continued with a warning when the lab certificate chain was untrusted. Evidence reference (mock): sync-certificate-test.txt.',
      'The behavior was observed only with the diagnostic fallback enabled; no production endpoint was contacted. Root-cause hypothesis: a permissive validation callback remains wired into the fallback path. Evidence reference (mock): sync-tls-debug.log.',
      'Recommendation: remove permissive validation, fail closed on all certificate errors, and test invalid chain, hostname mismatch, and expiry cases. Evidence reference (mock): certificate-validation-matrix.pdf.',
    ],
  },
];

function seedSampleAuditData() {
  const tickets = readJson(files.tickets, []);
  const notes = readJson(files.notes, []);
  if (!Array.isArray(tickets) || !Array.isArray(notes)) {
    throw new Error('Tickets and notes storage must contain JSON arrays.');
  }
  if (tickets.length > 0) return 0;

  const seededAt = Date.now();
  const sampleTickets = SAMPLE_AUDIT_CASES.map((sample, index) => ({
    id: sample.id,
    displayId: sample.id,
    title: sample.title,
    description: sample.description,
    status: 'Open',
    riskRating: sample.riskRating,
    createdAt: new Date(seededAt - (SAMPLE_AUDIT_CASES.length - index) * 60_000).toISOString(),
    author: 'Sample Audit',
  }));
  const sampleNotes = SAMPLE_AUDIT_CASES.flatMap((sample, ticketIndex) =>
    sample.notes.map((text, noteIndex) => {
      const createdAt = new Date(seededAt - (ticketIndex * 3 + noteIndex + 1) * 60 * 60_000).toISOString();
      return {
        id: `${sample.id}-note-${noteIndex + 1}`,
        ticketId: sample.id,
        text,
        attachments: [],
        createdAt,
        updatedAt: createdAt,
        author: 'Sample Audit',
      };
    }),
  );
  atomicWriteJsonPair(files.tickets, sampleTickets, files.notes, [...notes, ...sampleNotes], tickets, notes);
  return sampleTickets.length;
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
const seededTicketCount = seedSampleAuditData();
if (seededTicketCount > 0) {
  console.log(`Seeded ${seededTicketCount} sample audit tickets and ${seededTicketCount * 3} sample notes.`);
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

function getTickets() {
  const result = readJson(files.tickets, []);
  if (!Array.isArray(result)) throw new Error('tickets.json must contain an array.');
  return result;
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

app.get('/api/tickets', (req, res, next) => {
  try {
    return res.json(getTickets());
  } catch (error) {
    return next(error);
  }
});

app.post('/api/tickets', (req, res, next) => {
  try {
    const { title, description } = req.body || {};
    if (typeof title !== 'string' || !title.trim() || title.length > 200) {
      return res.status(400).json({ error: 'Title of Issue is required and must be at most 200 characters.' });
    }
    if (typeof description !== 'string' || !description.trim() || description.length > 10000) {
      return res.status(400).json({ error: 'Description is required and must be at most 10,000 characters.' });
    }
    const tickets = getTickets();
    const ticket = {
      id: createTicketId(tickets),
      title: title.trim(),
      description: description.trim(),
      status: 'Open',
      createdAt: new Date().toISOString(),
      author: req.user.username,
    };
    tickets.push(ticket);
    atomicWriteJson(files.tickets, tickets);
    return res.status(201).json(ticket);
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/tickets/:id', (req, res, next) => {
  if (!masterPasswordMatches(masterPasswordFromRequest(req))) {
    return res.status(403).json({ error: 'Incorrect Master Password. Access Denied.' });
  }
  try {
    const tickets = getTickets();
    const ticket = tickets.find((candidate) => candidate.id === req.params.id);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found.' });
    const notes = getNotes();
    const deletedNotes = notes.filter((note) => note.ticketId === ticket.id);
    const nextTickets = tickets.filter((candidate) => candidate.id !== ticket.id);
    const nextNotes = notes.filter((note) => note.ticketId !== ticket.id);
    atomicWriteJsonPair(files.tickets, nextTickets, files.notes, nextNotes, tickets, notes);
    removeAttachmentFiles(deletedNotes);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get('/api/notes/:ticketId', (req, res, next) => {
  try {
    if (!getTickets().some((ticket) => ticket.id === req.params.ticketId)) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }
    return res.json(getNotes().filter((note) => note.ticketId === req.params.ticketId));
  } catch (error) {
    return next(error);
  }
});

app.post('/api/notes', upload.array('attachments', MAX_FILES_PER_NOTE), (req, res, next) => {
  let savedAttachments = [];
  try {
    const { ticketId, text = '' } = req.body || {};
    if (typeof ticketId !== 'string' || !ticketId.trim() || !getTickets().some((ticket) => ticket.id === ticketId)) {
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SiyanoAV audit dashboard listening on 0.0.0.0:${PORT}`);
});
