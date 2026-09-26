const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const archiverModule = require('archiver');
function createArchive(format, options) {
  if (format === 'zip' && typeof archiverModule.ZipArchive === 'function')
    return new archiverModule.ZipArchive(options);
  if (typeof archiverModule === 'function') return archiverModule(format, options);
  if (typeof archiverModule.default === 'function') return archiverModule.default(format, options);
  return new archiverModule.Archiver(format, options);
}

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'ganti-secret-ini-dengan-yang-kuat-12345';
const QUOTA_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB

const STORAGE_DIR = process.env.STORAGE_DIR || __dirname;
const DATA_DIR = path.join(STORAGE_DIR, 'data');
const UPLOAD_DIR = path.join(STORAGE_DIR, 'uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const FOLDERS_FILE = path.join(DATA_DIR, 'folders.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(FILES_FILE)) fs.writeFileSync(FILES_FILE, '[]');
if (!fs.existsSync(FOLDERS_FILE)) fs.writeFileSync(FOLDERS_FILE, '[]');

const readJson = (p, fallback) => {
  try {
    if (!fs.existsSync(p)) return fallback;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  catch { return fallback; }
};
const writeJson = (p, data) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Header keamanan dasar ----
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ---- Enkripsi saat penyimpanan (AES-256-GCM) ----
// Semua isi file dienkripsi sebelum ditulis ke disk, dibuka hanya saat diunduh
// oleh pemiliknya yang sudah login. Kunci utama tersimpan di data/.master.key
// (dibuat otomatis sekali, permission 600). JANGAN hapus file kunci tersebut
// atau semua file tidak akan bisa dibuka lagi. Backup kunci = backup data.
function getMasterKey() {
  const kp = path.join(DATA_DIR, '.master.key');
  if (!fs.existsSync(kp)) {
    const k = crypto.randomBytes(32);
    fs.mkdirSync(path.dirname(kp), { recursive: true });
    fs.writeFileSync(kp, k, { mode: 0o600 });
    return k;
  }
  return fs.readFileSync(kp);
}
const MASTER_KEY = getMasterKey();

// Enkripsi file temp (plain) menjadi file .enc, lalu hapus file plain.
async function encryptFileToDisk(tempPath, destPath) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  await pipeline(fs.createReadStream(tempPath), cipher, fs.createWriteStream(destPath));
  const tag = cipher.getAuthTag();
  fs.unlinkSync(tempPath);
  return { iv: iv.toString('hex'), tag: tag.toString('hex') };
}

// Stream pembuka enkripsi untuk diunduh (verifikasi tag GCM otomatis).
function decryptFileStream(encPath, ivHex, tagHex) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return fs.createReadStream(encPath).pipe(decipher);
}

// ---- Auth helpers ----
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Belum login' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Token tidak valid, silakan login ulang' });
  }
}

function userFolder(username) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const dir = path.join(UPLOAD_DIR, username);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// Kuota menghitung SEMUA file termasuk isi sampah (kosongkan sampah untuk membebaskan)
function getUserUsage(username) {
  const files = readJson(FILES_FILE, []);
  return files.filter(f => f.owner === username).reduce((s, f) => s + f.size, 0);
}

// ---- Multer storage (simpan dengan nama unik, nama asli disimpan di metadata) ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const payload = jwt.verify(
        (req.headers.authorization || '').replace('Bearer ', ''),
        JWT_SECRET
      );
      cb(null, userFolder(payload.username));
    } catch {
      cb(new Error('Unauthorized'));
    }
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + Buffer.from(file.originalname, 'latin1').toString('utf8').replace(/[/\\?%*:|"<>]/g, '_'));
  }
});
const upload = multer({ storage });

// ---- API: Register ----
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ message: 'Username dan password wajib diisi' });
  if (username.length < 3)
    return res.status(400).json({ message: 'Username minimal 3 karakter' });
  if (password.length < 8)
    return res.status(400).json({ message: 'Password minimal 8 karakter' });
  if (!/^[a-zA-Z0-9_.-]+$/.test(username))
    return res.status(400).json({ message: 'Username hanya boleh huruf, angka, _ . -' });

  const users = readJson(USERS_FILE, []);
  if (users.find(u => u.username === username))
    return res.status(400).json({ message: 'Username sudah dipakai' });

  const hash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash: hash, quota: QUOTA_BYTES, createdAt: new Date().toISOString() });
  writeJson(USERS_FILE, users);
  userFolder(username);
  res.json({ message: 'Akun berhasil dibuat, silakan login' });
});

// ---- API: Login ----
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: 'Username atau password salah' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Username atau password salah' });
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

// ---- API: Info kuota ----
app.get('/api/quota', authMiddleware, (req, res) => {
  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.username === req.user.username);
  const quota = user ? user.quota : QUOTA_BYTES;
  const used = getUserUsage(req.user.username);
  res.json({ used, quota, free: quota - used, percent: +(used / quota * 100).toFixed(2) });
});

// ---- API: List file (sampah dikecualikan; lihat /api/trash) ----
app.get('/api/files', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  let files = readJson(FILES_FILE, []).filter(f => f.owner === req.user.username && !f.trashed);
  if ('folderId' in req.query) {
    const fid = req.query.folderId === 'root' || req.query.folderId === '' ? null : req.query.folderId;
    files = files.filter(f => (f.folderId || null) === fid);
  }
  if (q) files = files.filter(f => f.originalName.toLowerCase().includes(q));
  files.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json(files);
});

// ---- API: Folder ----
function getUserFolders(username) {
  return readJson(FOLDERS_FILE, []).filter(f => f.owner === username);
}

// Semua folder milik user (frontend yang menyusun path & breadcrumb)
app.get('/api/folders', authMiddleware, (req, res) => {
  res.json(getUserFolders(req.user.username).sort((a, b) => a.name.localeCompare(b.name)));
});

app.post('/api/folders', authMiddleware, (req, res) => {
  const { name, parentId } = req.body || {};
  if (!name || !String(name).trim())
    return res.status(400).json({ message: 'Nama folder wajib diisi' });
  const folders = readJson(FOLDERS_FILE, []);
  const parent = parentId ? folders.find(f => f.id === parentId && f.owner === req.user.username) : null;
  if (parentId && !parent)
    return res.status(400).json({ message: 'Folder induk tidak ditemukan' });
  const folder = {
    id: Date.now() + '-' + Math.round(Math.random() * 1e9),
    owner: req.user.username,
    name: String(name).trim().replace(/[/\\?%*:|"<>]/g, '_').slice(0, 80),
    parentId: parent ? parent.id : null,
    createdAt: new Date().toISOString()
  };
  folders.push(folder);
  writeJson(FOLDERS_FILE, folders);
  res.json({ message: 'Folder dibuat', folder });
});

app.patch('/api/folders/:id', authMiddleware, (req, res) => {
  const { newName, pinned } = req.body || {};
  if (newName === undefined && pinned === undefined)
    return res.status(400).json({ message: 'Tidak ada perubahan' });
  const folders = readJson(FOLDERS_FILE, []);
  const folder = folders.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!folder) return res.status(404).json({ message: 'Folder tidak ditemukan' });
  if (newName !== undefined) {
    if (!String(newName).trim()) return res.status(400).json({ message: 'Nama baru wajib diisi' });
    folder.name = String(newName).trim().replace(/[/\\?%*:|"<>]/g, '_').slice(0, 80);
  }
  if (pinned !== undefined) folder.pinned = !!pinned;
  writeJson(FOLDERS_FILE, folders);
  res.json({ message: 'Folder diperbarui', folder });
});

// Hapus folder beserta seluruh isi di dalamnya (rekursif)
app.delete('/api/folders/:id', authMiddleware, (req, res) => {
  let folders = readJson(FOLDERS_FILE, []);
  const root = folders.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!root) return res.status(404).json({ message: 'Folder tidak ditemukan' });
  const ids = new Set([root.id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of folders) {
      if (f.owner === req.user.username && f.parentId && ids.has(f.parentId) && !ids.has(f.id)) {
        ids.add(f.id); grew = true;
      }
    }
  }
  let files = readJson(FILES_FILE, []);
  let trashedFiles = 0;
  for (const f of files) {
    if (f.owner === req.user.username && !f.trashed && f.folderId && ids.has(f.folderId)) {
      f.trashed = true;
      f.trashedAt = new Date().toISOString();
      trashedFiles++;
    }
  }
  folders = folders.filter(f => !(f.owner === req.user.username && ids.has(f.id)));
  writeJson(FILES_FILE, files);
  writeJson(FOLDERS_FILE, folders);
  res.json({ message: `Folder dihapus, ${trashedFiles} file dipindah ke sampah` });
});

// Path folder untuk nama entry ZIP (mis. "Liburan/Bali/")
function folderZipPath(username, folderId) {
  if (!folderId) return '';
  const map = new Map(getUserFolders(username).map(f => [f.id, f]));
  const parts = [];
  const seen = new Set();
  let cur = folderId, guard = 0;
  while (cur && map.has(cur) && !seen.has(cur) && guard++ < 50) {
    seen.add(cur);
    parts.unshift(map.get(cur).name);
    cur = map.get(cur).parentId;
  }
  return parts.length ? parts.join('/') + '/' : '';
}

// ---- API: Upload (isi file dienkripsi sebelum disimpan) ----
app.post('/api/upload', authMiddleware, upload.array('files', 20), async (req, res) => {
  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.username === req.user.username);
  const quota = user ? user.quota : QUOTA_BYTES;

  let used = getUserUsage(req.user.username);
  const allFiles = readJson(FILES_FILE, []);
  const saved = [];
  let rejected = 0;
  let quotaRejected = 0;

  // Target folder upload (dari folder yang sedang dibuka)
  let folderId = null;
  if (req.body && req.body.folderId && req.body.folderId !== 'root') {
    const folders = readJson(FOLDERS_FILE, []);
    if (!folders.find(f => f.id === req.body.folderId && f.owner === req.user.username))
      return res.status(400).json({ message: 'Folder tujuan tidak ditemukan' });
    folderId = req.body.folderId;
  }

  for (const f of req.files) {
    if (used + f.size > quota) {
      fs.unlinkSync(f.path); // tolak file yang melebihi kuota 10 GB
      rejected++;
      quotaRejected++;
      continue;
    }
    try {
      const encPath = f.path + '.enc';
      const { iv, tag } = await encryptFileToDisk(f.path, encPath);
      const meta = {
        id: Date.now() + '-' + Math.round(Math.random() * 1e9),
        owner: req.user.username,
        originalName: Buffer.from(f.originalname, 'latin1').toString('utf8'),
        storedName: path.basename(encPath),
        size: f.size,
        mimetype: f.mimetype,
        folderId,
        encrypted: true,
        iv, tag,
        uploadedAt: new Date().toISOString()
      };
      allFiles.push(meta);
      saved.push(meta);
      used += f.size;
    } catch {
      if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
      rejected++;
    }
  }
  writeJson(FILES_FILE, allFiles);
  if (!saved.length && quotaRejected > 0)
    return res.status(400).json({ message: '⛔ Penyimpanan penuh (10 GB). Hapus file atau kosongkan sampah untuk menambah data.', files: saved, rejected });
  res.json({ message: `${saved.length} file berhasil diupload (tersimpan terenkripsi)`, files: saved, rejected });
});

// ---- API: Buat file teks langsung dari website (disimpan terenkripsi) ----
app.post('/api/create', authMiddleware, async (req, res) => {
  const { name, content, folderId } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ message: 'Nama file wajib diisi' });
  if (typeof content !== 'string')
    return res.status(400).json({ message: 'Isi file tidak valid' });
  let targetFolder = null;
  if (folderId && folderId !== 'root') {
    const folders = readJson(FOLDERS_FILE, []);
    if (!folders.find(f => f.id === folderId && f.owner === req.user.username))
      return res.status(400).json({ message: 'Folder tujuan tidak ditemukan' });
    targetFolder = folderId;
  }

  let safeName = name.trim().replace(/[/\\?%*:|"<>]/g, '_').slice(0, 100);
  if (!/\.[a-z0-9]{1,10}$/i.test(safeName)) safeName += '.txt'; // default .txt bila tanpa ekstensi
  const buf = Buffer.from(content, 'utf8');
  const MAX_TEXT = 10 * 1024 * 1024; // 10 MB per file teks
  if (buf.length > MAX_TEXT)
    return res.status(400).json({ message: 'Isi file maksimal 10 MB. Untuk file besar gunakan Upload.' });

  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.username === req.user.username);
  const quota = user ? user.quota : QUOTA_BYTES;
  if (getUserUsage(req.user.username) + buf.length > quota)
    return res.status(400).json({ message: 'Kuota 10 GB tidak cukup' });

  const dir = userFolder(req.user.username);
  const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
  const destPath = path.join(dir, unique + '-' + safeName + '.enc');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  fs.writeFileSync(destPath, enc);

  const ext = safeName.split('.').pop().toLowerCase();
  const mimeByExt = { txt: 'text/plain', md: 'text/markdown', html: 'text/html', css: 'text/css', js: 'text/javascript', json: 'application/json', csv: 'text/csv' };
  const meta = {
    id: unique + '-' + Math.round(Math.random() * 1e9),
    owner: req.user.username,
    originalName: safeName,
    storedName: path.basename(destPath),
    size: buf.length,
    mimetype: mimeByExt[ext] || 'text/plain',
    folderId: targetFolder,
    encrypted: true,
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    uploadedAt: new Date().toISOString()
  };
  const allFiles = readJson(FILES_FILE, []);
  allFiles.push(meta);
  writeJson(FILES_FILE, allFiles);
  res.json({ message: 'File berhasil dibuat dan disimpan terenkripsi', file: meta });
});

// ---- API: Download (file terenkripsi dibuka khusus untuk pemiliknya) ----
app.get('/api/files/:id/download', authMiddleware, (req, res) => {
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (meta.trashed) return res.status(404).json({ message: 'File ada di sampah, pulihkan dulu untuk mengunduh' });
  const fullPath = path.join(userFolder(req.user.username), meta.storedName);
  if (!fs.existsSync(fullPath)) return res.status(404).json({ message: 'File fisik hilang' });
  if (!meta.encrypted) return res.download(fullPath, meta.originalName); // file lama (sebelum enkripsi)
  res.setHeader('Content-Type', meta.mimetype || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(meta.originalName)}`);
  const stream = decryptFileStream(fullPath, meta.iv, meta.tag);
  stream.on('error', () => {
    if (!res.headersSent) return res.status(410).json({ message: 'File rusak / tidak bisa dibuka' });
    res.end();
  });
  stream.pipe(res);
});

// ---- API: Hapus banyak file sekaligus → pindah ke SAMPAH (bisa dipulihkan) ----
app.delete('/api/files', authMiddleware, (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || !ids.length)
    return res.status(400).json({ message: 'Pilih dulu file yang ingin dihapus' });
  const idSet = new Set(ids);
  const files = readJson(FILES_FILE, []);
  let removed = 0;
  for (const f of files) {
    if (f.owner === req.user.username && !f.trashed && idSet.has(f.id)) {
      f.trashed = true;
      f.trashedAt = new Date().toISOString();
      removed++;
    }
  }
  writeJson(FILES_FILE, files);
  res.json({ message: `${removed} file dipindah ke sampah` });
});

// ---- API: Hapus 1 file → pindah ke SAMPAH (bisa dipulihkan) ----
app.delete('/api/files/:id', authMiddleware, (req, res) => {
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (meta.trashed) return res.status(400).json({ message: 'File sudah ada di sampah' });
  meta.trashed = true;
  meta.trashedAt = new Date().toISOString();
  writeJson(FILES_FILE, files);
  res.json({ message: 'File dipindah ke sampah' });
});

// ---- API: SAMPAH (recovery) ----
app.get('/api/trash', authMiddleware, (req, res) => {
  const files = readJson(FILES_FILE, [])
    .filter(f => f.owner === req.user.username && f.trashed)
    .sort((a, b) => new Date(b.trashedAt || b.uploadedAt) - new Date(a.trashedAt || a.uploadedAt));
  res.json(files);
});

// Pulihkan file dari sampah (kembali ke folder asal; bila foldernya sudah tidak ada → Utama)
app.post('/api/files/:id/restore', authMiddleware, (req, res) => {
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (!meta.trashed) return res.status(400).json({ message: 'File tidak ada di sampah' });
  if (meta.folderId) {
    const folders = readJson(FOLDERS_FILE, []);
    if (!folders.find(f => f.id === meta.folderId && f.owner === req.user.username)) meta.folderId = null;
  }
  delete meta.trashed;
  delete meta.trashedAt;
  writeJson(FILES_FILE, files);
  res.json({ message: 'File dipulihkan', file: meta });
});

// Hapus permanen 1 file (tidak bisa dipulihkan)
app.delete('/api/files/:id/permanent', authMiddleware, (req, res) => {
  let files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  const fullPath = path.join(userFolder(req.user.username), meta.storedName);
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  files = files.filter(f => f.id !== meta.id);
  writeJson(FILES_FILE, files);
  res.json({ message: 'File dihapus permanen' });
});

// Kosongkan sampah (hapus permanen semua isi sampah)
app.delete('/api/trash', authMiddleware, (req, res) => {
  let files = readJson(FILES_FILE, []);
  let removed = 0;
  files = files.filter(f => {
    if (f.owner === req.user.username && f.trashed) {
      const p = path.join(userFolder(req.user.username), f.storedName);
      if (fs.existsSync(p)) fs.unlinkSync(p);
      removed++;
      return false;
    }
    return true;
  });
  writeJson(FILES_FILE, files);
  res.json({ message: `Sampah dikosongkan (${removed} file dihapus permanen)` });
});

// ---- API: Baca isi file teks (untuk dibuka & diedit langsung di website) ----
const MAX_EDIT_BYTES = 5 * 1024 * 1024; // 5 MB
function isEditableMeta(meta) {
  if (!meta || meta.size > MAX_EDIT_BYTES) return false;
  const t = meta.mimetype || '';
  const ext = (meta.originalName.split('.').pop() || '').toLowerCase();
  return t.startsWith('text/') || t === 'application/json' ||
    ['txt', 'md', 'html', 'css', 'js', 'json', 'csv', 'xml', 'log'].includes(ext);
}

app.get('/api/files/:id/content', authMiddleware, (req, res) => {
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (meta.trashed) return res.status(404).json({ message: 'File ada di sampah, pulihkan dulu untuk dibuka' });
  if (!isEditableMeta(meta))
    return res.status(400).json({ message: 'Hanya file teks (txt, md, html, dll, maks 5 MB) yang bisa dibuka di website. File lain silakan Unduh.' });
  const fullPath = path.join(userFolder(req.user.username), meta.storedName);
  if (!fs.existsSync(fullPath)) return res.status(404).json({ message: 'File fisik hilang' });
  try {
    let buf;
    if (meta.encrypted) {
      const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(meta.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(meta.tag, 'hex'));
      buf = Buffer.concat([decipher.update(fs.readFileSync(fullPath)), decipher.final()]);
    } else {
      buf = fs.readFileSync(fullPath);
    }
    res.json({ content: buf.toString('utf8') });
  } catch {
    res.status(410).json({ message: 'File rusak / tidak bisa dibuka' });
  }
});

// ---- API: Simpan hasil edit file teks ----
app.put('/api/files/:id/content', authMiddleware, (req, res) => {
  const { content } = req.body || {};
  if (typeof content !== 'string')
    return res.status(400).json({ message: 'Isi file tidak valid' });
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (meta.trashed) return res.status(400).json({ message: 'File ada di sampah, pulihkan dulu untuk diubah' });
  if (!isEditableMeta(meta) && Buffer.byteLength(content, 'utf8') > 0)
    return res.status(400).json({ message: 'File ini tidak bisa diedit di website' });

  const buf = Buffer.from(content, 'utf8');
  if (buf.length > MAX_EDIT_BYTES)
    return res.status(400).json({ message: 'Isi file maksimal 5 MB' });

  const users = readJson(USERS_FILE, []);
  const user = users.find(u => u.username === req.user.username);
  const quota = user ? user.quota : QUOTA_BYTES;
  if (getUserUsage(req.user.username) - meta.size + buf.length > quota)
    return res.status(400).json({ message: 'Kuota 10 GB tidak cukup untuk menyimpan perubahan' });

  const fullPath = path.join(userFolder(req.user.username), meta.storedName);
  try {
    if (meta.encrypted) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
      fs.writeFileSync(fullPath, Buffer.concat([cipher.update(buf), cipher.final()]));
      meta.iv = iv.toString('hex');
      meta.tag = cipher.getAuthTag().toString('hex');
    } else {
      fs.writeFileSync(fullPath, buf);
    }
    meta.size = buf.length;
    writeJson(FILES_FILE, files);
    res.json({ message: 'Perubahan disimpan', size: buf.length });
  } catch {
    res.status(500).json({ message: 'Gagal menyimpan perubahan' });
  }
});
// ---- API: Rename / Sematkan (pin) / Pindah folder ----
app.patch('/api/files/:id', authMiddleware, (req, res) => {
  const { newName, pinned, folderId } = req.body || {};
  if (newName === undefined && pinned === undefined && folderId === undefined)
    return res.status(400).json({ message: 'Tidak ada perubahan' });
  const files = readJson(FILES_FILE, []);
  const meta = files.find(f => f.id === req.params.id && f.owner === req.user.username);
  if (!meta) return res.status(404).json({ message: 'File tidak ditemukan' });
  if (meta.trashed) return res.status(400).json({ message: 'File ada di sampah, pulihkan dulu' });
  if (newName !== undefined) {
    if (!String(newName).trim()) return res.status(400).json({ message: 'Nama baru wajib diisi' });
    meta.originalName = String(newName).replace(/[/\\?%*:|"<>]/g, '_');
  }
  if (pinned !== undefined) meta.pinned = !!pinned;
  if (folderId !== undefined) {
    if (folderId && folderId !== 'root') {
      const folders = readJson(FOLDERS_FILE, []);
      if (!folders.find(f => f.id === folderId && f.owner === req.user.username))
        return res.status(400).json({ message: 'Folder tujuan tidak ditemukan' });
      meta.folderId = folderId;
    } else {
      meta.folderId = null;
    }
  }
  writeJson(FILES_FILE, files);
  res.json({ message: 'File diperbarui', file: meta });
});

// ---- API: Unduh sebagai ZIP ----
// Tanpa folderId: seluruh file (cadangan akun).
// Dengan ?folderId=: hanya isi folder itu (+ subfolder), path relatif jadi nama foldernya.
app.get('/api/download-all', authMiddleware, (req, res) => {
  let files = readJson(FILES_FILE, []).filter(f => f.owner === req.user.username && !f.trashed);
  let zipName = `datavora-backup-${req.user.username}.zip`;
  let stripPrefix = '';
  let wrapFolder = ''; // pembungkus agar hasil ekstrak = folder utuh berisi file
  const qfid = req.query.folderId;
  if (qfid) {
    const folders = readJson(FOLDERS_FILE, []).filter(f => f.owner === req.user.username);
    const rootFolder = folders.find(f => f.id === qfid);
    if (!rootFolder) return res.status(404).json({ message: 'Folder tidak ditemukan' });
    const ids = new Set([qfid]);
    let grew = true, g = 0;
    while (grew && g++ < 50) {
      grew = false;
      for (const f of folders) {
        if (f.parentId && ids.has(f.parentId) && !ids.has(f.id)) { ids.add(f.id); grew = true; }
      }
    }
    files = files.filter(f => f.folderId && ids.has(f.folderId));
    stripPrefix = folderZipPath(req.user.username, qfid);
    const safeRoot = rootFolder.name.replace(/[/\\?%*:|"<>]/g, '_');
    wrapFolder = safeRoot + '/';
    zipName = `datavora-${safeRoot}.zip`;
  }
  if (!files.length) return res.status(404).json({ message: 'Belum ada file untuk diunduh' });
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
  const archive = createArchive('zip', { zlib: { level: 6 } });
  archive.on('error', () => { if (!res.headersSent) res.status(500).end(); });
  archive.pipe(res);
  const usedNames = new Set();
  const uniqueName = (name) => {
    if (!usedNames.has(name)) { usedNames.add(name); return name; }
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : '';
    const base = ext ? name.slice(0, -ext.length) : name;
    let i = 1, candidate;
    do { candidate = `${base} (${i})${ext}`; i++; } while (usedNames.has(candidate));
    usedNames.add(candidate);
    return candidate;
  };
  for (const meta of files) {
    const fullPath = path.join(userFolder(req.user.username), meta.storedName);
    if (!fs.existsSync(fullPath)) continue;
    // Pertahankan struktur folder di dalam ZIP.
    // Bila mengunduh satu folder: potong path induk, lalu bungkus dengan nama
    // folder itu agar hasil ekstrak = folder utuh berisi semua file.
    let entry = folderZipPath(req.user.username, meta.folderId) + meta.originalName;
    if (stripPrefix && entry.startsWith(stripPrefix)) entry = entry.slice(stripPrefix.length);
    if (wrapFolder) entry = wrapFolder + entry;
    const name = uniqueName(entry);
    if (meta.encrypted) archive.append(decryptFileStream(fullPath, meta.iv, meta.tag), { name });
    else archive.append(fs.createReadStream(fullPath), { name });
  }
  archive.finalize();
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
