import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';
import { Zip, ZipPassThrough } from 'fflate';

// === Datavora API — Cloudflare Workers + R2 + D1 ===
// Paritas fitur dengan server.js (Node): auth, kuota 10 GB, folder, upload
// terenkripsi AES-256-GCM, buat/edit file teks, sampah, pin, ZIP.
//
// Batasan platform (jujur): Worker buffering per file di memori (maks 128 MB),
// jadi 1 file dibatasi 50 MB. R2 gratis 10 GB = pas untuk kuota. Untuk produksi
// disarankan Workers Paid ($5/bln, CPU longgar untuk enkripsi); Free hanya
// untuk coba-coba.

const QUOTA_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB
const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MB per file (limit memori Worker)
const MAX_TEXT_BYTES = 10 * 1024 * 1024;
const MAX_EDIT_BYTES = 5 * 1024 * 1024;
const PBKDF2_ITER = 120000;
const DEV_JWT = 'dev-only-change-me';

const app = new Hono();
app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));

// ---------- util ----------
const nowISO = () => new Date().toISOString();
const uid = () => `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g).map(b => parseInt(b, 16)));
const te = new TextEncoder();
const td = new TextDecoder();
const sanitize = (s, max) => String(s).replace(/[/\\?%*:|"<>]/g, '_').slice(0, max);

async function pbkdf2(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: unhex(saltHex), iterations: PBKDF2_ITER, hash: 'SHA-256' },
    key, 256
  );
  return hex(bits);
}

let _masterKey = null;
async function masterKey(env) {
  if (_masterKey) return _masterKey;
  let raw;
  if (env.MASTER_KEY) {
    raw = Uint8Array.from(atob(env.MASTER_KEY), c => c.charCodeAt(0));
  } else {
    console.warn('MASTER_KEY tidak diset — memakai kunci ephemeral (file tak terbaca setelah restart). Set via: wrangler secret put MASTER_KEY');
    raw = crypto.getRandomValues(new Uint8Array(32));
  }
  _masterKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return _masterKey;
}

// Enkripsi: kembalikan {data (hex, tanpa tag), iv, tag} — tag = 16 byte terakhir GCM
async function encBuf(env, buf) {
  const key = await masterKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf));
  return { data: hex(out.slice(0, -16)), iv: hex(iv), tag: hex(out.slice(-16)) };
}
async function decBuf(env, dataHex, ivHex, tagHex) {
  const key = await masterKey(env);
  const data = unhex(dataHex), tag = unhex(tagHex);
  const joined = new Uint8Array(data.length + tag.length);
  joined.set(data); joined.set(tag, data.length);
  return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(ivHex) }, key, joined);
}

const jwtSecret = (env) => env.JWT_SECRET || DEV_JWT;

async function auth(c, next) {
  const h = c.req.header('Authorization') || '';
  if (!h.startsWith('Bearer ')) return c.json({ message: 'Belum login' }, 401);
  try {
    const payload = await verify(h.slice(7), jwtSecret(c.env), 'HS256');
    c.set('username', payload.username);
    await next();
  } catch {
    return c.json({ message: 'Token tidak valid, silakan login ulang' }, 401);
  }
}

async function usage(db, username) {
  const r = await db.prepare('SELECT COALESCE(SUM(size),0) AS used FROM files WHERE owner=?').bind(username).first();
  return r ? r.used : 0;
}
async function userQuota(db, username) {
  const u = await db.prepare('SELECT quota FROM users WHERE username=?').bind(username).first();
  return u ? u.quota : QUOTA_BYTES;
}
// Bentuk API sama persis dengan server.js (camelCase) agar frontend tak berubah
function fileOut(r) {
  if (!r) return r;
  return {
    id: r.id, owner: r.owner, originalName: r.original_name, storedName: r.stored_name,
    size: r.size, mimetype: r.mimetype, folderId: r.folder_id || null,
    encrypted: !!r.encrypted, iv: r.iv, tag: r.tag, pinned: !!r.pinned,
    trashed: !!r.trashed, trashedAt: r.trashed_at || null, uploadedAt: r.uploaded_at
  };
}
function folderOut(r) {
  if (!r) return r;
  return { id: r.id, owner: r.owner, name: r.name, parentId: r.parent_id || null, pinned: !!r.pinned, createdAt: r.created_at };
}

// ---------- root ----------
app.get('/', (c) => c.json({ app: 'Datavora API (Workers)', storage: 'R2 + D1' }));

// ---------- register / login ----------
app.post('/api/register', async (c) => {
  const { username, password } = await c.req.json().catch(() => ({}));
  if (!username || !password) return c.json({ message: 'Username dan password wajib diisi' }, 400);
  if (username.length < 3) return c.json({ message: 'Username minimal 3 karakter' }, 400);
  if (password.length < 8) return c.json({ message: 'Password minimal 8 karakter' }, 400);
  if (!/^[a-zA-Z0-9_.-]+$/.test(username))
    return c.json({ message: 'Username hanya boleh huruf, angka, _ . -' }, 400);
  const exists = await c.env.DB.prepare('SELECT 1 FROM users WHERE username=?').bind(username).first();
  if (exists) return c.json({ message: 'Username sudah dipakai' }, 400);
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await pbkdf2(password, salt);
  await c.env.DB.prepare('INSERT INTO users(username,password_hash,salt,quota,created_at) VALUES(?,?,?,?,?)')
    .bind(username, hash, salt, QUOTA_BYTES, nowISO()).run();
  return c.json({ message: 'Akun berhasil dibuat, silakan login' });
});

app.post('/api/login', async (c) => {
  const { username, password } = await c.req.json().catch(() => ({}));
  const u = await c.env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
  if (!u) return c.json({ message: 'Username atau password salah' }, 401);
  const hash = await pbkdf2(password, u.salt);
  if (hash !== u.password_hash) return c.json({ message: 'Username atau password salah' }, 401);
  const token = await sign({ username: u.username, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }, jwtSecret(c.env), 'HS256');
  return c.json({ token, username: u.username });
});

// ---------- quota / list ----------
app.get('/api/quota', auth, async (c) => {
  const username = c.get('username');
  const used = await usage(c.env.DB, username);
  const quota = await userQuota(c.env.DB, username);
  return c.json({ used, quota, free: quota - used, percent: +(used / quota * 100).toFixed(2) });
});

app.get('/api/files', auth, async (c) => {
  const username = c.get('username');
  const q = (c.req.query('q') || '').toLowerCase();
  const fidRaw = c.req.query('folderId');
  let sql = 'SELECT * FROM files WHERE owner=? AND trashed=0';
  const args = [username];
  if (fidRaw !== undefined) {
    const fid = fidRaw === 'root' || fidRaw === '' ? null : fidRaw;
    sql += fid === null ? ' AND folder_id IS NULL' : ' AND folder_id=?';
    if (fid !== null) args.push(fid);
  }
  if (q) { sql += ' AND LOWER(original_name) LIKE ?'; args.push(`%${q}%`); }
  sql += ' ORDER BY uploaded_at DESC';
  const { results } = await c.env.DB.prepare(sql).bind(...args).all();
  return c.json(results.map(fileOut));
});

// ---------- folders ----------
app.get('/api/folders', auth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM folders WHERE owner=? ORDER BY name')
    .bind(c.get('username')).all();
  return c.json(results.map(folderOut));
});

app.post('/api/folders', auth, async (c) => {
  const username = c.get('username');
  const { name, parentId } = await c.req.json().catch(() => ({}));
  if (!name || !String(name).trim()) return c.json({ message: 'Nama folder wajib diisi' }, 400);
  let parent = null;
  if (parentId) {
    parent = await c.env.DB.prepare('SELECT * FROM folders WHERE id=? AND owner=?').bind(parentId, username).first();
    if (!parent) return c.json({ message: 'Folder induk tidak ditemukan' }, 400);
  }
  const folder = { id: uid(), owner: username, name: sanitize(String(name).trim(), 80), parentId: parent ? parent.id : null, pinned: false, createdAt: nowISO() };
  await c.env.DB.prepare('INSERT INTO folders(id,owner,name,parent_id,pinned,created_at) VALUES(?,?,?,?,?,?)')
    .bind(folder.id, username, folder.name, folder.parentId, 0, folder.createdAt).run();
  return c.json({ message: 'Folder dibuat', folder });
});

app.patch('/api/folders/:id', auth, async (c) => {
  const username = c.get('username');
  const { newName, pinned } = await c.req.json().catch(() => ({}));
  if (newName === undefined && pinned === undefined) return c.json({ message: 'Tidak ada perubahan' }, 400);
  const f = await c.env.DB.prepare('SELECT * FROM folders WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!f) return c.json({ message: 'Folder tidak ditemukan' }, 404);
  if (newName !== undefined) {
    if (!String(newName).trim()) return c.json({ message: 'Nama baru wajib diisi' }, 400);
    await c.env.DB.prepare('UPDATE folders SET name=? WHERE id=?').bind(sanitize(String(newName).trim(), 80), f.id).run();
  }
  if (pinned !== undefined)
    await c.env.DB.prepare('UPDATE folders SET pinned=? WHERE id=?').bind(pinned ? 1 : 0, f.id).run();
  const updated = await c.env.DB.prepare('SELECT * FROM folders WHERE id=?').bind(f.id).first();
  return c.json({ message: 'Folder diperbarui', folder: folderOut(updated) });
});

app.delete('/api/folders/:id', auth, async (c) => {
  const username = c.get('username');
  const root = await c.env.DB.prepare('SELECT * FROM folders WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!root) return c.json({ message: 'Folder tidak ditemukan' }, 404);
  const { results } = await c.env.DB.prepare('SELECT * FROM folders WHERE owner=?').bind(username).all();
  const ids = new Set([root.id]);
  let grew = true, g = 0;
  while (grew && g++ < 50) {
    grew = false;
    for (const f of results) {
      if (f.parent_id && ids.has(f.parent_id) && !ids.has(f.id)) { ids.add(f.id); grew = true; }
    }
  }
  const now = nowISO();
  let trashed = 0;
  for (const id of ids) {
    const r = await c.env.DB.prepare('UPDATE files SET trashed=1, trashed_at=? WHERE owner=? AND folder_id=? AND trashed=0')
      .bind(now, username, id).run();
    trashed += r.meta.changes || 0;
  }
  for (const id of ids)
    await c.env.DB.prepare('DELETE FROM folders WHERE id=? AND owner=?').bind(id, username).run();
  return c.json({ message: `Folder dihapus, ${trashed} file dipindah ke sampah` });
});

async function folderZipPath(db, username, folderId) {
  if (!folderId) return '';
  const { results } = await db.prepare('SELECT * FROM folders WHERE owner=?').bind(username).all();
  const map = new Map(results.map(f => [f.id, f]));
  const parts = [], seen = new Set();
  let cur = folderId, n = 0;
  while (cur && map.has(cur) && !seen.has(cur) && n++ < 50) {
    seen.add(cur); parts.unshift(map.get(cur).name); cur = map.get(cur).parent_id;
  }
  return parts.length ? parts.join('/') + '/' : '';
}

// ---------- upload ----------
app.post('/api/upload', auth, async (c) => {
  const username = c.get('username');
  const len = Number(c.req.header('content-length') || 0);
  if (len > MAX_FILE_BYTES * 20) return c.json({ message: 'Total upload terlalu besar' }, 413);
  const body = await c.req.parseBody({ all: true });
  const firstVal = (v) => Array.isArray(v) ? v[0] : v;
  const allVals = (v) => (!v ? [] : Array.isArray(v) ? v.flat() : [v]);
  let folderId = null;
  const folderIdRaw = firstVal(body.folderId);
  if (folderIdRaw && folderIdRaw !== 'root') {
    const f = await c.env.DB.prepare('SELECT 1 FROM folders WHERE id=? AND owner=?').bind(folderIdRaw, username).first();
    if (!f) return c.json({ message: 'Folder tujuan tidak ditemukan' }, 400);
    folderId = folderIdRaw;
  }
  let incoming = allVals(body.files);
  if (!incoming.length) return c.json({ message: 'Tidak ada file' }, 400);
  incoming = incoming.slice(0, 20);
  const quota = await userQuota(c.env.DB, username);
  let used = await usage(c.env.DB, username);
  const saved = [];
  let rejected = 0;
  for (const file of incoming) {
    if (typeof file === 'string' || file.size > MAX_FILE_BYTES || used + file.size > quota) { rejected++; continue; }
    const buf = new Uint8Array(await file.arrayBuffer());
    const originalName = file.name || 'file';
    const storedName = `${uid()}-${sanitize(originalName, 100)}.enc`;
    const { data, iv, tag } = await encBuf(c.env, buf);
    await c.env.BUCKET.put(storedName, unhex(data), { httpMetadata: { contentType: 'application/octet-stream' } });
    const meta = {
      id: uid(), owner: username, originalName, storedName, size: file.size,
      mimetype: file.type || 'application/octet-stream', folderId,
      encrypted: 1, iv, tag, pinned: 0, trashed: 0, trashedAt: null, uploadedAt: nowISO()
    };
    await c.env.DB.prepare(
      'INSERT INTO files(id,owner,original_name,stored_name,size,mimetype,folder_id,encrypted,iv,tag,pinned,trashed,trashed_at,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(meta.id, username, originalName, storedName, file.size, meta.mimetype, folderId, 1, iv, tag, 0, 0, null, meta.uploadedAt).run();
    saved.push({
      id: meta.id, owner: username, originalName, storedName, size: file.size,
      mimetype: meta.mimetype, folderId, encrypted: true, iv, tag,
      pinned: false, trashed: false, trashedAt: null, uploadedAt: meta.uploadedAt
    });
    used += file.size;
  }
  return c.json({ message: `${saved.length} file berhasil diupload (tersimpan terenkripsi)`, files: saved, rejected });
});

// ---------- buat file teks ----------
const MIME_BY_EXT = { txt: 'text/plain', md: 'text/markdown', html: 'text/html', css: 'text/css', js: 'text/javascript', json: 'application/json', csv: 'text/csv' };
app.post('/api/create', auth, async (c) => {
  const username = c.get('username');
  const { name, content, folderId } = await c.req.json().catch(() => ({}));
  if (!name || typeof name !== 'string' || !name.trim()) return c.json({ message: 'Nama file wajib diisi' }, 400);
  if (typeof content !== 'string') return c.json({ message: 'Isi file tidak valid' }, 400);
  let targetFolder = null;
  if (folderId && folderId !== 'root') {
    const f = await c.env.DB.prepare('SELECT 1 FROM folders WHERE id=? AND owner=?').bind(folderId, username).first();
    if (!f) return c.json({ message: 'Folder tujuan tidak ditemukan' }, 400);
    targetFolder = folderId;
  }
  let safeName = sanitize(name.trim(), 100);
  if (!/\.[a-z0-9]{1,10}$/i.test(safeName)) safeName += '.txt';
  const buf = te.encode(content);
  if (buf.length > MAX_TEXT_BYTES) return c.json({ message: 'Isi file maksimal 10 MB. Untuk file besar gunakan Upload.' }, 400);
  const quota = await userQuota(c.env.DB, username);
  if (await usage(c.env.DB, username) + buf.length > quota) return c.json({ message: 'Kuota 10 GB tidak cukup' }, 400);
  const storedName = `${uid()}-${safeName}.enc`;
  const { data, iv, tag } = await encBuf(c.env, buf);
  await c.env.BUCKET.put(storedName, unhex(data), { httpMetadata: { contentType: 'application/octet-stream' } });
  const ext = safeName.split('.').pop().toLowerCase();
  const id = uid(), uploadedAt = nowISO();
  await c.env.DB.prepare(
    'INSERT INTO files(id,owner,original_name,stored_name,size,mimetype,folder_id,encrypted,iv,tag,pinned,trashed,trashed_at,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, username, safeName, storedName, buf.length, MIME_BY_EXT[ext] || 'text/plain', targetFolder, 1, iv, tag, 0, 0, null, uploadedAt).run();
  return c.json({ message: 'File berhasil dibuat dan disimpan terenkripsi', file: { id, owner: username, originalName: safeName, storedName, size: buf.length, mimetype: MIME_BY_EXT[ext] || 'text/plain', folderId: targetFolder, encrypted: true, iv, tag, uploadedAt } });
});

// ---------- download ----------
async function getLiveFile(db, username, id) {
  const meta = await db.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(id, username).first();
  if (!meta) return { err: 404, message: 'File tidak ditemukan' };
  if (meta.trashed) return { err: 404, message: 'File ada di sampah, pulihkan dulu untuk mengunduh' };
  return { meta };
}
app.get('/api/files/:id/download', auth, async (c) => {
  const username = c.get('username');
  const { meta, err, message } = await getLiveFile(c.env.DB, username, c.req.param('id'));
  if (err) return c.json({ message }, err);
  const obj = await c.env.BUCKET.get(meta.stored_name);
  if (!obj) return c.json({ message: 'File fisik hilang' }, 404);
  try {
    const plain = await decBuf(c.env, hex(await obj.arrayBuffer()), meta.iv, meta.tag);
    return new Response(plain, {
      headers: {
        'Content-Type': meta.mimetype || 'application/octet-stream',
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(meta.original_name)}`
      }
    });
  } catch {
    return c.json({ message: 'File rusak / tidak bisa dibuka' }, 410);
  }
});

// ---------- hapus → sampah / restore / permanen ----------
app.delete('/api/files', auth, async (c) => {
  const username = c.get('username');
  const { ids } = await c.req.json().catch(() => ({}));
  if (!Array.isArray(ids) || !ids.length) return c.json({ message: 'Pilih dulu file yang ingin dihapus' }, 400);
  let removed = 0;
  for (const id of ids.slice(0, 100)) {
    const r = await c.env.DB.prepare('UPDATE files SET trashed=1, trashed_at=? WHERE id=? AND owner=? AND trashed=0')
      .bind(nowISO(), id, username).run();
    removed += r.meta.changes || 0;
  }
  return c.json({ message: `${removed} file dipindah ke sampah` });
});

app.delete('/api/files/:id', auth, async (c) => {
  const username = c.get('username');
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  if (meta.trashed) return c.json({ message: 'File sudah ada di sampah' }, 400);
  await c.env.DB.prepare('UPDATE files SET trashed=1, trashed_at=? WHERE id=?').bind(nowISO(), meta.id).run();
  return c.json({ message: 'File dipindah ke sampah' });
});

app.get('/api/trash', auth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM files WHERE owner=? AND trashed=1 ORDER BY trashed_at DESC')
    .bind(c.get('username')).all();
  return c.json(results.map(fileOut));
});

app.post('/api/files/:id/restore', auth, async (c) => {
  const username = c.get('username');
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  if (!meta.trashed) return c.json({ message: 'File tidak ada di sampah' }, 400);
  let folderId = meta.folder_id;
  if (folderId) {
    const f = await c.env.DB.prepare('SELECT 1 FROM folders WHERE id=? AND owner=?').bind(folderId, username).first();
    if (!f) folderId = null;
  }
  await c.env.DB.prepare('UPDATE files SET trashed=0, trashed_at=NULL, folder_id=? WHERE id=?').bind(folderId, meta.id).run();
  return c.json({ message: 'File dipulihkan' });
});

app.delete('/api/files/:id/permanent', auth, async (c) => {
  const username = c.get('username');
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  await c.env.BUCKET.delete(meta.stored_name);
  await c.env.DB.prepare('DELETE FROM files WHERE id=?').bind(meta.id).run();
  return c.json({ message: 'File dihapus permanen' });
});

app.delete('/api/trash', auth, async (c) => {
  const username = c.get('username');
  const { results } = await c.env.DB.prepare('SELECT * FROM files WHERE owner=? AND trashed=1').bind(username).all();
  for (const f of results) await c.env.BUCKET.delete(f.stored_name);
  await c.env.DB.prepare('DELETE FROM files WHERE owner=? AND trashed=1').bind(username).run();
  return c.json({ message: `Sampah dikosongkan (${results.length} file dihapus permanen)` });
});

// ---------- baca / edit isi teks ----------
const EDITABLE_EXT = ['txt', 'md', 'html', 'css', 'js', 'json', 'csv', 'xml', 'log'];
function editableMeta(meta) {
  if (!meta || meta.size > MAX_EDIT_BYTES) return false;
  const t = meta.mimetype || '';
  const ext = (meta.original_name.split('.').pop() || '').toLowerCase();
  return t.startsWith('text/') || t === 'application/json' || EDITABLE_EXT.includes(ext);
}
app.get('/api/files/:id/content', auth, async (c) => {
  const username = c.get('username');
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  if (meta.trashed) return c.json({ message: 'File ada di sampah, pulihkan dulu untuk dibuka' }, 404);
  if (!editableMeta(meta)) return c.json({ message: 'Hanya file teks (txt, md, html, dll, maks 5 MB) yang bisa dibuka di website. File lain silakan Unduh.' }, 400);
  const obj = await c.env.BUCKET.get(meta.stored_name);
  if (!obj) return c.json({ message: 'File fisik hilang' }, 404);
  try {
    const plain = await decBuf(c.env, hex(await obj.arrayBuffer()), meta.iv, meta.tag);
    return c.json({ content: td.decode(plain) });
  } catch {
    return c.json({ message: 'File rusak / tidak bisa dibuka' }, 410);
  }
});

app.put('/api/files/:id/content', auth, async (c) => {
  const username = c.get('username');
  const { content } = await c.req.json().catch(() => ({}));
  if (typeof content !== 'string') return c.json({ message: 'Isi file tidak valid' }, 400);
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  if (meta.trashed) return c.json({ message: 'File ada di sampah, pulihkan dulu untuk diubah' }, 400);
  if (!editableMeta(meta) && te.encode(content).length > 0) return c.json({ message: 'File ini tidak bisa diedit di website' }, 400);
  const buf = te.encode(content);
  if (buf.length > MAX_EDIT_BYTES) return c.json({ message: 'Isi file maksimal 5 MB' }, 400);
  const quota = await userQuota(c.env.DB, username);
  if (await usage(c.env.DB, username) - meta.size + buf.length > quota)
    return c.json({ message: 'Kuota 10 GB tidak cukup untuk menyimpan perubahan' }, 400);
  const { data, iv, tag } = await encBuf(c.env, buf);
  await c.env.BUCKET.put(meta.stored_name, unhex(data), { httpMetadata: { contentType: 'application/octet-stream' } });
  await c.env.DB.prepare('UPDATE files SET size=?, iv=?, tag=? WHERE id=?').bind(buf.length, iv, tag, meta.id).run();
  return c.json({ message: 'Perubahan disimpan', size: buf.length });
});

// ---------- rename / pin / pindah ----------
app.patch('/api/files/:id', auth, async (c) => {
  const username = c.get('username');
  const { newName, pinned, folderId } = await c.req.json().catch(() => ({}));
  if (newName === undefined && pinned === undefined && folderId === undefined)
    return c.json({ message: 'Tidak ada perubahan' }, 400);
  const meta = await c.env.DB.prepare('SELECT * FROM files WHERE id=? AND owner=?').bind(c.req.param('id'), username).first();
  if (!meta) return c.json({ message: 'File tidak ditemukan' }, 404);
  if (meta.trashed) return c.json({ message: 'File ada di sampah, pulihkan dulu' }, 400);
  if (newName !== undefined) {
    if (!String(newName).trim()) return c.json({ message: 'Nama baru wajib diisi' }, 400);
    await c.env.DB.prepare('UPDATE files SET original_name=? WHERE id=?').bind(sanitize(newName, 100), meta.id).run();
  }
  if (pinned !== undefined)
    await c.env.DB.prepare('UPDATE files SET pinned=? WHERE id=?').bind(pinned ? 1 : 0, meta.id).run();
  if (folderId !== undefined) {
    if (folderId && folderId !== 'root') {
      const f = await c.env.DB.prepare('SELECT 1 FROM folders WHERE id=? AND owner=?').bind(folderId, username).first();
      if (!f) return c.json({ message: 'Folder tujuan tidak ditemukan' }, 400);
      await c.env.DB.prepare('UPDATE files SET folder_id=? WHERE id=?').bind(folderId, meta.id).run();
    } else {
      await c.env.DB.prepare('UPDATE files SET folder_id=NULL WHERE id=?').bind(meta.id).run();
    }
  }
  const updated = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(meta.id).first();
  return c.json({ message: 'File diperbarui', file: fileOut(updated) });
});

// ---------- ZIP ----------
app.get('/api/download-all', auth, async (c) => {
  const username = c.get('username');
  const qfid = c.req.query('folderId');
  let files, stripPrefix = '', wrapFolder = '', zipName = `datavora-backup-${username}.zip`;
  if (qfid) {
    const rootFolder = await c.env.DB.prepare('SELECT * FROM folders WHERE id=? AND owner=?').bind(qfid, username).first();
    if (!rootFolder) return c.json({ message: 'Folder tidak ditemukan' }, 404);
    const { results: allFolders } = await c.env.DB.prepare('SELECT * FROM folders WHERE owner=?').bind(username).all();
    const ids = new Set([qfid]);
    let grew = true, g = 0;
    while (grew && g++ < 50) {
      grew = false;
      for (const f of allFolders) {
        if (f.parent_id && ids.has(f.parent_id) && !ids.has(f.id)) { ids.add(f.id); grew = true; }
      }
    }
    const placeholders = [...ids].map(() => '?').join(',');
    const r = await c.env.DB.prepare(`SELECT * FROM files WHERE owner=? AND trashed=0 AND folder_id IN (${placeholders})`).bind(username, ...ids).all();
    files = r.results;
    stripPrefix = await folderZipPath(c.env.DB, username, qfid);
    const safeRoot = rootFolder.name.replace(/[/\\?%*:|"<>]/g, '_');
    wrapFolder = safeRoot + '/';
    zipName = `datavora-${safeRoot}.zip`;
  } else {
    const r = await c.env.DB.prepare('SELECT * FROM files WHERE owner=? AND trashed=0').bind(username).all();
    files = r.results;
  }
  if (!files.length) return c.json({ message: 'Belum ada file untuk diunduh' }, 404);

  const usedNames = new Set();
  const uniqueName = (name) => {
    if (!usedNames.has(name)) { usedNames.add(name); return name; }
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 ? name.slice(dot) : '';
    const base = ext ? name.slice(0, -ext.length) : name;
    let i = 1, cand;
    do { cand = `${base} (${i})${ext}`; i++; } while (usedNames.has(cand));
    usedNames.add(cand);
    return cand;
  };

  let ctrl;
  const stream = new ReadableStream({ start(c2) { ctrl = c2; } });
  const zip = new Zip((err, data, final) => {
    if (err) { ctrl.error(err); return; }
    if (data.length) ctrl.enqueue(data);
    if (final) ctrl.close();
  });
  (async () => {
    try {
      for (const meta of files) {
        const obj = await c.env.BUCKET.get(meta.stored_name);
        if (!obj) continue;
        let entry = await folderZipPath(c.env.DB, username, meta.folder_id) + meta.original_name;
        if (stripPrefix && entry.startsWith(stripPrefix)) entry = entry.slice(stripPrefix.length);
        if (wrapFolder) entry = wrapFolder + entry;
        const zf = new ZipPassThrough(uniqueName(entry));
        zip.add(zf);
        try {
          const plain = await decBuf(c.env, hex(await obj.arrayBuffer()), meta.iv, meta.tag);
          zf.push(new Uint8Array(plain), true);
        } catch {
          zf.push(new Uint8Array(0), true);
        }
      }
      zip.end();
    } catch (e) {
      ctrl.error(e);
    }
  })();
  return new Response(stream, {
    headers: { 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${zipName}"` }
  });
});

export default app;
