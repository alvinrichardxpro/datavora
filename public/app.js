const API = '';
// Pustaka ikon garis (SVG) — pengganti emoji agar tampilan bersih & elegan
const ICONS = {
  eyeOff: '<path d="M17.94 17.94A10.6 10.6 0 0 1 12 19c-6.5 0-10-7-10-7a17.6 17.6 0 0 1 4.06-4.94"/><path d="M9.9 4.24A9.5 9.5 0 0 1 12 5c6.5 0 10 7 10 7a17.7 17.7 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><path d="M2 2l20 20"/>',
  pencil: '<path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/>',
  pin: '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>',
  tag: '<path d="M12 2H2v10l9.3 9.3a1 1 0 0 0 1.4 0l8.6-8.6a1 1 0 0 0 0-1.4z"/><circle cx="7" cy="7" r="1.5"/>',
  trash: '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  folder: '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9L9.6 3.9A2 2 0 0 1 7.9 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/>',
  fileText: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>',
  home: '<path d="M3 9.5 12 3l9 6.5V20a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>',
  back: '<path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/>',
  dots: '<circle cx="12" cy="5" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="12" cy="19" r="1.7"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  undo: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  archive: '<rect x="1" y="3" width="22" height="5" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  plus: '<path d="M12 5v14M5 12h14"/>'
};
function ic(name, filled) {
  const style = filled
    ? 'fill="currentColor" stroke="none"'
    : 'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  return `<svg class="ic" viewBox="0 0 24 24" ${style} aria-hidden="true">${ICONS[name] || ''}</svg>`;
}
// Token disimpan di sessionStorage: hilang saat tab/browser ditutup → otomatis logout.
// (Migrasi sekali: pindahkan token lama bila ada, termasuk dari nama lama FileKu.)
function storedAuth(key) {
  return sessionStorage.getItem('datavora_' + key)
    || localStorage.getItem('datavora_' + key)
    || sessionStorage.getItem('fileku_' + key)
    || localStorage.getItem('fileku_' + key) || '';
}
let token = storedAuth('token');
let username = storedAuth('user');
if (token) {
  sessionStorage.setItem('datavora_token', token);
  sessionStorage.setItem('datavora_user', username);
  ['fileku_token', 'fileku_user'].forEach(k => { sessionStorage.removeItem(k); localStorage.removeItem(k); });
  localStorage.removeItem('datavora_token');
  localStorage.removeItem('datavora_user');
}

// Logout otomatis setelah 15 menit tidak ada aktivitas (keamanan)
const IDLE_LIMIT = 15 * 60 * 1000;
let idleTimer = null;
function resetIdleTimer() {
  clearTimeout(idleTimer);
  if (!token) return;
  idleTimer = setTimeout(() => {
    alert('Sesi berakhir karena tidak ada aktivitas selama 15 menit. Silakan login kembali.');
    logout();
  }, IDLE_LIMIT);
}
['mousemove', 'keydown', 'click', 'touchstart'].forEach(evt =>
  document.addEventListener(evt, resetIdleTimer, { passive: true })
);

// Mode gelap / terang (tersimpan, default gelap)
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('datavora_theme', t); } catch { /* abaikan */ }
  const b = document.getElementById('themeBtn');
  if (b) b.innerHTML = ic(t === 'dark' ? 'sun' : 'moon');
}
function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
}
try { applyTheme(localStorage.getItem('datavora_theme') || 'dark'); }
catch { applyTheme('dark'); }

function switchTab(t) {
  document.getElementById('loginForm').style.display = t === 'login' ? 'block' : 'none';
  document.getElementById('registerForm').style.display = t === 'register' ? 'block' : 'none';
  document.getElementById('tabLogin').classList.toggle('active', t === 'login');
  document.getElementById('tabRegister').classList.toggle('active', t === 'register');
}

function showAuth(msg) { document.getElementById('authMsg').textContent = msg || ''; }

function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  btn.innerHTML = ic(show ? 'eyeOff' : 'eye');
}

async function register() {
  const u = document.getElementById('regUser').value.trim();
  const p = document.getElementById('regPass').value;
  const r = await fetch('/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  });
  const d = await r.json();
  showAuth(d.message);
  if (r.ok) switchTab('login');
}

async function login() {
  const u = document.getElementById('loginUser').value.trim();
  const p = document.getElementById('loginPass').value;
  const r = await fetch('/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  });
  const d = await r.json();
  if (!r.ok) return showAuth(d.message);
  token = d.token; username = d.username;
  sessionStorage.setItem('datavora_token', token);
  sessionStorage.setItem('datavora_user', username);
  enterApp();
}

function logout() {
  ['datavora_token', 'datavora_user', 'fileku_token', 'fileku_user'].forEach(k => {
    sessionStorage.removeItem(k); localStorage.removeItem(k);
  });
  token = ''; username = '';
  clearTimeout(idleTimer);
  document.getElementById('appPage').style.display = 'none';
  document.getElementById('authPage').style.display = 'flex';
}

function enterApp() {
  document.getElementById('authPage').style.display = 'none';
  document.getElementById('appPage').style.display = 'block';
  document.getElementById('helloUser').textContent = '• Halo, ' + username;
  resetIdleTimer();
  animateView();
  loadQuota(); loadFolders(); loadFiles();
}

function fmt(bytes) {
  if (bytes === 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
}

function authHeaders() { return { 'Authorization': 'Bearer ' + token }; }

async function loadQuota() {
  const r = await fetch('/api/quota', { headers: authHeaders() });
  if (r.status === 401) return logout();
  const d = await r.json();
  document.getElementById('quotaText').textContent = `${fmt(d.used)} / ${fmt(d.quota)}`;
  document.getElementById('quotaBar').style.width = Math.min(100, d.percent) + '%';
  document.getElementById('quotaDetail').textContent = `Terpakai ${d.percent}% • Sisa ${fmt(d.free)}`;
}

let currentFolderId = null;
let trashMode = false;
let allFolders = [];
const thumbURLs = {};

function folderMap() { return new Map(allFolders.map(f => [f.id, f])); }
function folderDepth(id) {
  const m = folderMap(); let d = 0, cur = id, g = 0;
  while (cur && m.has(cur) && g++ < 50) { d++; cur = m.get(cur).parentId; }
  return d;
}
function childFolders(parentId) {
  return allFolders.filter(f => (f.parentId || null) === (parentId || null));
}
function folderPathIds(folderId) {
  const m = folderMap(); const ids = []; let cur = folderId, g = 0;
  const seen = new Set();
  while (cur && m.has(cur) && !seen.has(cur) && g++ < 50) { seen.add(cur); ids.unshift(cur); cur = m.get(cur).parentId; }
  return ids;
}

async function loadFolders() {
  const r = await fetch('/api/folders', { headers: authHeaders() });
  if (r.status === 401) return logout();
  allFolders = r.ok ? await r.json() : [];
  renderBreadcrumb();
  renderFolderList();
}

function renderBreadcrumb() {
  const box = document.getElementById('breadcrumb');
  if (!box) return;
  const bb = document.getElementById('backBtn');
  if (bb) bb.style.display = (currentFolderId || trashMode) ? '' : 'none';
  if (trashMode) {
    box.innerHTML = `<button onclick="openFolder(null)">${ic('home')}<span>Utama</span></button><span class="sep">›</span><button class="current" onclick="enterTrash()">${ic('trash')}<span>Sampah</span></button>`;
    return;
  }
  const m = folderMap();
  let html = `<button class="${!currentFolderId ? 'current' : ''}" onclick="openFolder(null)">${ic('home')}<span>Utama</span></button>`;
  for (const id of folderPathIds(currentFolderId)) {
    const f = m.get(id);
    html += `<span class="sep">›</span><button class="${id === currentFolderId ? 'current' : ''}" onclick="openFolder('${id}')">${escapeHtml(f.name)}</button>`;
  }
  box.innerHTML = html;
}

function renderFolderList() {
  const box = document.getElementById('folderList');
  if (!box) return;
  const kids = childFolders(currentFolderId);
  const lbl = document.getElementById('folderSecLabel');
  if (lbl) lbl.style.display = kids.length ? '' : 'none';
  box.innerHTML = kids.map(f => `
    <div class="folder-item" ondragover="event.preventDefault();this.classList.add('folder-drop')" ondragleave="this.classList.remove('folder-drop')" ondrop="dropToFolder(event,'${f.id}')" title="Seret file ke sini untuk mengisi folder ini">
      <div class="ficon">${ic('folder')}</div>
      <div class="finfo" onclick="openFolder('${f.id}')" title="Klik untuk membuka folder">
        <div class="name">${f.pinned ? ic('pin', true) + ' ' : ''}${escapeHtml(f.name)}</div>
        <div class="meta">${childFolders(f.id).length} subfolder • klik untuk buka</div>
      </div>
      <div class="actions">
        <div class="menu-wrap">
          <button class="icon-btn menu-btn" onclick="toggleMenu('md-${f.id}')" title="Aksi folder">⋮</button>
          <div class="menu" id="md-${f.id}">
            <button onclick="openFolder('${f.id}')">${ic('folder')}<span>Buka folder</span></button>
            <button onclick="quickAddFiles('${f.id}')">${ic('plus')}<span>Tambah file</span></button>
            <button onclick="downloadFolder('${f.id}')">${ic('download')}<span>Unduh folder</span></button>
            <button onclick="togglePinFolder('${f.id}', ${f.pinned ? 'false' : 'true'})">${ic('pin', f.pinned)}<span>${f.pinned ? 'Lepas sematan' : 'Sematkan'}</span></button>
            <button onclick="renameFolder('${f.id}')">${ic('tag')}<span>Ubah nama</span></button>
            <button class="danger" onclick="deleteFolder('${f.id}')">${ic('trash')}<span>Hapus folder</span></button>
          </div>
        </div>
      </div>
    </div>`).join('');
}

async function togglePinFolder(id, pin) {
  await fetch('/api/folders/' + id, {
    method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ pinned: pin })
  });
  loadFolders(); renderPinned();
}

function setTrashMode(on) {
  trashMode = on;
  const c = document.querySelector('.container');
  if (c) c.classList.toggle('trash-mode', on);
}

function enterTrash() {
  setTrashMode(true);
  currentFolderId = null;
  animateView();
  document.getElementById('search').value = '';
  renderBreadcrumb();
  renderFolderList();
  loadFiles();
}

function animateView() {
  const c = document.querySelector('.container');
  if (!c) return;
  c.classList.remove('view-enter');
  void c.offsetWidth; // paksa reflow agar animasi mengulang
  c.classList.add('view-enter');
}

function openFolder(id) {
  setTrashMode(false);
  currentFolderId = id || null;
  animateView();
  document.getElementById('search').value = '';
  renderBreadcrumb();
  renderFolderList();
  loadFiles();
}

function goBack() {
  if (trashMode) { openFolder(null); return; }
  if (!currentFolderId) return;
  const m = folderMap().get(currentFolderId);
  openFolder(m && m.parentId ? m.parentId : null);
}

async function createFolder() {
  const n = prompt('Nama folder baru (mis. Foto, Video, Dokumen):');
  if (!n || !n.trim()) return;
  const r = await fetch('/api/folders', {
    method: 'POST', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: n.trim(), parentId: currentFolderId })
  });
  const d = await r.json();
  if (!r.ok) { alert(d.message); return; }
  loadFolders();
}

async function renameFolder(id) {
  const m = folderMap().get(id);
  const n = prompt('Nama folder baru:', m ? m.name : '');
  if (!n) return;
  await fetch('/api/folders/' + id, {
    method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ newName: n })
  });
  loadFolders();
}

async function deleteFolder(id) {
  const m = folderMap().get(id);
  if (!confirm(`Hapus folder "${m ? m.name : ''}" beserta SEMUA file & subfolder di dalamnya?`)) return;
  const r = await fetch('/api/folders/' + id, { method: 'DELETE', headers: authHeaders() });
  const d = await r.json();
  alert(d.message || 'Folder dihapus');
  loadFolders(); loadQuota(); loadFiles();
}

// Unduh satu folder beserta seluruh isinya sebagai 1 FILE (ZIP).
// Ekstrak 1x → folder utuh bernama sesuai folder Datavora, isi lengkap.
async function downloadFolder(id) {
  const m = folderMap().get(id);
  const folderName = m ? m.name : 'folder';
  if (!confirm(`Unduh folder "${folderName}" beserta SELURUH isinya sebagai 1 file?\nEkstrak 1x → folder "${folderName}" lengkap sama isinya.`)) return;
  const zr = await fetch('/api/download-all?folderId=' + id, { headers: authHeaders() });
  if (!zr.ok) { alert('Gagal mengunduh folder (mungkin folder kosong)'); return; }
  const blob = await zr.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `datavora-${folderName}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  alert(`1 file terunduh. Ekstrak 1x → folder "${folderName}" lengkap sama isinya.`);
}

async function moveFile(id, folderId) {
  await fetch('/api/files/' + id, {
    method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ folderId })
  });
  loadFiles();
}

// Seret & letakkan file langsung ke folder tertentu
function dropToFolder(e, folderId) {
  e.preventDefault();
  e.stopPropagation(); // jangan sampai diupload 2x oleh drop global
  document.querySelectorAll('.folder-drop').forEach(x => x.classList.remove('folder-drop'));
  if (e.dataTransfer.files.length) uploadToFolder(e.dataTransfer.files, folderId);
}
async function uploadToFolder(fileList, folderId) {
  if (!fileList.length) return;
  const fd = new FormData();
  fd.append('folderId', folderId || 'root');
  for (const f of fileList) fd.append('files', f);
  const r = await fetch('/api/upload', { method: 'POST', headers: authHeaders(), body: fd });
  const d = await r.json();
  const m = (folderId && folderMap().get(folderId)) || null;
  alert((d.message || (r.ok ? 'Upload selesai' : 'Upload gagal')) + (m ? ` ke folder ${m.name}` : ''));
  loadQuota(); loadFiles();
}

// Tombol ＋ : tambah file langsung ke folder tertentu tanpa harus membukanya dulu
let quickTarget = null;
function quickAddFiles(folderId) {
  quickTarget = folderId || null;
  document.getElementById('quickFileInput').click();
}
async function uploadQuickFiles() {
  const input = document.getElementById('quickFileInput');
  if (!input.files.length) return;
  const fd = new FormData();
  fd.append('folderId', quickTarget || 'root');
  for (const f of input.files) fd.append('files', f);
  input.value = '';
  const r = await fetch('/api/upload', { method: 'POST', headers: authHeaders(), body: fd });
  const d = await r.json();
  alert(d.message || (r.ok ? 'Upload selesai' : 'Upload gagal'));
  loadQuota(); loadFiles();
}

// Menu ⋮ : buka/tutup, klik di luar menutup semua
function closeMenus() {
  document.querySelectorAll('.menu.open').forEach(m => m.classList.remove('open'));
}
function toggleMenu(mid) {
  const el = document.getElementById(mid);
  if (!el) return;
  const was = el.classList.contains('open');
  closeMenus();
  if (!was) el.classList.add('open');
}
document.addEventListener('click', e => {
  if (!e.target.closest('.menu') && !e.target.closest('.menu-btn')) closeMenus();
});

function moveOptions(selectedId) {
  let html = `<option value="root" ${!selectedId ? 'selected' : ''}>Utama</option>`;
  for (const x of allFolders) {
    html += `<option value="${x.id}" ${selectedId === x.id ? 'selected' : ''}>${'—'.repeat(folderDepth(x.id))} ${escapeHtml(x.name)}</option>`;
  }
  return html;
}

function isPreviewable(f) {
  const t = f.mimetype || '';
  return t.startsWith('image/') || t.startsWith('video/') || t.startsWith('audio/') || t === 'application/pdf';
}

async function fileBlobURL(id) {
  if (thumbURLs[id]) return thumbURLs[id];
  const r = await fetch('/api/files/' + id + '/download', { headers: authHeaders() });
  if (!r.ok) return null;
  const url = URL.createObjectURL(await r.blob());
  thumbURLs[id] = url;
  return url;
}

async function loadThumbs(files) {
  for (const f of files) {
    if (!(f.mimetype || '').startsWith('image/')) continue;
    const url = await fileBlobURL(f.id);
    if (!url) continue;
    document.querySelectorAll(`img[data-thumb="${f.id}"]`).forEach(img => { img.src = url; });
  }
}

let previewFileId = null;
let previewPinned = false;

async function previewFile(id) {
  previewFileId = id;
  document.getElementById('previewTitle').textContent = 'Memuat...';
  document.getElementById('previewBody').textContent = 'Memuat...';
  document.getElementById('previewModal').style.display = 'flex';
  const all = await (await fetch('/api/files', { headers: authHeaders() })).json();
  const meta = all.find(f => f.id === id) || {};
  const url = await fileBlobURL(id);
  if (!url) { document.getElementById('previewBody').textContent = 'Gagal memuat pratinjau.'; return; }
  previewPinned = !!meta.pinned;
  document.getElementById('previewTitle').textContent = meta.originalName || 'Pratinjau';
  document.getElementById('previewPinBtn').textContent = previewPinned ? 'Lepas' : 'Sematkan';
  const t = meta.mimetype || '';
  const body = document.getElementById('previewBody');
  if (t.startsWith('image/')) body.innerHTML = `<img src="${url}" alt="pratinjau">`;
  else if (t.startsWith('video/')) body.innerHTML = `<video src="${url}" controls></video>`;
  else if (t.startsWith('audio/')) body.innerHTML = `<audio src="${url}" controls></audio>`;
  else if (t === 'application/pdf') body.innerHTML = `<iframe src="${url}"></iframe>`;
  else body.textContent = 'Tidak ada pratinjau untuk tipe ini. Silakan unduh.';
}

function closePreview() {
  document.getElementById('previewModal').style.display = 'none';
  document.getElementById('previewBody').textContent = '';
  previewFileId = null;
}

async function togglePinPreview() {
  if (!previewFileId) return;
  await togglePin(previewFileId, !previewPinned);
  previewPinned = !previewPinned;
  document.getElementById('previewPinBtn').textContent = previewPinned ? 'Lepas' : 'Sematkan';
}

function downloadPreviewFile() {
  if (previewFileId) downloadFile(previewFileId);
}

async function loadFiles() {
  const q = document.getElementById('search').value || '';
  if (trashMode && q) {
    // Mencari dari halaman sampah → kembali ke daftar file
    setTrashMode(false);
    renderBreadcrumb();
    renderFolderList();
  }
  if (trashMode) return loadTrashView();
  // Mencari → cari di semua folder. Tidak mencari → isi folder yang sedang dibuka.
  const folderParam = q ? '' : '&folderId=' + (currentFolderId || 'root');
  const r = await fetch('/api/files?q=' + encodeURIComponent(q) + folderParam, { headers: authHeaders() });
  if (r.status === 401) return logout();
  const files = await r.json();
  document.getElementById('fileCount').textContent = files.length ? `• ${files.length} file` : '';
  const box = document.getElementById('fileList');
  if (!files.length) { box.innerHTML = '<div class="empty">Folder ini kosong. Upload file atau buat file baru di atas ⬆</div>'; renderPinned(); updateSelBar(); toggleDelAll(false); return; }
  box.innerHTML = files.map(f => {
    const thumb = (f.mimetype || '').startsWith('image/')
      ? `<img class="thumb" data-thumb="${f.id}" onclick="previewFile('${f.id}')" title="Klik untuk melihat foto">` : '';
    return `
    <div class="file-item">
      <input type="checkbox" class="pick" data-fid="${f.id}" title="Centang, atau seret area kosong untuk memilih banyak" ${selected.has(f.id) ? 'checked' : ''} onchange="toggleSelect('${f.id}', this.checked)">
      ${thumb}
      <div class="info"><div class="name">${f.encrypted ? ic('lock') + ' ' : ''}${f.pinned ? ic('pin', true) + ' ' : ''}${escapeHtml(f.originalName)}</div>
      <div class="meta">${fmt(f.size)} • ${new Date(f.uploadedAt).toLocaleString('id-ID')}</div></div>
      <div class="actions">
        <div class="menu-wrap">
          <button class="icon-btn menu-btn" onclick="toggleMenu('mf-${f.id}')" title="Aksi file">⋮</button>
          <div class="menu" id="mf-${f.id}">
            ${isPreviewable(f) ? `<button onclick="previewFile('${f.id}')">${ic('eye')}<span>Pratinjau</span></button>` : ''}
            ${isEditable(f) ? `<button onclick="openFile('${f.id}')">${ic('pencil')}<span>Buka & edit</span></button>` : ''}
            <button onclick="downloadFile('${f.id}')">${ic('download')}<span>Unduh</span></button>
            <button onclick="togglePin('${f.id}', ${f.pinned ? 'false' : 'true'})">${ic('pin', f.pinned)}<span>${f.pinned ? 'Lepas sematan' : 'Sematkan'}</span></button>
            <button onclick="renameFile('${f.id}')">${ic('tag')}<span>Ubah nama</span></button>
            <button class="danger" onclick="deleteFile('${f.id}')">${ic('trash')}<span>Hapus</span></button>
            <div class="mdiv"></div>
            <select onchange="moveFile('${f.id}', this.value)" title="Pindahkan ke folder">${moveOptions(f.folderId || null)}</select>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');
  renderPinned();
  updateSelBar();
  toggleDelAll(files.length > 0);
  loadThumbs(files);
}

function toggleDelAll(show) {
  const b = document.getElementById('delAllBtn');
  if (b) b.style.display = show ? '' : 'none';
}

async function renderPinned() {
  // SEMUA yang disematkan (folder + file), tidak ikut filter pencarian/folder
  const box = document.getElementById('pinnedList');
  if (!box) return;
  let pinnedFiles = [], pinnedFolders = [];
  try {
    const [rf, rd] = await Promise.all([
      fetch('/api/files', { headers: authHeaders() }),
      fetch('/api/folders', { headers: authHeaders() })
    ]);
    if (rf.ok) pinnedFiles = (await rf.json()).filter(f => f.pinned);
    if (rd.ok) pinnedFolders = (await rd.json()).filter(f => f.pinned);
  } catch { /* abaikan, sidebar tetap tampil */ }
  if (!pinnedFolders.length && !pinnedFiles.length) {
    box.innerHTML = '<div class="side-empty">Belum ada. Klik <strong>⋮ → Sematkan</strong> pada file/folder penting agar muncul di sini.</div>';
    return;
  }
  box.innerHTML =
    pinnedFolders.map(f => `
    <div class="pin-item pin-folder">
      <div class="name" onclick="openFolder('${f.id}')" title="Klik untuk membuka">${ic('pin', true)} ${ic('folder')} ${escapeHtml(f.name)}</div>
      <div class="meta">folder</div>
      <div class="actions">
        <button class="icon-btn btn-open" title="Buka folder" onclick="openFolder('${f.id}')">${ic('folder')}</button>
        <button class="icon-btn btn-ren" title="Lepas dari sematan" onclick="togglePinFolder('${f.id}', false)">${ic('x')}</button>
      </div>
    </div>`).join('') +
    pinnedFiles.map(f => `
    <div class="pin-item">
      <div class="name">${f.encrypted ? ic('lock') + ' ' : ''}${escapeHtml(f.originalName)}</div>
      <div class="meta">${fmt(f.size)}</div>
      <div class="actions">
        <div class="menu-wrap">
          <button class="icon-btn menu-btn" onclick="toggleMenu('mp-${f.id}')" title="Aksi">⋮</button>
          <div class="menu" id="mp-${f.id}">
            ${isPreviewable(f) ? `<button onclick="previewFile('${f.id}')">${ic('eye')}<span>Pratinjau</span></button>` : ''}
            ${isEditable(f) ? `<button onclick="openFile('${f.id}')">${ic('pencil')}<span>Buka & edit</span></button>` : ''}
            <button onclick="downloadFile('${f.id}')">${ic('download')}<span>Unduh</span></button>
            <button onclick="togglePin('${f.id}', false)">${ic('x')}<span>Lepas sematan</span></button>
          </div>
        </div>
      </div>
    </div>`).join('');
}

// ---- Tampilan halaman Sampah ----
async function loadTrashView() {
  const r = await fetch('/api/trash', { headers: authHeaders() });
  if (r.status === 401) return logout();
  const trash = r.ok ? await r.json() : [];
  const box = document.getElementById('fileList');
  if (!trash.length) {
    box.innerHTML = '<div class="empty">Sampah kosong.<br>File yang dihapus akan tampil di sini dan bisa dipulihkan.</div>';
    return;
  }
  box.innerHTML =
    `<div class="trash-head">${ic('trash')} Sampah • ${trash.length} file <button class="empty-trash" onclick="emptyTrash()">Kosongkan sampah</button></div>` +
    trash.map(f => `
    <div class="file-item trash-item">
      <div class="info"><div class="name">${escapeHtml(f.originalName)}</div>
      <div class="meta">${fmt(f.size)} • dihapus ${new Date(f.trashedAt || f.uploadedAt).toLocaleString('id-ID')}</div></div>
      <div class="actions">
        <button class="icon-btn btn-open" title="Pulihkan file" onclick="restoreFile('${f.id}')">${ic('undo')}</button>
        <button class="icon-btn btn-del" title="Hapus permanen" onclick="permanentDeleteFile('${f.id}')">${ic('trash')}</button>
      </div>
    </div>`).join('');
}

async function restoreFile(id) {
  const r = await fetch('/api/files/' + id + '/restore', { method: 'POST', headers: authHeaders() });
  const d = await r.json();
  if (!r.ok) { alert(d.message); return; }
  loadQuota(); loadFiles();
}

async function permanentDeleteFile(id) {
  if (!confirm('Hapus PERMANEN? File tidak bisa dipulihkan lagi.')) return;
  await fetch('/api/files/' + id + '/permanent', { method: 'DELETE', headers: authHeaders() });
  loadQuota(); loadFiles();
}

async function emptyTrash() {
  if (!confirm('Kosongkan sampah? SEMUA file di sampah dihapus permanen dan kuota terbebaskan.')) return;
  const r = await fetch('/api/trash', { method: 'DELETE', headers: authHeaders() });
  const d = await r.json();
  alert(d.message);
  loadQuota(); loadFiles();
}

async function togglePin(id, pin) {
  await fetch('/api/files/' + id, {
    method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ pinned: pin })
  });
  loadFiles();
}

async function downloadAll() {
  if (!confirm('Unduh SEMUA file sebagai 1 file ZIP (struktur folder tetap terjaga)?\nEkstrak 1x untuk mendapatkan semua folder & file.')) return;
  const r = await fetch('/api/download-all', { headers: authHeaders() });
  if (!r.ok) { alert('Gagal: belum ada file atau sesi berakhir'); return; }
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'datavora-backup-' + username + '.zip';
  document.body.appendChild(a);
  a.click();
  a.remove();
  alert('1 file ZIP terunduh. Ekstrak 1x untuk mendapatkan semua folder & file.');
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function isEditable(f) {
  const t = f.mimetype || '';
  const ext = (f.originalName.split('.').pop() || '').toLowerCase();
  return t.startsWith('text/') || t === 'application/json' ||
    ['txt', 'md', 'html', 'css', 'js', 'json', 'csv', 'xml', 'log'].includes(ext);
}

let modalFileId = null;
let modalPinned = false;
let modalMode = 'edit'; // 'edit' | 'create'

function newTextFile() {
  closeMenus();
  modalMode = 'create';
  modalFileId = null;
  modalPinned = false;
  document.getElementById('modalTitle').textContent = 'File teks baru';
  const nameEl = document.getElementById('modalFileName');
  nameEl.style.display = 'block';
  nameEl.value = '';
  document.getElementById('modalContent').value = '';
  document.getElementById('modalStatus').textContent = 'Tersimpan terenkripsi ke folder saat ini.';
  document.getElementById('modalPinBtn').style.display = 'none';
  document.getElementById('fileModal').style.display = 'flex';
  nameEl.focus();
}

async function openFile(id) {
  modalFileId = id;
  modalMode = 'edit';
  document.getElementById('modalFileName').style.display = 'none';
  document.getElementById('modalPinBtn').style.display = '';
  document.getElementById('modalTitle').textContent = 'Memuat...';
  document.getElementById('modalContent').value = '';
  document.getElementById('modalStatus').textContent = 'Membuka file...';
  document.getElementById('fileModal').style.display = 'flex';
  const r = await fetch('/api/files/' + id + '/content', { headers: authHeaders() });
  const d = await r.json();
  if (!r.ok) {
    document.getElementById('modalStatus').textContent = d.message || 'Gagal membuka file';
    return;
  }
  const all = await (await fetch('/api/files', { headers: authHeaders() })).json();
  const meta = all.find(f => f.id === id);
  modalPinned = !!(meta && meta.pinned);
  document.getElementById('modalTitle').textContent = meta ? meta.originalName : 'File';
  document.getElementById('modalPinBtn').textContent = modalPinned ? 'Lepas' : 'Sematkan';
  document.getElementById('modalContent').value = d.content;
  document.getElementById('modalStatus').textContent = 'File dibuka dari penyimpanan terenkripsi. Edit lalu Simpan.';
}

function closeFileModal() {
  document.getElementById('fileModal').style.display = 'none';
  modalFileId = null;
}

async function saveFileModal() {
  const status = document.getElementById('modalStatus');
  if (modalMode === 'create') {
    const name = document.getElementById('modalFileName').value.trim();
    if (!name) { status.textContent = 'Isi nama file dulu, contoh: catatan.txt'; return; }
    status.textContent = 'Menyimpan...';
    const r = await fetch('/api/create', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, content: document.getElementById('modalContent').value, folderId: currentFolderId || 'root' })
    });
    const d = await r.json();
    status.textContent = d.message || (r.ok ? 'Tersimpan' : 'Gagal menyimpan');
    if (r.ok) {
      modalMode = 'edit';
      modalFileId = d.file.id;
      modalPinned = false;
      document.getElementById('modalFileName').style.display = 'none';
      document.getElementById('modalPinBtn').style.display = '';
      document.getElementById('modalPinBtn').textContent = 'Sematkan';
      document.getElementById('modalTitle').textContent = d.file.originalName;
      loadQuota(); loadFiles();
    }
    return;
  }
  if (!modalFileId) return;
  status.textContent = 'Menyimpan...';
  const r = await fetch('/api/files/' + modalFileId + '/content', {
    method: 'PUT',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: document.getElementById('modalContent').value })
  });
  const d = await r.json();
  status.textContent = d.message || (r.ok ? 'Tersimpan' : 'Gagal menyimpan');
  if (r.ok) { loadQuota(); loadFiles(); }
}

async function togglePinModal() {
  if (!modalFileId) return;
  await togglePin(modalFileId, !modalPinned);
  modalPinned = !modalPinned;
  document.getElementById('modalPinBtn').textContent = modalPinned ? 'Lepas' : 'Sematkan';
  document.getElementById('modalStatus').textContent = modalPinned ? 'File disematkan ke panel kiri.' : 'File dilepas dari sematan.';
}

function downloadModalFile() {
  if (modalFileId) downloadFile(modalFileId);
}

async function downloadFileBlob(id) {
  const r = await fetch(`/api/files/${id}/download`, { headers: authHeaders() });
  if (!r.ok) return false;
  const blob = await r.blob();
  const cd = r.headers.get('content-disposition') || '';
  let name = 'file';
  const mStar = cd.match(/filename\*=UTF-8''([^;]+)/);
  const mPlain = cd.match(/filename="(.+)"/);
  if (mStar) { try { name = decodeURIComponent(mStar[1]); } catch { name = mStar[1]; } }
  else if (mPlain) name = mPlain[1];
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  return true;
}

function downloadFile(id) {
  downloadFileBlob(id).then(ok => { if (!ok) alert('Gagal mengunduh'); });
}

async function deleteFile(id) {
  if (!confirm('Hapus file ini?')) return;
  await fetch('/api/files/' + id, { method: 'DELETE', headers: authHeaders() });
  selected.delete(id);
  loadQuota(); loadFiles();
}

// Hapus banyak file yang dicentang sekaligus
const selected = new Set();
function toggleSelect(id, checked) {
  if (checked) selected.add(id);
  else selected.delete(id);
  updateSelBar();
}
function updateSelBar() {
  const bar = document.getElementById('selBar');
  if (!bar) return;
  bar.style.display = selected.size ? 'flex' : 'none';
  document.getElementById('selCount').textContent = `${selected.size} dipilih`;
}
async function deleteAllShown() {
  const ids = [...document.querySelectorAll('#fileList input.pick')].map(cb => cb.dataset.fid);
  if (!ids.length) { alert('Tidak ada file yang tampil.'); return; }
  if (!confirm(`Hapus SEMUA ${ids.length} file yang tampil? Tindakan ini tidak bisa dibatalkan.`)) return;
  const r = await fetch('/api/files', {
    method: 'DELETE',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids })
  });
  const d = await r.json();
  alert(d.message || (r.ok ? 'Dihapus' : 'Gagal menghapus'));
  ids.forEach(id => selected.delete(id));
  loadQuota(); loadFiles();
}
function clearSelection() {
  selected.clear();
  updateSelBar();
  loadFiles();
}

// Seleksi SERET (marquee): tahan klik kiri di area kosong daftar file lalu seret —
// semua baris yang tersentuh kotak langsung tercentang. Tahan Ctrl untuk menambah.
let marquee = null;
function marqueeList() { return document.getElementById('fileList'); }
document.getElementById('fileList').addEventListener('pointerdown', e => {
  if (!marqueeList() || e.pointerType !== 'mouse' || e.button !== 0) return;
  if (e.target.closest('input,button,select,a,img,.menu')) return;
  if (!marqueeList().querySelector('.file-item')) return;
  const box = document.createElement('div');
  box.className = 'marquee';
  marqueeList().appendChild(box);
  marquee = { x0: e.clientX, y0: e.clientY, box, moved: false, add: e.ctrlKey || e.metaKey };
  lastPointer = { x: e.clientX, y: e.clientY };
  if (!scrollAnim) scrollAnim = requestAnimationFrame(marqueeScrollLoop);
});
function updateMarqueeBox(cx, cy) {
  const lr = marqueeList().getBoundingClientRect();
  const w = Math.abs(cx - marquee.x0), h = Math.abs(cy - marquee.y0);
  if (w + h > 6) marquee.moved = true;
  Object.assign(marquee.box.style, {
    display: 'block',
    left: (Math.min(cx, marquee.x0) - lr.left) + 'px',
    top: (Math.min(cy, marquee.y0) - lr.top) + 'px',
    width: w + 'px',
    height: h + 'px'
  });
  document.body.classList.add('marqueeing');
}
// Scroll otomatis mengikuti seretan ke tepi bawah/atas layar (makin ke tepi makin cepat)
let scrollAnim = null;
let lastPointer = { x: 0, y: 0 };
function marqueeScrollLoop() {
  if (!marquee) { scrollAnim = null; return; }
  const edge = 90;
  const distBottom = window.innerHeight - lastPointer.y;
  const distTop = lastPointer.y;
  let dy = 0;
  if (distBottom < edge) dy = 6 + Math.round((edge - Math.max(0, distBottom)) / edge * 24);
  else if (distTop < edge) dy = -(6 + Math.round((edge - Math.max(0, distTop)) / edge * 24));
  if (dy) {
    window.scrollBy(0, dy);
    updateMarqueeBox(lastPointer.x, lastPointer.y);
  }
  scrollAnim = requestAnimationFrame(marqueeScrollLoop);
}
document.addEventListener('pointermove', e => {
  if (!marquee) return;
  lastPointer = { x: e.clientX, y: e.clientY };
  updateMarqueeBox(e.clientX, e.clientY);
});
function endMarquee(select) {
  if (!marquee) return;
  const m = marquee;
  marquee = null;
  document.body.classList.remove('marqueeing');
  const r = m.box.getBoundingClientRect();
  m.box.remove();
  if (!select || !m.moved) return;
  const ids = [];
  marqueeList().querySelectorAll('.file-item').forEach(item => {
    const cb = item.querySelector('input.pick');
    if (!cb) return;
    const ir = item.getBoundingClientRect();
    if (ir.left < r.right && ir.right > r.left && ir.top < r.bottom && ir.bottom > r.top)
      ids.push(cb.dataset.fid);
  });
  if (!m.add) selected.clear();
  ids.forEach(id => selected.add(id));
  updateSelBar();
  loadFiles();
}
document.addEventListener('pointerup', () => endMarquee(true));
document.addEventListener('pointercancel', () => endMarquee(false));
window.addEventListener('blur', () => endMarquee(false)); // pengaman: lepas di luar jendela
async function deleteSelected() {
  if (!selected.size) return;
  if (!confirm(`Hapus ${selected.size} file yang dipilih?`)) return;
  const r = await fetch('/api/files', {
    method: 'DELETE',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids: [...selected] })
  });
  const d = await r.json();
  alert(d.message || (r.ok ? 'Dihapus' : 'Gagal menghapus'));
  selected.clear();
  loadQuota(); loadFiles();
}

async function renameFile(id) {
  const n = prompt('Nama baru:');
  if (!n) return;
  await fetch('/api/files/' + id, {
    method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ newName: n })
  });
  loadFiles();
}

// input file tersembunyi untuk ＋ Baru / ＋ folder
document.getElementById('quickFileInput').addEventListener('change', uploadQuickFiles);

// Drop di MANA SAJA (tanpa card): file masuk ke folder yang sedang dibuka
let dragDepth = 0;
function dropTargetName() {
  const m = currentFolderId ? folderMap().get(currentFolderId) : null;
  return m ? 'folder ' + m.name : 'Utama';
}
function appVisible() {
  return token && document.getElementById('appPage').style.display !== 'none';
}
function hasFiles(e) {
  return e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
}
document.addEventListener('dragenter', e => {
  if (!appVisible() || !hasFiles(e)) return;
  dragDepth++;
  document.getElementById('dropOverlayTarget').textContent = dropTargetName();
  document.getElementById('dropOverlay').classList.add('show');
});
document.addEventListener('dragleave', () => {
  if (dragDepth > 0) dragDepth--;
  if (dragDepth <= 0) {
    dragDepth = 0;
    document.getElementById('dropOverlay').classList.remove('show');
  }
});
document.addEventListener('dragover', e => { if (dragDepth > 0) e.preventDefault(); });
document.addEventListener('drop', e => {
  if (dragDepth === 0) return;
  e.preventDefault();
  dragDepth = 0;
  document.getElementById('dropOverlay').classList.remove('show');
  if (!appVisible() || !e.dataTransfer.files.length) return;
  uploadToFolder(e.dataTransfer.files, currentFolderId);
});

// auto-login
if (token) enterApp();
