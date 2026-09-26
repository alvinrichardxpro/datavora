# 🗄️ Datavora — Website Penyimpanan File Pribadi

Penyimpanan file apapun (foto, video, PDF, ZIP, dokumen) agar memori HP/laptop tidak penuh dan file penting terpisah rapi.

Fitur:
- ✅ Login dengan username + password (hash bcrypt, token JWT, intip password 👁)
- ✅ Daftar akun baru
- ✅ Tutup tab/browser = otomatis logout + logout otomatis setelah 15 menit idle
- ✅ Kuota awal **10 GB per user** + bar progres sisa penyimpanan
- ✅ Upload file apapun (maks 20 file sekaligus, drag & drop)
- ✅ **Folder bersarang** (mis. Foto > Liburan) + pindahkan file antar folder + hapus folder rekursif
- ✅ **Thumbnail & pratinjau** foto/video/audio/PDF langsung di website (klik thumbnail atau Lihat 👁)
- ✅ **Buat file teks langsung dari website** (catatan .txt/.md/.html/dll) + buka & edit isinya
- ✅ Daftar, cari, unduh, ubah nama, hapus file
- ✅ **Data tersimpan terenkripsi (AES-256-GCM)** — isi file di disk tidak bisa dibaca tanpa kunci server + login pemilik
- ✅ Data terpisah per user

## Deploy (Vercel + GitHub + Cloudflare Workers + R2 + D1)

Arsitektur: **frontend** (`public/`) di Vercel (statis) • **backend** (`worker/`)
di Cloudflare Workers • file di **R2** • metadata di **D1** • domain dari Cloudflare.
Backend Worker sudah dites penuh (21/21 cek lolos di runtime Workers lokal).

> Catatan jujur:
> - Akun & file **mulai dari nol** di Cloudflare (hash password lokal bcrypt
>   tidak terbaca di Workers/PBKDF2) — daftar ulang + upload ulang sekali.
> - 1 file maksimal **50 MB** (limit memori Worker). Foto/dokumen aman.
> - Untuk produksi disarankan **Workers Paid ($5/bln)** — Free CPU-nya terlalu
>   kecil untuk enkripsi. R2 gratis 10 GB = pas untuk kuota.

1. **GitHub** — push repo ini (dari folder `file-storage-website`):
```powershell
git init
git add .
git commit -m "Datavora v1"
git remote add origin https://github.com/USERNAME/datavora.git
git branch -M main
git push -u origin main
```
2. **Cloudflare** — R2 + D1 + secret (di folder `worker/`, sudah `npm install`):
```powershell
npx wrangler login
npx wrangler r2 bucket create datavora-files
npx wrangler d1 create datavora
# → salin database_id ke wrangler.toml (GANTI-D1-DATABASE-ID)
npx wrangler d1 execute datavora --remote --file=./schema.sql
# kunci enkripsi 32 byte base64 (simpan baik-baik, = nyawa data):
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
npx wrangler secret put MASTER_KEY
npx wrangler secret put JWT_SECRET
npx wrangler deploy
# → dapat https://datavora-api.USERNAME.workers.dev — tes: buka URL itu
```
3. **Vercel** — Import Project dari GitHub → Framework Preset: **Other**,
   Output Directory: `public`, tanpa build command. Edit `vercel.json`:
   ganti `GANTI-DENGAN-HOST-BACKEND` dengan host Worker
   (mis. `datavora-api.USERNAME.workers.dev`) → redeploy.
   (`/api/*` diproxy Vercel ke Worker, frontend tanpa perubahan.)
4. **Cloudflare (domain Anda)**:
   - Frontend: DNS CNAME `files` → `cname.vercel-dns.com` (proxy ON),
     SSL/TLS: **Full**. Akses: `https://files.domainanda.com`.
   - API (opsional, agar API pakai domain sendiri): Worker → Settings →
     Domains & Routes → Add Custom Domain: `api.domainanda.com`.
     Lalu ganti host di `vercel.json` ke `api.domainanda.com` + redeploy.
5. **Versi lokal** (Node, tanpa batas 50 MB) tetap bisa jalan:
```powershell
npm install
npm start   # http://localhost:3001
```

## Keamanan data
- Password tidak pernah disimpan polos (bcrypt hash).
- Isi semua file dienkripsi AES-256-GCM sebelum ditulis ke `uploads/`. Kunci ada di `data/.master.key` (dibuat otomatis).
- **PENTING: backup `data/.master.key` bersama backup file.** Jika kunci hilang, file terenkripsi tidak bisa dibuka lagi.
- Token login hanya di `sessionStorage` (tutup tab = logout) + idle-timeout 15 menit.

## Cara menjalankan

1. Install Node.js (sudah terdeteksi v24 di komputer ini)
2. Buka terminal di folder ini:
```powershell
cd C:\Users\Alvin\file-storage-website
npm install
npm start
```
3. Buka browser: http://localhost:3000
4. Klik **Daftar** → buat username + password → **Masuk** → upload file.

## Struktur folder
```
file-storage-website/
  server.js          → backend (Express + auth + kuota 10GB)
  package.json
  public/
    index.html       → tampilan
    style.css
    app.js           → logika frontend
  data/              → users.json & files.json (otomatis dibuat)
  uploads/           → file fisik per user (otomatis dibuat)
```

## Catatan
- Kuota diatur di `server.js` → variabel `QUOTA_BYTES`.
- Ganti `JWT_SECRET` dengan string acak yang kuat untuk produksi.
- Ini versi lokal. Kalau ingin bisa diakses dari HP/internet, beri tahu saya untuk deploy.
