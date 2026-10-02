# AMAN — Flow Code Lengkap

> Versi dokumen: v1.8.0-stage3e | Total: ~8.266 baris Go + 440 baris dashboard + 144 baris installer

---

## 1. Arsitektur High-Level

```
┌─────────────────────────────────────────────────────────────┐
│                        PENGGUNA                              │
│   CLI (terminal)          Web Dashboard (browser :8080)     │
└──────────┬──────────────────────────┬───────────────────────┘
           │                          │
┌──────────▼──────────────────────────▼───────────────────────┐
│ cmd/aman/  (entry point)                                     │
│   main.go   → dispatch CLI: periksa / update / serve / ...   │
│   serve.go  → HTTP API server (9 endpoints + dashboard)      │
│   update.go → updater database CVE + self-update             │
└──────────┬───────────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────────────────┐
│ pkg/  (business logic)                                       │
│   pemindai/  → scanners: folder, docker, web, security,      │
│                system packages, OSV client, rpmvercmp        │
│   deteksi/   → CVE matching engine (DB + online)             │
│   db/        → SQLite: CVE database + scan history           │
│   github/    → GitHub Advisories API client                  │
│   output/    → report JSON/HTML + Version const + logger     │
│   config/    → config file loader                            │
│   tipe/      → shared types (Paket, Kelemahan, dst.)         │
└──────────┬───────────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────────────────┐
│ SUMBER DATA                                                   │
│   ~/.aman/aman.db        SQLite lokal (CVE cache + history)  │
│   OSV.dev API            CVE distro (AlmaLinux/Rocky/Debian) │
│   GitHub Advisories API  CVE app packages (7 ecosystems)     │
│   NVD API                (fallback updater)                  │
│   GitHub Releases        self-update binary                  │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Entry Point — `cmd/aman/main.go` (1.223 baris)

### Dispatch flow

```
main()
 ├─ "periksa"            → jalankanPeriksa()
 │    ├─ parse flags: --jenis/-j, --sasaran/-s, --online/-o, --format/-f, --help/-h
 │    └─ switch jenis:
 │        ├─ "folder"  → pindaiFolder()
 │        ├─ "docker"  → pindaiDocker()
 │        ├─ "web"     → pindaiWeb()
 │        └─ "all"     → pindaiAll()          ← komprehensif
 ├─ "periksa-all"        → jalankanPeriksaAll()   (versi lama, deprecated)
 ├─ "periksa-security"   → jalankanPeriksaSecurity()
 ├─ "update"             → jalankanUpdate()       (di update.go)
 ├─ "serve"              → jalankanServe()        (di serve.go)
 ├─ "version"            → print output.Version
 └─ "help"               → printHelp()
```

### Flow `pindaiAll()` — scan komprehensif (fitur utama)

```
pindaiAll(sasaran, checkOnline, format)
 │
 ├─ [1] SECURITY SCAN ── SecurityScanner.Run()          (36+ checks)
 │     └─ tampil issues per severity + detail
 │
 ├─ [2] SERVER INFO ──── ComprehensiveScanner.GetServerInfo()
 │     └─ hostname, OS, kernel, docker version
 │
 ├─ [3] FOLDER SCAN ──── PemindaiFolder.Pindai(path)
 │     └─ temukan app packages (package.json, dll) → DeteksiPaket() → CVE
 │
 ├─ [4] SYSTEM PACKAGES ─ nexus fitur ala-Nessus:
 │     ├─ SystemPackageScanner.ScanSystemPackages()     (rpm -qa / dpkg -l)
 │     ├─ DetectDistroEcosystem()                       (/etc/os-release → "AlmaLinux:9")
 │     ├─ OSVClient.QueryBatch()                        (1 API call, semua packages)
 │     ├─ CollectAllAdvisoryIDs() + FetchAdvisoryDetails()  (concurrent 10x)
 │     ├─ per advisory: GetFixedVersion(pkg)
 │     ├─ per package : IsVulnerable(installed, fixed)  → rpmvercmp()
 │     └─ hasil: []SysVuln sorted CRITICAL→LOW, tampil max 30
 │
 ├─ [5] SCAN HISTORY ─── persist + diff
 │     ├─ LoadLatestScan(db)          → previous scan
 │     ├─ LoadFindings(db, prevID)
 │     ├─ SaveScan(db, secIssues, findings)             → scan baru
 │     ├─ CleanupOldScans(db, 50)
 │     └─ DiffScans(prev, cur) → tampil 🆕 BARU / ✅ FIXED / ➡️ MASIH ADA
 │
 ├─ [6] DOCKER SCAN ──── docker images (listing)
 ├─ [7] WEB SCAN ──────── port check 80/443/8080/8443
 │
 └─ [8] REPORT EXPORT ── sesuai --format:
       ├─ "json" → output.ExportJSON()  → aman-report-<ts>.json
       ├─ "html" → output.ExportHTML()  → aman-report-<ts>.html
       └─ (default) text only
```

---

## 3. Scanner Layer — `pkg/pemindai/`

| File | Isi | Flow utama |
|------|-----|-----------|
| `security.go` (1.800+ brs) | **36+ security checks** | `Run()` → loop 27 check functions → `SecurityScanResult{Issues, Critical, High, Medium, Low}` |
| `osv.go` | OSV.dev client + rpmvercmp | `QueryBatch()` → `GetVulnDetail()` → `ExtractCVEs()`, `GetFixedVersion()`, `GetSeverity()`; `rpmvercmp()` = algoritma versi RPM asli (segment alpha/numeric) |
| `system_packages.go` | Inventory paket OS | `scanRPM()` (rpm -qa --qf) / `scanDPKG()` (dpkg -l) → `[]SystemPackage{Name, Version, Arch, Ecosystem}` |
| `comprehensive.go` | Server info | `GetServerInfo()` → hostname/OS/kernel/docker |
| `docker.go` | Image scanner | `Pindai(image)` → `docker save` → extract tar → parse manifest → baca package files per layer (npm/pip) |
| `folder.go` | Folder scanner | `Pindai(path)` → walk → `deteksiPaket(file)` by extension (package.json, requirements.txt, go.mod, dst.) |
| `web.go` | Web scanner | `Pindai(url)` → HTTP GET → title, status, server header, tech stack, links |
| `ssl.go` | SSL checker | `CheckSSL(host, port)` → TLS handshake → cert info; `CheckSecurityHeaders()` |
| `ignore.go` | Path exclusions | `.amanignore` patterns |

### Security checks list (di `Run()`, urut eksekusi)

```
 1. kernel version          15. world-writable files /var
 2. pending updates         16. SUID binaries
 3. failed SSH logins       17. firewall status (firewalld/iptables/nft)
 4. inactive user accounts  18. weak SSL ciphers
 5. users without password  19. suspicious processes (nc, msf, dll)
 6. duplicate UID           20. exposed sensitive files (.git, .env)
 7. root PATH integrity     21. backup status (cron/dir/offsite)
 8. SSH root login          22. NTP/time sync
 9. SSH password auth       23. SSH config detail (Protocol, X11, MaxAuthTries)
10. open ports (danger)     24. sysctl kernel params (rp_filter, redirects, dll)
11. web security headers    25. unnecessary services (telnet, ftp, cups...)
12. HSTS/CSP/X-Frame/dll    26. cron security (world-writable, cron.allow)
13. docker socket exposure  27. SELinux/AppArmor status
14. world-writable /etc
```

---

## 4. Deteksi & Database Layer

### `pkg/deteksi/deteksi.go` — mesin matching

```
DeteksiPaket(db, paket, checkOnline)
 ├─ QueryKelemahan(db, paket.Nama)          ← lokal SQLite dulu
 │    └─ match versi via deteksi/versi.go (version compare)
 ├─ if checkOnline:
 │    └─ github.SearchAdvisory(ecosystem, nama)   ← online supplement
 └─ return []Kelemahan + CheckSource (local/online/mixed)
```

### `pkg/db/` — dua domain

**A. CVE Database** (`lokal.go`, `seed.go`, `updater.go`, `query.go`)

```
Tabel:
  kelemahan        (id, judul, penjelasan, tingkat, paket, pattern, versi_aman, referensi)
  konfigurasi_salah (nama, penjelasan, tingkat, file_pattern, matcher, referensi)

Updater:
  UpdateFromGitHub(db, eco)  → api.github.com/advisories?ecosystem=X
                               (cargo→"rust" mapping!)
  UpdateFromNVD(db, eco)     → services.nvd.nist.gov (keyword search)
  getEcosystemKeyword()      → npm→nodejs, pip→python, go→golang, ...
```

**B. Scan History** (`scanhistory.go`) — fitur v1.6.0

```
Tabel:
  scan_history   (id, timestamp, total_findings, security_issues)
  scan_findings  (scan_id FK, package, installed, fixed, advisory, cves, severity, summary)

Fungsi:
  InitScanHistory() → CREATE TABLE IF NOT EXISTS + index
  SaveScan()        → insert scan + bulk findings (transaction)
  LoadLatestScan()  → scan terakhir (exclude optional ID)
  LoadFindings()    → findings milik satu scan
  DiffScans(prev, cur) → {New[], Fixed[], StillThere}  (key: package|advisory)
  ListScans(n)      → N scan terbaru untuk API/GUI
  CleanupOldScans(50)
```

Lokasi DB: `~/.aman/aman.db` (dibuat via `InitDB()`)

---

## 5. HTTP Server — `cmd/aman/serve.go` (~520 baris)

```
jalankanServe(port)
 ├─ deteksi.InitDatabase()
 ├─ InitScanHistory()
 ├─ Routes:
 │   GET  /health              → {"service","status","version"}
 │   POST /api/v1/scan         → folder scan (body: {path, check_online})
 │   POST /api/v1/update       → trigger update (body: {ecosystem|all})
 │   GET  /api/v1/scan-all     → overview lama (info/folders/docker/web)
 │   GET  /api/v1/security     → 36 security checks (JSON)
 │   POST /api/v1/scan-web     → web scan (body: {url})
 │   GET  /api/v1/history      → daftar scan + new/fixed counts  (v1.8)
 │   GET  /api/v1/findings     → findings per scan (?scan=<id>)   (v1.8)
 │   POST /api/v1/fullscan     → MULAI background scan            (v1.8)
 │   GET  /api/v1/fullscan     → status polling + hasil terakhir  (v1.8)
 │   GET  /dashboard/*         → static files (dashboard/index.html)
 │
 ├─ fullscan background pattern:
 │     mutex-guarded state {running, started, finished, err}
 │     goroutine: stdout→devnull + panic recovery → pindaiAll()
 │     double-trigger → "already_running"
 │
 └─ GET / → redirect/serve index
```

### Dashboard — `dashboard/index.html` (440 baris, vanilla JS)

```
Load page
 ├─ checkHealth()          → dot hijau/merah + versi (30s interval)
 ├─ loadHistory()          → GET /history → render tabel riwayat
 │    └─ renderCompare()   → panel "Perbandingan Scan Terakhir"
 │       └─ 2 scan terbaru: delta headline + tabel severity ▲▼
 ├─ pollScanStatus()       → GET /fullscan (3s interval saat running)
 │    ├─ running → spinner + elapsed
 │    └─ selesai → refresh hasil + update lastScanInfo
 └─ selectScan(id)         → GET /findings → render tabel
      ├─ filter severity chips (All/Crit/High/Med/Low)
      ├─ search box (package/CVE/advisory)
      └─ CVE pills clickable → auto-search
Interaksi:
  ▶ Run Full Scan → POST /fullscan → polling sampai selesai
  🌐 Scan Website → POST /scan-web → tabel hasil (status/title/server)
```

---

## 6. Update System — `cmd/aman/update.go` (~340 baris)

```
jalankanUpdate()
 ├─ --cve / --db    → updateCVEDatabase(ecosystem="")
 ├─ --self / --aman → updateAmanSelf()
 ├─ --all / default → keduanya
 └─ --ecosystem X   → satu ecosystem saja

updateCVEDatabase():
  for eco in [npm, pip, go, rubygems, cargo, maven, nuget]:
      updater.UpdateFromGitHub(db, eco)     ← cargo dipetakan ke "rust"
      print OK (N CVE, Xs)

updateAmanSelf():
  cekVersiTerbaru()        → GET github releases/latest
                             (404 → "belum ada release", jelas)
  compareVersions()        → semver compare
  downloadDanInstall()     → download asset aman-linux-amd64
                             → replace binary sendiri
```

---

## 7. Output Layer — `pkg/output/`

| File | Fungsi |
|------|--------|
| `version.go` | **`const Version`** — single source of truth (CLI, JSON, health) |
| `report.go` | `FullReport` struct + `ExportJSON()` + `ExportHTML()` (standalone styled HTML, severity cards + 2 tabel) |
| `hasil.go` | `FormatJSON()` legacy per-scan JSON (pakai `output.Version`) |
| `logger.go` | structured logging |

---

## 8. Installer — `deploy/`

```
install.sh (one-liner, 144 baris):
 [1/5] binary: lokal ($1 / script dir) ATAU download releases/latest/aman-linux-<arch>
 [2/5] mkdir /opt/aman/data
 [3/5] stop service (anti "Text file busy") → cp binary → tulis aman.service
 [4/5] systemctl enable + restart aman
 [5/5] curl health check → sukses/gagal+journalctl hint

aman.service:
  User=root (scan butuh akses sistem penuh)
  ExecStart=/opt/aman/aman serve --port 8080
  Restart=on-failure
```

---

## 9. Data Flow Contoh End-to-End: `aman periksa --jenis all`

```
User
 └─ CLI parse
     └─ [Security]  read /proc, /etc, systemctl, ss, openssl...  (lokal)
     └─ [SysPkg]    rpm -qa                    → 979 packages
     └─ [SysPkg]    POST api.osv.dev/querybatch → advisory IDs per package
     └─ [SysPkg]    GET api.osv.dev/vulns/<id> ×576 (10 workers)
     └─ [SysPkg]    rpmvercmp(installed, fixed) → 187 vulnerable
     └─ [Folder]    walk /opt → 25 app packages
     └─ [Folder]    DeteksiPaket ×25 → SQLite + (GitHub Advisories if --online)
     └─ [History]   diff vs scan #prev → NEW/FIXED
     └─ [History]   INSERT scan #new + 187 findings
     └─ [Report]    --format html → aman-report-20261002-1420.html
     └─ print FINAL SUMMARY
```

---

## 10. Peta File Lengkap

```
aman/
├── cmd/aman/
│   ├── main.go            CLI dispatch + pindaiAll + report wiring
│   ├── serve.go           HTTP API (11 handlers) + background fullscan
│   └── update.go          CVE updater + self-update
├── pkg/
│   ├── pemindai/          9 scanner files (security 36 checks, osv+rpmvercmp,
│   │                      system_packages, docker, folder, web, ssl, ignore)
│   ├── deteksi/           CVE matching + version compare
│   ├── db/                SQLite lokal + updater + scan history (+tests)
│   ├── github/            GitHub Advisories client
│   ├── output/            Version const + report JSON/HTML + logger
│   ├── config/            config loader
│   └── tipe/              shared structs
├── dashboard/index.html   Web GUI (vanilla JS)
├── deploy/install.sh      one-liner installer
├── deploy/aman.service    systemd unit
├── Dockerfile + docker-compose.yml
└── README.md + INSTALL.md + TESTING.md
```

---

*Generated dari codebase aktual — semua flow diverifikasi terhadap source v1.8.0-stage3e (commit 273523a).*
