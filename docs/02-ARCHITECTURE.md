# Arsitektur AMAN

## Gambaran Besar

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER (CLI)                              │
│                   $ aman scan --target nginx            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     cmd/scanner/main.go                         │
│                   (Entry Point - Titik Mulai)                   │
│                    Parse argumen & jalankan                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      pkg/scanner/scanner.go                     │
│                   (Scanner - Orchestra)                         │
│         • Pilih jenis scanner (Docker/FS/HTTP)                  │
│         • Koordinasi semua komponen                             │
│         • Kumpulkan hasil                                      │
└─────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ pkg/scanner/     │ │ pkg/scanner/     │ │ pkg/scanner/     │
│ docker.go        │ │ filesystem.go    │ │ http.go          │
│                  │ │                  │ │                  │
│ Scan Docker      │ │ Scan Filesystem  │ │ Scan HTTP        │
│ Image layers     │ │ files/directories│ │ endpoints        │
└──────────────────┘ └──────────────────┘ └──────────────────┘
          │                    │                    │
          └────────────────────┼────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     pkg/detector/detector.go                    │
│                   (Detector - Pikirannya)                      │
│         • Proses setiap komponen yang ditemukan                │
│         • Cocokkan dengan rule/vulnerability database          │
│         • Beri skor severity                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      pkg/rule/rule.go                           │
│                    (Rule Engine - Aturan)                      │
│         • Load rule dari YAML/JSON                              │
│         • Match vulnerability pattern                           │
│         • Kembalikan hasil match                                │
└─────────────────────────────────────────────────────────────────┘
          │                    │
          ▼                    ▼
┌──────────────────┐ ┌──────────────────┐
│  pkg/database/   │ │    pkg/types/    │
│                  │ │                  │
│ Load & query     │ │ Representasi     │
│ CVE database     │ │ data (struct)    │
└──────────────────┘ └──────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      pkg/output/output.go                       │
│                  (Output - Hasil Akhir)                         │
│         • Format hasil ke JSON/Table/SARIF                     │
│         • Print ke terminal/file                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER                                    │
│                   💻 Lihat hasil vulnerability                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Alur Data (Data Flow)

```
INPUT                    PROCESS                    OUTPUT
────────                 ───────                    ──────

"nginx:1.21"     ────▶   [Parse Target]     ────▶   Target info
                     ────▶   [Load Rules]    ────▶   Rule list
                     ────▶   [Scan Image]    ────▶   Layer data
                     ────▶   [Detect Vuln]   ────▶   Vuln list
                     ────▶   [Format Output] ────▶   JSON/Table
```

---

## Struktur Direktori dan Penjelasan

```
aman/
│
├── cmd/                           ← 🌟 TITIK MASUK PROGRAM
│   └── scanner/
│       └── main.go                ← main() function — pertama kali jalan
│
├── pkg/                           ← 🌟 KODE UTAMA (bisa dipake ulang)
│   │
│   ├── scanner/                   ← 🟢 ORCHESTRATOR — mengerti semua scanner
│   │   ├── scanner.go             ← Interface umum scanner
│   │   ├── factory.go             ← Buat scanner sesuai type
│   │   ├── docker.go              ← Scanner untuk Docker image
│   │   ├── filesystem.go          ← Scanner untuk filesystem
│   │   └── http.go                ← Scanner untuk HTTP endpoint
│   │
│   ├── detector/                  ← 🟢 OTAK — deteksi vulnerability
│   │   ├── detector.go            ← Logic utama deteksi
│   │   ├── detector_test.go       ← Test untuk detector
│   │   └── vulnMatcher.go         ← Cocokkan dengan pattern
│   │
│   ├── rule/                      ← 🟢 ATURAN — definisi vulnerability
│   │   ├── rule.go                ← Struktur rule & matching
│   │   ├── loader.go              ← Load rule dari file
│   │   └── rule_test.go           ← Test untuk rule
│   │
│   ├── types/                     ← 🟡 DEFINISI DATA
│   │   ├── types.go               ← Tipe data utama (Result, Vulnerability, dll)
│   │   └── severity.go            ← Enum severity (LOW, MEDIUM, HIGH, CRITICAL)
│   │
│   ├── output/                    ← 🟡 FORMAT OUTPUT
│   │   ├── output.go              ← Interface output
│   │   ├── json.go                ← Output format JSON
│   │   ├── table.go               ← Output format Tabel
│   │   └── sarif.go               ← Output format SARIF
│   │
│   ├── database/                  ← 🔵 DATA PENUNJANG
│   │   ├── db.go                  ← Koneksi & query SQLite
│   │   ├── migration.go           ← Setup schema database
│   │   └── db_test.go             ← Test untuk database
│   │
│   └── httpclient/                ← 🔵 CLIENT UNTUK REMOTE
│       └── client.go              ← HTTP client wrapper
│
├── internal/                      ← 🔴 KODE INTERNAL (tidak di-export)
│   ├── scanner/                   ← Implementasi internal scanner
│   ├── detector/                  ← Implementasi internal detector
│   ├── rule/                      ← Implementasi internal rule
│   ├── output/                    ← Implementasi internal output
│   ├── types/                     ← Internal types
│   ├── database/                  ← Internal database helpers
│   └── httpclient/                ← Internal HTTP helpers
│
├── rules/                         ← 📁 FILE RULE (YAML/JSON)
│   ├── builtin/                   ← Rule bawaan (CVE, OWASP, dll)
│   │   ├── cve-2024.yaml         ← Contoh rule CVE
│   │   └── owasp-top10.yaml      ← Contoh rule OWASP
│   └── custom/                    ← Rule buatan sendiri
│       └── README.md              ← Cara bikin rule sendiri
│
├── config/                        ← ⚙️ KONFIGURASI
│   ├── config.yaml               ← Konfigurasi utama
│   └── trivy.yaml                ← Contoh konfigurasi (referensi Trivy)
│
├── docs/                          ← 📖 DOKUMENTASI
│   ├── 01-DESIGN.md              ← (file ini)
│   ├── 02-ARCHITECTURE.md        ← (file ini)
│   ├── 03-COMPONENTS.md          ← Penjelasan detail tiap komponen
│   ├── 04-DEVELOPMENT.md         ← Cara mulai ngoding
│   ├── 05-TESTING.md             ← Cara testing
│   └── 06-API.md                 ← Dokumentasi API/package
│
├── scripts/                       ← 🔧 SCRIPT HELPER
│   ├── build.sh                   ← Script build
│   ├── test.sh                    ← Script untuk run test
│   └── generate-db.sh             ← Script untuk generate database
│
├── examples/                      ← 📝 CONTOH PENGGUNAAN
│   ├── basic-scan.sh              ← Contoh scan basic
│   └── custom-rule.yaml           ← Contoh rule sendiri
│
└── test/                          ← 🧪 TEST
    ├── unit/                      ← Unit test per package
    └── integration/               ← Integration test
```

---

## Penjelasan Per Komponen

### 1. cmd/scanner (Entry Point)

```
Apakah itu:
  - Tempat program pertama kali berjalan
  - Parsing argument dari CLI
  - Memanggil pkg/scanner untuk eksekusi

Apa yang dilakukan:
  1. Baca argument (--target, --type, --format, dll)
  2. Validasi input
  3. Buat scanner sesuai type
  4. Jalankan scan
  5. Tampilkan output

USER → cmd → pkg/scanner
```

### 2. pkg/scanner (Orchestrator)

```
Apakah itu:
  - "Kapten" yang mengkoordinasi semua scanner
  - Memilih scanner yang tepat berdasarkan type
  - Menyatukan hasil dari semua scanner

Apa yang dilakukan:
  1. Terima instruksi dari cmd
  2. Buat scanner yang sesuai (Docker/FS/HTTP)
  3. Jalankan scanner satu per satu
  4. Kumpulkan hasil
  5. Kirim ke detector

cmd → scanner → detector
```

### 3. pkg/detector (Otak)

```
Apakah itu:
  - Intelligensia dari tools ini
  - Tempat "memikirkan" apa yang vulnerability
  - Memproses data dari scanner

Apa yang dilakukan:
  1. Terima data hasil scan
  2. Load rule yang relevan
  3. Cocokkan dengan rule
  4. Hitung severity
  5. Buat list vulnerability

scanner → detector → rule
```

### 4. pkg/rule (Aturan)

```
Apakah itu:
  - "Buku aturan" yang mendefinisikan apa itu vulnerability
  - Daftar pattern yang perlu dicocokkan
  - Bisa di-customize oleh user

Apa yang dilakukan:
  1. Load rule dari YAML/JSON
  2. Parse rule pattern
  3. Match dengan data dari scanner
  4. Return hasil match

Format Rule Contoh:
  
  id: CVE-2024-1234
  title: Buffer Overflow in OpenSSL
  severity: HIGH
  match:
    package: openssl
    version: < 3.0.8
  description: Buffer overflow vulnerability...
```

### 5. pkg/types (Definisi Data)

```
Apakah itu:
  - "Blueprint" untuk semua tipe data
  - Definisi struct yang dipakai everywhere
  - Tidak punya logic, hanya definisi

Struct Utama:
  - Vulnerability  → Satu vulnerability (CVE-xxxx)
  - Result         → Hasil scan keseluruhan
  - Severity       → Enum: LOW, MEDIUM, HIGH, CRITICAL
  - Package        → Software package yang di-scan
  - Target         → Target yang di-scan (image/directory/URL)
```

### 6. pkg/output (Output)

```
Apakah itu:
  - "Presenter" yang format hasil scan
  - Ubah data jadi JSON/Table/SARIF
  - Bisa print ke terminal atau save ke file

Format Output:
  - JSON   → Untuk parsing oleh tool lain
  - Table  → Untuk manusia baca di terminal
  - SARIF  → Untuk integrate dengan CI/CD

User bisa pilih format dengan flag --format
```

### 7. pkg/database (Database)

```
Apakah itu:
  - "Perpustakaan" untuk CVE database
  - Simpan data vulnerability secara lokal
  - Query untuk cek apakah sebuah package vulnerable

Database:
  - SQLite (local file)
  - Schema: packages, vulnerabilities, package_vulnerabilities

Kenapa SQLite?
  - Tidak perlu server terpisah
  - Mudah di-bundle dengan aplikasi
  - Cukup cepat untuk use case ini
```

---

## Perbandingan dengan Trivy

| Komponen | Trivy | AMAN (Kita) | Keterangan |
|---|---|---|---|
| **Scanner** | Highly advanced (multi-type) | Sederhana (Docker, FS, HTTP) | Kita buat versi sederhana |
| **Detector** | Parallel processing | Sequential (awal) | Perlu improvement |
| **Rule Engine** | Built-in policies | YAML-based rule | Kita lebih sederhana |
| **Database** | Embedded SQLite | SQLite | Sama, kita lebih simpel schema |
| **Output** | JSON, Table, SARIF, HTML, CycloneDX | JSON, Table, SARIF | Kita mulai dari 3 format |
| **Cache** | Multi-layer cache | Single-layer | Perlu improvement |

---

## Prinsip Design

```
1. SIMPEL DAHULU
   → Mulai dari fitur paling dasar
   → Tidak perlu sophisticated architecture di awal
   
2. MODULAR
   → Setiap komponen bisa diganti/ditambah sendiri
   → Tidak tight-coupled
   
3. TESTABLE
   → Setiap komponen punya test
   → Mudah di-test tanpa perlu seluruh sistem
   
4. DOCUMENTED
   → Setiap fungsi punya comment
   → Dokumen lengkap untuk pemula

5. EXTENSIBLE
   → Mudah tambah scanner baru
   → Mudah tambah output format baru
   → Mudah tambah rule baru
```

---

## Next Steps (Setelah Arsitektur Fix)

```
Priority 1 (Core):
  1. Setup Go module & dependencies
  2. Buat types.go (definisi data)
  3. Buat scanner interface
  4. Buat detector logic

Priority 2 (Feature):
  5. Implement filesystem scanner
  6. Implement rule loader
  7. Implement output (JSON + Table)

Priority 3 (Database):
  8. Setup SQLite database
  9. Buat CVE database integration

Priority 4 (Enhancement):
  10. Implement Docker scanner
  11. Add more output format (SARIF)
  12. Add HTTP scanner
```

---

## Cara Baca Dokumen Ini

```
Untuk PEMULA, baca berurutan:

1. Baca docs/01-DESIGN.md dulu
   → Apa yang mau dibuat & kenapa

2. Baca docs/02-ARCHITECTURE.md ini
   → Bagaimana sistem bekerja (kamu sudah di sini)

3. Baca docs/03-COMPONENTS.md
   → Penjelasan detail setiap bagian

4. Baru mulai ngoding di docs/04-DEVELOPMENT.md
   → Langkah-langkah teknis

Kalau sudah PRO, langsung aja ke docs/04-DEVELOPMENT.md
```
