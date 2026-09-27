# VulnScanner — Simple Vulnerability Scanner

## 📋 Deskripsi Singkat

VulnScanner adalah tools vulnerability scanner sederhana yang terinspirasi dari **Trivy**, dibangun dengan bahasa **Go**, dan dirancang untuk orang awam yang ingin belajar cara membuat security tools.

> **Note:** Dokumen ini menggunakan bahasa Indonesia untuk kemudahan pemahaman orang awam. Namun, code dan komentar menggunakan English.

---

## 🎯 Tujuan Project

1. **Belajar** — Memahami cara kerja vulnerability scanner seperti Trivy
2. **Praktik** — Mengaplikasikan pengetahuan Go untuk security tools
3. **Bangun fondasi** — Menyiapkan struktur yang bisa dikembangkan lebih lanjut

---

## 🔧 Fitur Utama (Versi Awal)

| Fitur | Status | Keterangan |
|---|---|---|
| Docker Image Scanning | ✅ Direncanakan | Scan vulnerability di container image |
| Filesystem Scanning | ✅ Direncanakan | Scan direktori/file untuk vulnerability |
| CVE Database | ✅ Direncanakan | Database vulnerability lokal |
| Rule Engine | ✅ Direncanakan | Rule-based vulnerability detection |
| JSON/Table Output | ✅ Direncanakan | Multiple output format |
| HTTP-based Scanning | 🔜 Next | Scan endpoint untuk known CVEs |

---

## 📂 Struktur Project

```
vuln-scanner/
├── cmd/              ← Entry point (titik awal program berjalan)
├── pkg/              ← Library kode yang bisa dipakai ulang (public)
├── internal/         ← Kode internal yang tidak di-export
├── rules/            ← File rule (YAML/JSON)
├── config/           ← File konfigurasi
├── docs/             ← Dokumentasi
├── scripts/          ← Script helper (build, test, dll)
├── examples/         ← Contoh penggunaan
└── test/             ← Unit test dan integration test
```

---

## 📚 Dokumentasi Lengkap

| Dokumen | Lokasi | Isi |
|---|---|---|
| **Perancangan** | `docs/01-DESIGN.md` | Penjelasan tujuan, fitur, roadmap |
| **Arsitektur** | `docs/02-ARCHITECTURE.md` | Diagram dan penjelasan struktur |
| **Komponen Detail** | `docs/03-COMPONENTS.md` | Penjelasan setiap komponen |
| **Panduan Pengembangan** | `docs/04-DEVELOPMENT.md` | Cara mulai ngoding |
| **Panduan Testing** | `docs/05-TESTING.md` | Cara menulis test |
| **API Reference** | `docs/06-API.md` | Dokumentasi package (untuk developer) |

---

## 🚀 Cara Memulai

```bash
# 1. Clone repository
git clone https://github.com/yourusername/vuln-scanner
cd vuln-scanner

# 2. Install dependencies
go mod tidy

# 3. Run
go run cmd/scanner/main.go --help

# 4. Test basic scan
go run cmd/scanner/main.go scan --type docker --target nginx:1.21
```

---

## 📊 Pembagian Tugas (untuk tim development)

| Modul | Tanggung Jawab | Prioritas |
|---|---|---|
| `pkg/scanner` | Orchestrate semua scanning process | 🔴 Tinggi |
| `pkg/detector` | Logic deteksi vulnerability | 🔴 Tinggi |
| `pkg/rule` | Rule engine dan matching | 🔴 Tinggi |
| `pkg/types` | Definisi tipe data | 🟡 Sedang |
| `pkg/output` | Format output (JSON, table) | 🟡 Sedang |
| `pkg/database` | Operasi database (SQLite) | 🟡 Sedang |
| `pkg/httpclient` | HTTP client untuk remote scan | 🟢 Rendah |

---

## 🔗 Referensi yang Dipakai

- [Trivy Architecture](https://github.com/aquasecurity/trivy)
- [OWASP Vulnerability Classification](https://owasp.org/www-project-vulnerability-management/)
- [NVD CVE Database](https://nvd.nist.gov/)

---

## 📝 Lisensi

MIT License — Bebas digunakan untuk belajar dan development.
