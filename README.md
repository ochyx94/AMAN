# AMAN - Alat Deteksi Kelemahan Software

AMAN adalah alat CLI untuk mendeteksi kelemahan (vulnerability) dalam software. Terinspirasi dari Trivy, AMAN membantu developer menemukan kerentanan security di project mereka.

## Fitur

- **🔍 Scanner Folder** - Deteksi kelemahan di folder project
- **🐳 Scanner Docker** - Deteksi kelemahan di container images
- **🌐 Scanner Web** - Deteksi kelemahan di website (coming soon)
- **📦 Database CVE Lokal** - Tidak perlu internet untuk scan basic
- **🔄 Auto-Update** - Update database CVE otomatis
- **🌐 GitHub Advisories** - Cek kelemahan terbaru dari GitHub
- **⚙️ Service Mode** - Jalankan sebagai HTTP API service
- **🔧 Self-Update** - Update AMAN ke versi terbaru

## Install

### Cara 1: Download Binary

```bash
# Download dari GitHub Releases
wget https://github.com/ochyx94/AMAN/releases/latest/download/aman
chmod +x aman
sudo mv aman /usr/local/bin/
```

### Cara 2: Build dari Source

```bash
# Clone repository
git clone https://github.com/ochyx94/AMAN.git
cd AMAN

# Build
go build -o aman ./cmd/aman

# Install
sudo mv aman /usr/local/bin/
```

### Cara 3: Install sebagai Service (Systemd)

```bash
git clone https://github.com/ochyx94/AMAN.git
cd AMAN
sudo ./deploy/install.sh
```

## Penggunaan

### 1. Basic Scan (Offline)

Scan folder tanpa koneksi internet (pakai database lokal saja):

```bash
aman periksa --jenis folder --sasaran /path/ke/project
```

**Contoh:**
```bash
# Scan project Node.js
aman periksa --jenis folder --sasaran ~/project/nodejs-app

# Scan project Python
aman periksa --jenis folder --sasaran ~/project/python-api

# Scan project Go
aman periksa --jenis folder --sasaran ~/project/golang-service
```

### 2. Online Scan (Dengan GitHub Advisories)

Scan dengan koneksi ke GitHub untuk hasil lebih lengkap:

```bash
aman periksa --jenis folder --sasaran /path/ke/project --online
```

**Contoh:**
```bash
# Scan dengan cek online
aman periksa --jenis folder --sasaran ~/project/nodejs-app --online
```

### 3. Output JSON

Simpan hasil scan dalam format JSON:

```bash
aman periksa --jenis folder --sasaran /path/ke/project --format json
```

**Contoh:**
```bash
# Simpan hasil ke file
aman periksa --jenis folder --sasaran ~/project/api --format json > hasil-scan.json

# Lihat hasil
cat hasil-scan.json | jq
```

### 4. Docker Scanner

Scan container images untuk kelemahan:

```bash
aman periksa --jenis docker --sasaran nama:image
```

**Contoh:**
```bash
# Scan image Nginx
aman periksa --jenis docker --sasaran nginx:1.21

# Scan image Alpine
aman periksa --jenis docker --sasaran alpine:3.18

# Scan dengan online check
aman periksa --jenis docker --sasaran node:20-alpine --online

# Scan image Redis
aman periksa --jenis docker --sasaran redis:7.2-rc --online
```

### 5. Update Database CVE

```bash
# Update semua (CVE + AMAN)
aman update

# Update database CVE saja
aman update --cve

# Update AMAN saja
aman update --self

# Update CVE untuk ecosystem tertentu
aman update --ecosystem npm
aman update --ecosystem pip
aman update --ecosystem go
```

**Contoh:**
```bash
# Update semua ecosystem
aman update --all

# Update hanya npm packages
aman update --ecosystem npm

# Update hanya Python packages
aman update --ecosystem pip
```

### 6. Service Mode (HTTP API)

Jalankan AMAN sebagai HTTP service:

```bash
# Jalankan di port default (8080)
aman serve

# Jalankan di port custom
aman serve --port 9000
```

**Contoh API Call:**

```bash
# Health check
curl http://localhost:8080/health

# Scan folder via API
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/app", "check_online": false}'

# Update database via API
curl -X POST http://localhost:8080/api/v1/update \
  -H "Content-Type: application/json" \
  -d '{"all": true}'
```

### 7. Service Commands (Systemd)

```bash
# Cek status service
systemctl status aman

# Start service
sudo systemctl start aman

# Stop service
sudo systemctl stop aman

# Restart service
sudo systemctl restart aman

# Lihat logs
sudo journalctl -u aman -f
```

## Ecosystem yang Didukung

| Ecosystem | Command Flag | Contoh Package |
|----------|-------------|---------------|
| npm | `--ecosystem npm` | express, lodash, react |
| pip | `--ecosystem pip` | django, flask, requests |
| go | `--ecosystem go` | gin, echo, gorm |
| rubygems | `--ecosystem rubygems` | rails, rake |
| cargo | `--ecosystem cargo` | rust crates |
| maven | `--ecosystem maven` | spring-boot |
| nuget | `--ecosystem nuget` | .NET packages |

## Status Verdict

Setelah scan, AMAN akan menampilkan status:

| Status | Arti |
|--------|------|
| ✅ TERVERIFIKASI | Kelemahan ditemukan dan diverifikasi via GitHub |
| ⚠️ CEK LOKAL SAJA | Hasil dari database lokal, update untuk hasil lengkap |
| ✅ TIDAK ADA KLEMAHAN DIKETAHUI | Tidak ditemukan kelemahan setelah dicek |
| ❌ ERROR | Ada error saat scan |

## Flags Umum

| Flag | Singkatan | Fungsi |
|------|----------|--------|
| `--online` | `-o` | Cek juga ke GitHub Advisories |
| `--format json` | `-f json` | Output dalam format JSON |
| `--sasaran` | `-s` | Path atau target yang akan discan |
| `--jenis` | `-j` | Jenis scan (folder, docker, web) |

## Contoh Lengkap Workflow

### 1. First Time Setup

```bash
# Install AMAN
wget https://github.com/ochyx94/AMAN/releases/latest/download/aman
chmod +x aman && sudo mv aman /usr/local/bin/

# Update database CVE pertama kali
aman update --cve
```

### 2. Daily Development Workflow

```bash
# Clone project baru
git clone https://github.com/user/project.git
cd project

# Scan project
aman periksa --jenis folder --sasaran .

# Jika ada kelemahan, scan dengan online check untuk detail
aman periksa --jenis folder --sasaran . --online
```

### 3. Docker Security Check

```bash
# Update database
aman update --cve

# Build image
docker build -t myapp:1.0 .

# Scan image sebelum deploy
aman periksa --jenis docker --sasaran myapp:1.0 --online

# Jika ada kelemahan, update image base
docker pull node:20-alpine
docker build -t myapp:1.1 .
aman periksa --jenis docker --sasaran myapp:1.1 --online
```

### 4. CI/CD Integration

```bash
# Di CI pipeline
aman periksa --jenis folder --sasaran . --format json > scan-results.json

# Upload results
curl -X POST https://security-dashboard.example.com/upload \
  -d @scan-results.json
```

## Troubleshooting

### Error: "Docker tidak tersedia"

```bash
# Cek apakah Docker terinstall
docker --version

# Cek apakah Docker daemon berjalan
sudo systemctl status docker

# Start Docker
sudo systemctl start docker
```

### Error: "Database tidak ditemukan"

```bash
# Update database
aman update --cve
```

### Error: "Connection timeout"

```bash
# Scan offline saja
aman periksa --jenis folder --sasaran . --format json

# Atau tunggu koneksi stabil lalu scan online
aman periksa --jenis folder --sasaran . --online
```

## Sumber Data Kelemahan

AMAN menggunakan data dari:

1. **GitHub Advisories** - https://github.com/advisories
2. **NVD NIST** - https://nvd.nist.gov/

## License

MIT License - Silakan digunakan dan dimodifikasi.

## Kontribusi

Silakan buat issue atau pull request di GitHub.
