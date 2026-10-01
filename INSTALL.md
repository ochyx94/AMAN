# AMAN Installation Guide

## Quick Install (One-Liner)

```bash
curl -sSL https://raw.githubusercontent.com/ochyx94/AMAN/main/deploy/install.sh | sudo bash
```

Otomatis: download binary → install ke /opt/aman → systemd service → enable & start → health check. Selesai ±10 detik.

Update instalan lama: jalankan perintah yang sama (installer akan stop service, replace binary, start lagi).

---

AMAN dapat diinstall dengan beberapa cara:
1. **One-Liner Script** (recommended, di atas)
2. **Systemd Service manual** - Untuk server bare-metal/VM
3. **Docker** - Untuk environment container

---

## Cara 2: Install Manual sebagai Systemd Service (Bare Metal/VM)

### Prerequisites
- Go 1.22+ (untuk build)
- Root access

### Steps

#### 1. Build AMAN

```bash
# Clone repository
git clone https://github.com/ochyx94/AMAN.git
cd AMAN

# Build
go build -o aman ./cmd/aman
```

#### 2. Install

```bash
# Jalankan installer sebagai root
sudo ./deploy/install.sh
```

Atau manual:

```bash
# Buat user
sudo useradd -r -s /bin/false aman

# Buat directory
sudo mkdir -p /opt/aman/data

# Copy binary
sudo cp aman /opt/aman/aman

# Set permissions
sudo chown -R aman:aman /opt/aman
sudo chmod +x /opt/aman/aman

# Copy service file
sudo cp deploy/aman.service /etc/systemd/system/

# Reload & enable
sudo systemctl daemon-reload
sudo systemctl enable aman
sudo systemctl start aman
```

#### 3. Verify

```bash
# Check status
sudo systemctl status aman

# Test API
curl http://localhost:8080/health
```

#### 4. Commands

```bash
# Start/Stop/Restart
sudo systemctl start aman
sudo systemctl stop aman
sudo systemctl restart aman

# Check status
sudo systemctl status aman

# View logs
sudo journalctl -u aman -f

# Enable on boot
sudo systemctl enable aman
```

---

## Cara 3: Docker Installation

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+ (optional)

### Option A: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/ochyx94/AMAN.git
cd AMAN

# Build & Start
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Option B: Manual Docker

```bash
# Build image
docker build -t aman-scanner:latest .

# Run container
docker run -d \
  --name aman-scanner \
  -p 8080:8080 \
  -v $(pwd)/data:/opt/aman/data \
  aman-scanner serve --port 8080

# Test
curl http://localhost:8080/health
```

### Docker Commands

```bash
# Start
docker start aman-scanner

# Stop
docker stop aman-scanner

# Restart
docker restart aman-scanner

# View logs
docker logs -f aman-scanner

# Execute command inside container
docker exec aman-scanner periksa --jenis folder --sasaran /app

# Update image
docker build -t aman-scanner:latest .
docker stop aman-scanner
docker rm aman-scanner
docker run -d --name aman-scanner -p 8080:8080 aman-scanner:latest
```

### Scan dari Docker Container

```bash
# Scan folder di host
docker exec aman-scanner periksa --jenis folder --sasaran /path/to/project

# Scan semua
docker exec aman-scanner periksa-all

# Security scan
docker exec aman-scanner periksa-security

# Update database
docker exec aman-scanner update --cve
```

### Scan Directory dari Host

```bash
# Mount directory saat run
docker run --rm \
  -v /path/to/scan:/scan:ro \
  aman-scanner periksa --jenis folder --sasaran /scan

# Atau dengan docker-compose (edit volume mount)
```

---

## Post-Installation

### 1. Update Database CVE

```bash
# CLI
aman update --cve

# Docker
docker exec aman-scanner update --cve

# API
curl -X POST http://localhost:8080/api/v1/update \
  -H "Content-Type: application/json" \
  -d '{"all": true}'
```

### 2. Open Firewall (jika perlu)

```bash
# Ubuntu/Debian
sudo ufw allow 8080/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### 3. Configure Reverse Proxy (optional)

Nginx example:

```nginx
server {
    listen 80;
    server_name aman.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. Enable SSL (Recommended)

Gunakan Certbot untuk SSL:

```bash
sudo certbot --nginx -d aman.example.com
```

---

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u aman -xe

# Check config
/opt/aman/aman --help
```

### Port already in use

```bash
# Check what's using port 8080
sudo lsof -i :8080

# Change port
# Edit /etc/systemd/system/aman.service
# Change: ExecStart=/opt/aman/aman serve --port 8080
# To: ExecStart=/opt/aman/aman serve --port 9090

sudo systemctl daemon-reload
sudo systemctl restart aman
```

### Database error

```bash
# Recreate database
rm -f /opt/aman/data/aman.db
/opt/aman/aman update --cve
```

### Docker permission error

```bash
# Create data directory first
mkdir -p $(pwd)/data
chmod 777 $(pwd)/data
```

---

## Quick Reference

| Action | Systemd | Docker |
|--------|---------|--------|
| Start | `systemctl start aman` | `docker start aman-scanner` |
| Stop | `systemctl stop aman` | `docker stop aman-scanner` |
| Status | `systemctl status aman` | `docker ps` |
| Logs | `journalctl -u aman -f` | `docker logs -f aman-scanner` |
| Update | `./aman update --cve` | `docker exec aman-scanner update --cve` |
| Scan | `./aman periksa ...` | `docker exec aman-scanner periksa ...` |

---

## API Endpoints

```
GET  http://localhost:8080/              - Dashboard UI
GET  http://localhost:8080/health        - Health check
POST http://localhost:8080/api/v1/scan   - Scan folder
GET  http://localhost:8080/api/v1/scan-all - Server overview
GET  http://localhost:8080/api/v1/security - Security scan
POST http://localhost:8080/api/v1/update - Update database
```
