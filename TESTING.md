# AMAN - QA Testing Plan

## 1. Test Strategy

### Scope
- API Endpoints
- CLI Commands
- Dashboard UI
- Security Scanning
- Docker Deployment

### Testing Types
- Functional Testing
- Integration Testing
- Security Testing
- Performance Testing
- Smoke & Sanity Testing

---

## 2. API Endpoints Test Cases

### 2.1 Health Check
```
Method: GET
Endpoint: /health
Expected: 200 OK, JSON with status/version
```

### 2.2 Scan Folder
```
Method: POST
Endpoint: /api/v1/scan
Body: {"path": "/valid/path", "check_online": bool}
Expected: 200 OK, JSON with scan results
```

### 2.3 Scan All
```
Method: GET
Endpoint: /api/v1/scan-all
Expected: 200 OK, JSON with server overview
```

### 2.4 Security Scan
```
Method: GET
Endpoint: /api/v1/security
Expected: 200 OK, JSON with security issues
```

### 2.5 Update Database
```
Method: POST
Endpoint: /api/v1/update
Body: {"ecosystem": "npm"} or {"all": true}
Expected: 200 OK, JSON with update status
```

---

## 3. CLI Commands Test Cases

### 3.1 Help Command
```bash
aman help
Expected: Display help text with all commands
```

### 3.2 Version Command
```bash
aman version
Expected: Display version number
```

### 3.3 Scan Commands
```bash
aman periksa --jenis folder --sasaran /tmp
aman periksa --jenis docker --sasaran nginx:latest
aman periksa --jenis web --sasaran https://example.com
```

### 3.4 Comprehensive Commands
```bash
aman periksa-all
aman periksa-security
```

### 3.5 Update Commands
```bash
aman update
aman update --cve
aman update --self
```

### 3.6 Service Command
```bash
aman serve
aman serve --port 9090
```

---

## 4. Test Scenarios

### 4.1 Happy Path
- [ ] Health check returns 200
- [ ] Scan folder returns valid JSON
- [ ] Scan all returns server info
- [ ] Security scan returns issues list
- [ ] Update database completes

### 4.2 Error Handling
- [ ] Invalid path returns 404/400
- [ ] Empty body returns 400
- [ ] Invalid JSON returns 400
- [ ] Wrong method returns 405

### 4.3 Security
- [ ] No SQL injection in path parameter
- [ ] No command injection possible
- [ ] Path traversal blocked (/../../etc/passwd)

### 4.4 Performance
- [ ] API responds in < 1 second (simple endpoints)
- [ ] Scan endpoints respond in < 30 seconds
- [ ] Concurrent requests handled

---

## 5. Docker Testing

### 5.1 Build
```bash
docker build -t aman-test .
docker images | grep aman
```

### 5.2 Run
```bash
docker run -d -p 8081:8080 --name aman-test aman-test
docker ps | grep aman-test
```

### 5.3 Health
```bash
curl http://localhost:8081/health
```

### 5.4 Scan
```bash
docker exec aman-test periksa --jenis folder --sasaran /opt/aman
```

### 5.5 Cleanup
```bash
docker stop aman-test
docker rm aman-test
```

---

## 6. Systemd Service Testing

### 6.1 Install
```bash
sudo ./deploy/install.sh
systemctl status aman
```

### 6.2 Operate
```bash
systemctl stop aman
systemctl start aman
systemctl restart aman
systemctl enable aman
systemctl disable aman
```

### 6.3 Logs
```bash
journalctl -u aman -f
```

### 6.4 Port
```bash
ss -tlnp | grep 8080
curl http://localhost:8080/health
```

---

## 7. Test Execution

### Pre-requisites
```bash
# Build AMAN
go build -o aman ./cmd/aman

# Start service
./aman serve --port 8080 &
```

### Run Tests
```bash
# Test all endpoints
./test-api.sh

# Test CLI
./test-cli.sh

# Test all
make test
```
