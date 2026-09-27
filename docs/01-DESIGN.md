# 01 - Design Document

## Overview

**Project Name:** AMAN  
**Type:** Vulnerability Scanner Tool (CLI)  
**Bahasa:** Go (Golang)  
**Inspired by:** Trivy (aquasecurity/trivy)  
**Target User:** Pemula yang ingin belajar security tools development

---

## Tujuan

```
1. Educational
   → Memahami cara kerja vulnerability scanner seperti Trivy
   → Belajar Go programming untuk security tools
   → Memahami konsep CVE, severity, dan vulnerability detection

2. Praktikal
   → Tool yang actually bisa digunakan untuk scan sederhana
   → Fondasi untuk dikembangkan lebih lanjut

3. Modular
   → Struktur yang bersih dan mudah dipahami
   → Bisa diambil sebagian untuk project lain
```

---

## Scope

### Yang Termasuk

```
✅ Docker image scanning (vulnerability di container image)
✅ Filesystem scanning (vulnerability di file/direktori)
✅ CVE database integration (NVD-based vulnerability data)
✅ Rule-based detection (custom rule dengan YAML)
✅ Multiple output format (JSON, Table, SARIF)
✅ CLI interface (command-line tool)
✅ Go module structure yang rapi
✅ Unit test untuk core components
```

### Yang Tidak Termasuk (V1)

```
❌ Full CVE database update automation
❌ Kubernetes-native integration
❌ Enterprise features (authentication, multi-user)
❌ Plugin system yang advanced
❌ GUI (Graphical User Interface)
❌ Cloud provider integration (AWS, GCP, Azure)
```

---

## Fitur Utama

### 1. Docker Image Scanning

```
Description:
  Scan container image untuk known vulnerabilities
  berdasarkan package yang terinstall di dalam image

Input:
  - Image name (e.g., "nginx:1.21")
  - Image ID (e.g., "sha256:abc123...")

Process:
  1. Pull image manifest
  2. Extract image layers
  3. Parse installed packages dari setiap layer
  4. Match dengan CVE database
  5. Generate report

Output:
  - List of vulnerabilities
  - Severity level (LOW, MEDIUM, HIGH, CRITICAL)
  - Fixed version info jika tersedia
```

### 2. Filesystem Scanning

```
Description:
  Scan direktori atau file untuk vulnerability
  berdasarkan file yang ada di sistem

Input:
  - Path ke direktori (e.g., "/app")
  - Path ke file tertentu

Process:
  1. Walk directory tree
  2. Identify package files (package.json, requirements.txt, dll)
  3. Parse dependencies
  4. Match dengan CVE database
  5. Generate report

Output:
  - List of vulnerabilities
  - File/path yang affected
  - Severity level
```

### 3. CVE Database

```
Description:
  Local database berisi vulnerability data
  berbasis NVD (National Vulnerability Database)

Storage:
  - SQLite database (file local)
  - Schema dirancang simple untuk V1

Content:
  - CVE ID
  - Affected package
  - Version range (vulnerable & fixed)
  - Severity (CVSS score)
  - Description
  - Reference URL

Update Strategy:
  - Manual update via script (V1)
  - Auto-update via cron job (future)
```

### 4. Rule Engine

```
Description:
  Rule-based detection system yang memungkinkan
  custom vulnerability rules dengan YAML format

Rule Structure:
  id:          Unique identifier (e.g., "CVE-2024-1234")
  title:       Human-readable title
  severity:    LOW | MEDIUM | HIGH | CRITICAL
  description: Penjelasan vulnerability
  match:       Condition untuk match
    package:   Nama package (regex supported)
    version:   Version condition (e.g., "< 1.0.0")
  reference:   Link ke informasi lebih lanjut

Example Rule:
  id: CUSTOM-001
  title: Insecure Cookie Configuration
  severity: MEDIUM
  description: Cookie tanpa secure flag
  match:
    pattern: "Set-Cookie:.*HttpOnly"
    not_match: "Secure"
```

### 5. Output Format

```
JSON Format:
  → Machine-readable output
  → Cocok untuk integrate dengan tool lain
  → Bisa di-parse dengan jq, Python, dll

Table Format:
  → Human-readable output untuk terminal
  → Color-coded severity
  → Spacing yang rapi

SARIF Format:
  → Standard format untuk CI/CD integration
  → Compatible dengan GitHub Security Alerts
  → Microsoft-supported format
```

---

## User Stories

### Story 1: CLI User

```
As a user,
I want to scan a docker image from command line,
So that I can find vulnerabilities before deploying

Scenario:
  $ aman scan --type docker --target nginx:1.21
  $ aman scan -t docker -T nginx:1.21 --format json -o result.json

Acceptance:
  ✅ CLI menerima input type, target, format, output
  ✅ Output sesuai dengan format yang dipilih
  ✅ Error message yang jelas jika ada masalah
```

### Story 2: Developer

```
As a developer,
I want to integrate aman ke CI/CD pipeline,
So that I can auto-detect vulnerabilities di code

Scenario:
  $ cat Dockerfile | aman scan --type docker -T myapp:build
  $ curl http://example.com | aman scan --type http

Acceptance:
  ✅ Bisa pipe input dari command lain
  ✅ Output SARIF compatible dengan GitHub
  ✅ Exit code 0 jika no vulnerability, non-zero jika ada
```

### Story 3: Security Researcher

```
As a security researcher,
I want to add custom detection rules,
So that I can detect specific vulnerability patterns

Scenario:
  $ aman scan --type filesystem --target /app --rule-dir ./custom-rules/

Acceptance:
  ✅ Load custom rules dari directory
  ✅ Custom rule bisa override builtin rules
  ✅ Rule validation sebelum di-load
```

---

## Non-Functional Requirements

### Performance

```
- Scan Docker image < 30 detik (untuk image size normal)
- Scan filesystem < 60 detik (untuk 1000 files)
- Memory usage < 500MB untuk use case normal
- Database query < 100ms per lookup
```

### Reliability

```
- Graceful error handling (tidak crash)
- Clear error message untuk user
- Retry logic untuk network operations
- Logging untuk debugging
```

### Usability

```
- CLI yang intuitif
- Help text yang lengkap
- Progress indicator untuk long operation
- Color-coded output untuk readability
```

### Maintainability

```
- Code yang clean dan documented
- Unit test coverage > 70% untuk core modules
- Clear directory structure
- Separated concerns (modular design)
```

---

## Technology Stack

| Component | Technology | Justification |
|---|---|---|
| **Bahasa** | Go 1.21+ | Memory safe, concurrent, easy deployment |
| **Database** | SQLite | No server needed, embedded, sufficient performance |
| **CLI Parsing** | spf13/cobra | Standard Go CLI library, fitur lengkap |
| **Docker Client** | containers/buildkit | untuk docker image operations |
| **HTTP Client** | net/http (stdlib) | Built-in, sufficient untuk use case kita |
| **Logging** | sirupsen/logrus | Structured logging, banyak fitur |
| **Config** | spf13/viper | YAML config support, environment variable |
| **Regex** | google/re2 | Faster, safe regex |
| **Testing** | Go testing package + testify | Standard + assertion library |

---

## Dependency List

```
# go.mod (minimal dependencies for V1)

require (
    github.com/spf13/cobra           # CLI parsing
    github.com/spf13/viper           # Config management
    github.com/mattn/go-sqlite3      # SQLite driver
    github.com/sirupsen/logrus       # Logging
    github.com/stretchr/testify      # Testing assertions
    github.com/google/re2/re2        # Fast regex
    golang.org/x/net                 # Networking utilities
)
```

---

## Risk & Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| CVE database outdated | Medium | Clear message tentang database age, update mechanism |
| Docker image access issues | Medium | Fallback to filesystem scan, clear error |
| Performance degradation | Low | Async processing, progress indicator |
| Memory issues dengan large scan | Low | Streaming approach, limit concurrent operations |
| Complex dependency graph | Medium | Start with simple package managers (npm, pip) |

---

## Milestones

### M1: Foundation (Week 1-2)

```
□ Setup Go module structure
□ Buat basic CLI dengan cobra
□ Implementasi types (data structures)
□ Setup logging
□ Baca manual: https://go.dev/doc/
```

### M2: Core Scanner (Week 3-4)

```
□ Implementasi filesystem scanner
□ Implementasi detector logic
□ Basic rule matching
□ Unit tests untuk core modules
```

### M3: Database Integration (Week 5-6)

```
□ Setup SQLite schema
□ Import sample CVE data
□ Database query operations
□ Integration dengan detector
```

### M4: Docker Scanner (Week 7-8)

```
□ Docker image pulling
□ Layer extraction
□ Package identification
□ Integration dengan scanner interface
```

### M5: Output & Polish (Week 9-10)

```
□ JSON output formatter
□ Table output formatter
□ SARIF output formatter
□ Error handling & edge cases
□ Documentation
```

---

## Success Criteria

```
1. User bisa install tool dengan `go install` atau download binary
2. User bisa scan docker image dan lihat list vulnerability
3. User bisa scan filesystem directory
4. User bisa tambah custom rule dengan YAML
5. Output bisa di-export ke JSON
6. Codebase punya unit test untuk core functionality
7. Documentation lengkap untuk beginner
```

---

## Referensi

```
- Trivy: https://github.com/aquasecurity/trivy
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- OWASP: https://owasp.org/www-project-vulnerability-management/
- Go Best Practices: https://go.dev/doc/effective_go
```

---

**Next:** Lihat `docs/02-ARCHITECTURE.md` untuk memahami bagaimana semua komponen bekerja bersama.
