# 03 - Komponen Detail

## Daftar Komponen

| Komponen | Lokasi | Fungsi |
|---|---|---|
| cmd/scanner | cmd/scanner/main.go | Entry point CLI |
| scanner | pkg/scanner/ | Orchestrator scanning |
| detector | pkg/detector/ | Logic deteksi vulnerability |
| rule | pkg/rule/ | Rule engine & matching |
| types | pkg/types/ | Definisi tipe data |
| output | pkg/output/ | Format output |
| database | pkg/database/ | SQLite operations |
| httpclient | pkg/httpclient/ | HTTP client wrapper |

---

## cmd/scanner (Entry Point)

###Deskripsi
- Titik pertama program berjalan
- Parse argument CLI
- Inisialisasi komponen
- Jalankan scan

###File
- cmd/scanner/main.go

###Alur
```
1. Parse flags (--target, --type, --format, dll)
2. Validasi input
3. Setup logger
4. Buat scanner sesuai type
5. Jalankan scan()
6. Format hasil dengan output pkg
7. Print ke stdout / save ke file
```

###Flags CLI
```
--target, -t     → Target scan (image name, path, URL)
--type, -y       → Type scan (docker, filesystem, http)
--format, -f     → Format output (json, table, sarif)
--output, -o     → Output file (default: stdout)
--rule-dir       → Directory untuk custom rules
--db-path        → Path ke SQLite database
--verbose, -v    → Verbose logging
--help, -h       → Show help
```

---

## pkg/scanner (Orchestrator)

###Deskripsi
- Mengkoordinasi proses scanning
- Memilih scanner yang sesuai
- Menyatukan hasil dari berbagai scanner

###SubKomponen

####1. scanner.go (Interface)
```go
type Scanner interface {
    Scan(ctx context.Context, target string) ([]Package, error)
    Name() string
}
```
- Definisikan contract untuk semua scanner
- Setiap scanner harus implement Scan() dan Name()

####2. factory.go
```go
func NewScanner(targetType string) (Scanner, error)
```
- Buat scanner sesuai dengan type yang diminta
- Return error jika type tidak dikenal

####3. docker.go
- Scanner untuk Docker image
- Extract layers dan parse packages
- Dependency: buildkit atau docker client

####4. filesystem.go
- Scanner untuk filesystem
- Walk directory tree
- Identify package files (package.json, requirements.txt, dll)

####5. http.go
- Scanner untuk HTTP endpoint
- Fetch content dan analyze
- Pattern matching untuk known vulnerabilities

###Contoh Penggunaan
```go
scanner, _ := scanner.NewScanner("filesystem")
result, _ := scanner.Scan(ctx, "/app")
```

---

## pkg/detector (Otak)

###Deskripsi
- Memproses hasil scan
- Mencocokkan dengan vulnerability database
- Menentukan severity dan risk level

###SubKomponen

####1. detector.go (Main Logic)
```go
type Detector struct {
    db     *database.DB
    rules  *rule.Engine
}

func (d *Detector) Detect(packages []Package) ([]Vulnerability, error)
```

####2. vulnMatcher.go
- Logic untuk mencocokkan package dengan CVE
- Handle version comparison
- Multiple matching strategies

###Alur Kerja
```
1. Terima list Package dari scanner
2. Load relevant rules dari rule engine
3. Untuk setiap package:
   a. Query database untuk CVE terkait
   b. Match dengan rule patterns
   c. Hitung severity score
4. Return list Vulnerability
```

###Severity Calculation
```go
// Severity based on CVSS score
func calculateSeverity(cvss float64) Severity {
    switch {
    case cvss >= 9.0: return CRITICAL
    case cvss >= 7.0: return HIGH
    case cvss >= 4.0: return MEDIUM
    default:          return LOW
    }
}
```

---

## pkg/rule (Aturan)

###Deskripsi
- Menyimpan dan memproses vulnerability rules
- Rule berbasis YAML format
- Bisa custom oleh user

###SubKomponen

####1. rule.go
```go
type Rule struct {
    ID          string
    Title       string
    Severity    Severity
    Description string
    Match       MatchCondition
    Reference   string
}

type MatchCondition struct {
    Package      string // regex pattern
    Version      string // version condition
    FilePattern  string // regex for file content
}
```

####2. loader.go
```go
func LoadRules(ruleDir string) ([]Rule, error)
func ValidateRule(rule Rule) error
```
- Load semua rule dari directory
- Parse YAML ke struct
- Validasi rule format

###Contoh Rule (YAML)
```yaml
id: CUSTOM-001
title: SQL Injection Risk
severity: HIGH
description: Potential SQL injection in user input
match:
  package: mysql-connector
  version: "< 2.0.0"
reference: https://example.com/cve/CUSTOM-001
```

---

## pkg/types (Definisi Data)

###Deskripsi
- Definisi semua struct yang dipakai
- Tidak punya logic, hanya data structures

###Struct Utama

####Package
```go
type Package struct {
    Name      string
    Version   string
    Type     string  // "npm", "pip", "apt", dll
    FilePath  string
}
```

####Vulnerability
```go
type Vulnerability struct {
    ID          string
    Title       string
    Severity    Severity
    Description string
    Package     Package
    FixedVersion string
    Reference   string
    CVSS        float64
}
```

####Result
```go
type Result struct {
    Target       string
    ScannerType  string
    Vulnerabilities []Vulnerability
    ScanDuration time.Duration
    ScannedAt    time.Time
}
```

####Severity Enum
```go
type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)
```

---

## pkg/output (Output)

###Deskripsi
- Format hasil scan ke berbagai format
- Print ke terminal atau save ke file

###SubKomponen

####1. output.go (Interface)
```go
type OutputFormatter interface {
    Format(result Result) ([]byte, error)
    Extension() string
}
```

####2. json.go
```go
type JSONFormatter struct{}

func (j JSONFormatter) Format(result Result) ([]byte, error)
func (j JSONFormatter) Extension() string  // return ".json"
```

####3. table.go
```go
type TableFormatter struct{}

func (t TableFormatter) Format(result Result) ([]byte, error)
func (t TableFormatter) Extension() string  // return ".txt"
```

####4. sarif.go
```go
type SARIFFormatter struct{}

func (s SARIFFormatter) Format(result Result) ([]byte, error)
func (s SARIFFormatter) Extension() string  // return ".sarif"
```

###Cara Pakai
```go
formatter := output.GetFormatter("json")
bytes, _ := formatter.Format(result)
fmt.Print(string(bytes))
```

---

## pkg/database (Database)

###Deskripsi
- SQLite operations untuk CVE data
- Query dan update vulnerability database

###SubKomponen

####1. db.go
```go
type DB struct {
    conn *sql.DB
}

func Open(path string) (*DB, error)
func (db *DB) Close() error
func (db *DB) GetVulnerabilities(pkg Package) ([]Vulnerability, error)
func (db *DB) SearchCVE(keyword string) ([]CVE, error)
```

####2. migration.go
```go
func (db *DB) Migrate() error
```
- Create tables jika belum ada
- Setup schema

###Schema

####packages table
```sql
CREATE TABLE packages (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL  -- npm, pip, apt, dll
);
```

####vulnerabilities table
```sql
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,  -- CVE-XXXX-XXXX
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss REAL,
    fixed_version TEXT,
    reference TEXT
);
```

####package_vulnerabilities table
```sql
CREATE TABLE package_vulnerabilities (
    package_id INTEGER,
    vuln_id TEXT,
    version_range TEXT,  -- ">=1.0.0 <2.0.0"
    PRIMARY KEY (package_id, vuln_id)
);
```

---

## pkg/httpclient (HTTP Client)

###Deskripsi
- Wrapper untuk net/http
- Handle retries, timeouts, errors
- untuk HTTP-based scanning

###Fitur
```go
type Client struct {
    Timeout    time.Duration
    MaxRetries int
    UserAgent  string
}

func (c *Client) Get(url string) (*Response, error)
func (c *Client) Post(url string, body []byte) (*Response, error)
```

###Konfigurasi Default
```go
DefaultClient = &Client{
    Timeout:    30 * time.Second,
    MaxRetries: 3,
    UserAgent:  "AMAN/1.0",
}
```

---

## pkg/httpclient (HTTP Client)

###Deskripsi
- Wrapper untuk net/http
- Handle retries, timeouts, errors
- Untuk HTTP-based scanning

###Fitur
```go
type Client struct {
    Timeout    time.Duration
    MaxRetries int
    UserAgent  string
}

func (c *Client) Get(url string) (*Response, error)
func (c *Client) Post(url string, body []byte) (*Response, error)
```

###Konfigurasi Default
```go
DefaultClient = &Client{
    Timeout:    30 * time.Second,
    MaxRetries: 3,
    UserAgent:  "AMAN/1.0",
}
```

---

## Diagram Hubungan Komponen

```
┌──────────────────────────────────────────────────────┐
│                      USER                             │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│                  cmd/scanner/main.go                  │
│                  (Parse CLI Args)                     │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│                   pkg/scanner/                        │
│               (Select & Run Scanner)                  │
│  ┌─────────────┬──────────────┬──────────────┐       │
│  │   docker   │  filesystem  │    http      │       │
│  └─────────────┴──────────────┴──────────────┘       │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│                   pkg/detector/                       │
│           (Match dengan Rules & DB)                   │
└──────────────────────────────────────────────────────┘
           │                        │
           ▼                        ▼
┌──────────────────┐    ┌──────────────────────────┐
│    pkg/rule/     │    │      pkg/database/        │
│  (Load & Match)  │    │   (Query CVE Data)       │
└──────────────────┘    └──────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│                    pkg/output/                        │
│              (Format & Print Result)                 │
│  ┌─────────────┬──────────────┬──────────────┐       │
│  │    json    │    table     │    sarif     │       │
│  └─────────────┴──────────────┴──────────────┘       │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│                      USER                             │
└──────────────────────────────────────────────────────┘
```

---

## Package Dependencies

```
cmd/scanner
    └── pkg/scanner
            ├── pkg/types
            ├── pkg/detector
            │       ├── pkg/rule
            │       └── pkg/database
            ├── pkg/output
            │       └── pkg/types
            └── pkg/httpclient

Ket: → = imports
```

---

**Next:** Lihat `docs/04-DEVELOPMENT.md` untuk langkah-langkah implementasi code.
