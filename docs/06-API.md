# 06 - API Reference

## Daftar Package

| Package | Lokasi | Deskripsi |
|---|---|---|
| scanner | pkg/scanner/ | Scanner interface & implementations |
| detector | pkg/detector/ | Vulnerability detection |
| rule | pkg/rule/ | Rule engine |
| output | pkg/output/ | Output formatters |
| types | pkg/types/ | Data structures |
| database | pkg/database/ | SQLite operations |

---

## scanner (pkg/scanner/)

### Interface: Scanner

```go
type Scanner interface {
    Scan(ctx context.Context, target string) ([]types.Package, error)
    Name() string
}
```

### Functions

#### NewScanner

```go
func NewScanner(scanType string) (Scanner, error)
```

**Parameters:**
- `scanType` (string): Type scanner — "docker", "filesystem", atau "http"

**Return:**
- (Scanner, error): Scanner instance atau error

**Example:**
```go
scanner, err := scanner.NewScanner("filesystem")
if err != nil {
    log.Fatal(err)
}
packages, err := scanner.Scan(ctx, "/app")
```

---

### FilesystemScanner

```go
type FilesystemScanner struct{}
```

**Methods:**

```go
func (s *FilesystemScanner) Name() string
// Return: "filesystem"

func (s *FilesystemScanner) Scan(ctx context.Context, target string) ([]types.Package, error)
// Parameters:
//   - ctx: context.Context
//   - target: directory path
// Return: list of Package atau error
```

**Example:**
```go
s := &scanner.FilesystemScanner{}
packages, err := s.Scan(context.Background(), "/tmp/myapp")
```

---

### DockerScanner

```go
type DockerScanner struct{}
```

**Methods:**

```go
func (s *DockerScanner) Name() string
// Return: "docker"

func (s *DockerScanner) Scan(ctx context.Context, target string) ([]types.Package, error)
// Parameters:
//   - ctx: context.Context
//   - target: image name atau ID
// Return: list of Package atau error
```

---

### HTTPScanner

```go
type HTTPScanner struct{}
```

**Methods:**

```go
func (s *HTTPScanner) Name() string
// Return: "http"

func (s *HTTPScanner) Scan(ctx context.Context, target string) ([]types.Package, error)
// Parameters:
//   - ctx: context.Context
//   - target: URL
// Return: list of Package atau error
```

---

## detector (pkg/detector/)

### Detector

```go
type Detector struct {
    db    *database.DB
    rules *rule.Engine
}
```

**Constructor:**

```go
func NewDetector(db *database.DB, rules *rule.Engine) *Detector
```

**Methods:**

```go
func (d *Detector) Detect(packages []types.Package) ([]types.Vulnerability, error)
// Parameters:
//   - packages: list Package dari scanner
// Return: list Vulnerability yang ditemukan
```

**Example:**
```go
detector := detector.NewDetector(db, ruleEngine)
vulns, err := detector.Detect(packages)
```

---

## rule (pkg/rule/)

### Rule Struct

```go
type Rule struct {
    ID          string
    Title       string
    Severity    types.Severity
    Description string
    Match       MatchCondition
    Reference   string
}

type MatchCondition struct {
    Package     string  // regex pattern
    Version     string  // version condition
    FilePattern string  // regex for file content
}
```

### Functions

#### LoadRules

```go
func LoadRules(ruleDir string) ([]Rule, error)
```

**Parameters:**
- `ruleDir` (string): Path ke directory rule

**Return:**
- ([]Rule, error): List Rule atau error

**Example:**
```go
rules, err := rule.LoadRules("./rules/builtin")
```

#### ValidateRule

```go
func ValidateRule(r Rule) error
```

**Parameters:**
- `r` (Rule): Rule untuk divalidasi

**Return:**
- error jika rule tidak valid

---

## output (pkg/output/)

### Interface: OutputFormatter

```go
type OutputFormatter interface {
    Format(result types.Result) ([]byte, error)
    Extension() string
}
```

### Functions

#### GetFormatter

```go
func GetFormatter(formatName string) OutputFormatter
```

**Parameters:**
- `formatName` (string): "json", "table", atau "sarif"

**Return:**
- OutputFormatter instance

**Example:**
```go
formatter := output.GetFormatter("json")
bytes, err := formatter.Format(result)
```

---

### JSONFormatter

```go
type JSONFormatter struct{}
```

**Methods:**

```go
func (j *JSONFormatter) Format(result types.Result) ([]byte, error)
// Return: JSON encoded result

func (j *JSONFormatter) Extension() string
// Return: ".json"
```

---

### TableFormatter

```go
type TableFormatter struct{}
```

**Methods:**

```go
func (t *TableFormatter) Format(result types.Result) ([]byte, error)
// Return: Human-readable table format

func (t *TableFormatter) Extension() string
// Return: ".txt"
```

---

### SARIFFormatter

```go
type SARIFFormatter struct{}
```

**Methods:**

```go
func (s *SARIFFormatter) Format(result types.Result) ([]byte, error)
// Return: SARIF format untuk CI/CD integration

func (s *SARIFFormatter) Extension() string
// Return: ".sarif"
```

---

## types (pkg/types/)

### Severity

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

### Package

```go
type Package struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Type     string `json:"type"` // "npm", "pip", "apt", "go", dll
    FilePath string `json:"file_path,omitempty"`
}
```

---

### Vulnerability

```go
type Vulnerability struct {
    ID           string   `json:"id"`
    Title        string   `json:"title"`
    Description  string   `json:"description"`
    Severity     Severity `json:"severity"`
    Package      Package  `json:"package"`
    FixedVersion string   `json:"fixed_version,omitempty"`
    Reference    string   `json:"reference,omitempty"`
    CVSS         float64  `json:"cvss"`
}
```

---

### Result

```go
type Result struct {
    Target          string            `json:"target"`
    ScannerType     string            `json:"scanner_type"`
    Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
    ScanDuration    time.Duration     `json:"scan_duration"`
    ScannedAt       time.Time         `json:"scanned_at"`
}
```

---

## database (pkg/database/)

### DB

```go
type DB struct {
    conn *sql.DB
}
```

**Constructor:**

```go
func Open(path string) (*DB, error)
```

**Methods:**

```go
func (db *DB) Close() error
// Tutup koneksi database

func (db *DB) GetVulnerabilities(pkg types.Package) ([]types.Vulnerability, error)
// Parameters:
//   - pkg: Package untuk dicheck
// Return: list Vulnerability untuk package tersebut

func (db *DB) SearchCVE(keyword string) ([]CVE, error)
// Parameters:
//   - keyword: kata kunci pencarian
// Return: list CVE yang match

func (db *DB) Migrate() error
// Setup schema database
```

---

## httpclient (pkg/httpclient/)

### Client

```go
type Client struct {
    Timeout    time.Duration
    MaxRetries int
    UserAgent  string
}
```

**Constructor:**

```go
func NewClient() *Client
// Return: Client dengan konfigurasi default
```

**Methods:**

```go
func (c *Client) Get(url string) (*Response, error)
// GET request

func (c *Client) Post(url string, body []byte) (*Response, error)
// POST request dengan JSON body
```

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|---|---|---|
| `context deadline exceeded` | Timeout | Increase timeout atau check network |
| `invalid scan type` | Unknown type | Gunakan: docker, filesystem, http |
| `rule not found` | Rule file missing | Check rule directory path |
| `database locked` | Concurrent access | Close connection properly |

### Pattern Error Handling

```go
packages, err := scanner.Scan(ctx, target)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Fatal("scan timeout")
    }
    log.Fatalf("scan error: %v", err)
}
```

---

## Usage Examples

### Complete Scan Flow

```go
package main

import (
    "context"
    "fmt"
    "log"

    "aman/pkg/database"
    "aman/pkg/detector"
    "aman/pkg/output"
    "aman/pkg/rule"
    "aman/pkg/scanner"
)

func main() {
    // 1. Setup
    ctx := context.Background()

    // 2. Load rules
    rules, err := rule.LoadRules("./rules/builtin")
    if err != nil {
        log.Fatal(err)
    }
    ruleEngine := rule.NewEngine(rules)

    // 3. Open database
    db, err := database.Open("./vuln.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // 4. Create scanner
    s, err := scanner.NewScanner("filesystem")
    if err != nil {
        log.Fatal(err)
    }

    // 5. Scan
    packages, err := s.Scan(ctx, "/app")
    if err != nil {
        log.Fatal(err)
    }

    // 6. Detect
    det := detector.NewDetector(db, ruleEngine)
    vulns, err := det.Detect(packages)
    if err != nil {
        log.Fatal(err)
    }

    // 7. Format output
    result := types.Result{
        Target:          "/app",
        ScannerType:     s.Name(),
        Vulnerabilities: vulns,
    }

    formatter := output.GetFormatter("json")
    bytes, _ := formatter.Format(result)
    fmt.Print(string(bytes))
}
```

---

**End of Documentation**

Kembali ke: `docs/01-DESIGN.md`
