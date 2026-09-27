# 05 - Panduan Testing

## Overview Testing

Testing memastikan kode berjalan benar dan mencegah regression. Untuk project ini, kita gunakan:

```
Testing Framework: Go testing package + testify
Coverage Target: >70% untuk core modules
```

---

## Struktur Test

```
test/
├── unit/                    # Unit test per package
│   ├── scanner_test.go
│   ├── detector_test.go
│   └── rule_test.go
└── integration/            # Integration test
    └── scanner_integration_test.go
```

---

## Unit Test

### Contoh: Unit Test untuk Scanner

#### Buat file: test/unit/scanner_test.go

```go
package unit

import (
    "context"
    "testing"

    "aman/pkg/scanner"
)

func TestFilesystemScanner_Scan(t *testing.T) {
    // Setup
    s := &scanner.FilesystemScanner{}

    // Test scan directory yang ada
    packages, err := s.Scan(context.Background(), "/tmp")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // Verifikasi return list (bisa kosong, tapi tidak error)
    if packages == nil {
        t.Fatal("expected non-nil slice")
    }

    t.Logf("found %d packages", len(packages))
}

func TestFilesystemScanner_Name(t *testing.T) {
    s := &scanner.FilesystemScanner{}

    name := s.Name()
    if name != "filesystem" {
        t.Errorf("expected 'filesystem', got '%s'", name)
    }
}

func TestDockerScanner_Scan(t *testing.T) {
    s := &scanner.DockerScanner{}

    packages, err := s.Scan(context.Background(), "nginx:1.21")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // V1: placeholder scanner return empty atau placeholder
    t.Logf("docker scanner returned %d packages", len(packages))
}

func TestHTTPScanner_Scan(t *testing.T) {
    s := &scanner.HTTPScanner{}

    packages, err := s.Scan(context.Background(), "http://example.com")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    if len(packages) != 0 {
        t.Errorf("expected 0 packages for http scanner in V1")
    }
}
```

---

## Unit Test untuk Types

#### Buat file: test/unit/types_test.go

```go
package unit

import (
    "testing"

    "aman/pkg/types"
)

func TestSeverity_Ordering(t *testing.T) {
    levels := []types.Severity{
        types.SeverityLow,
        types.SeverityMedium,
        types.SeverityHigh,
        types.SeverityCritical,
    }

    // Test severity comparison
    for i := 0; i < len(levels)-1; i++ {
        current := levels[i]
        next := levels[i+1]

        if current >= next {
            t.Errorf("severity ordering violated: %s >= %s", current, next)
        }
    }
}

func TestPackage_Creation(t *testing.T) {
    pkg := types.Package{
        Name:    "test-package",
        Version: "1.0.0",
        Type:    "npm",
        FilePath: "/app/package.json",
    }

    if pkg.Name != "test-package" {
        t.Errorf("expected name 'test-package', got '%s'", pkg.Name)
    }

    if pkg.Version != "1.0.0" {
        t.Errorf("expected version '1.0.0', got '%s'", pkg.Version)
    }
}

func TestVulnerability_Creation(t *testing.T) {
    pkg := types.Package{Name: "openssl", Version: "1.0.0", Type: "apt"}

    vuln := types.Vulnerability{
        ID:          "CVE-2024-1234",
        Title:       "Test Vulnerability",
        Severity:    types.SeverityHigh,
        Package:     pkg,
        FixedVersion: "1.0.1",
        CVSS:        7.5,
    }

    if vuln.ID != "CVE-2024-1234" {
        t.Errorf("unexpected ID: %s", vuln.ID)
    }

    if vuln.Severity != types.SeverityHigh {
        t.Errorf("unexpected severity: %s", vuln.Severity)
    }

    if vuln.CVSS != 7.5 {
        t.Errorf("unexpected CVSS: %f", vuln.CVSS)
    }
}
```

---

## Unit Test untuk Rule

#### Buat file: test/unit/rule_test.go

```go
package unit

import (
    "testing"

    "aman/pkg/types"
)

func TestMatchCondition_VersionComparison(t *testing.T) {
    testCases := []struct {
        condition string
        version   string
        expected  bool
    }{
        {"< 2.0.0", "1.0.0", true},
        {"< 2.0.0", "2.0.0", false},
        {"< 2.0.0", "3.0.0", false},
        {">= 1.0.0", "1.0.0", true},
        {">= 1.0.0", "2.0.0", true},
        {">= 1.0.0", "0.9.0", false},
        {"= 1.0.0", "1.0.0", true},
        {"= 1.0.0", "1.0.1", false},
    }

    for _, tc := range testCases {
        result := matchVersion(tc.condition, tc.version)
        if result != tc.expected {
            t.Errorf("matchVersion(%s, %s): expected %v, got %v",
                tc.condition, tc.version, tc.expected, result)
        }
    }
}

// Helper function untuk version matching
func matchVersion(condition, version string) bool {
    // Simplified implementation for testing
    // Real implementation akan lebih complex
    return true
}
```

---

## Unit Test untuk Output

#### Buat file: test/unit/output_test.go

```go
package unit

import (
    "testing"
    "time"

    "aman/pkg/output"
    "aman/pkg/types"
)

func TestJSONFormatter_Format(t *testing.T) {
    formatter := &output.JSONFormatter{}

    result := types.Result{
        Target:   "/app",
        ScannerType: "filesystem",
        Vulnerabilities: []types.Vulnerability{},
        ScanDuration: 100 * time.Millisecond,
        ScannedAt:  time.Now(),
    }

    bytes, err := formatter.Format(result)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    if len(bytes) == 0 {
        t.Error("expected non-empty output")
    }

    expectedExt := ".json"
    if formatter.Extension() != expectedExt {
        t.Errorf("expected extension %s, got %s", expectedExt, formatter.Extension())
    }
}

func TestTableFormatter_Format(t *testing.T) {
    formatter := &output.TableFormatter{}

    result := types.Result{
        Target:   "/app",
        ScannerType: "filesystem",
        Vulnerabilities: []types.Vulnerability{},
        ScanDuration: 100 * time.Millisecond,
        ScannedAt:  time.Now(),
    }

    bytes, err := formatter.Format(result)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    output := string(bytes)

    // Verifikasi header ada
    if !contains(output, "AMAN Result") {
        t.Error("expected header in output")
    }

    if !contains(output, "Target: /app") {
        t.Error("expected target in output")
    }
}

func TestGetFormatter(t *testing.T) {
    formatter := output.GetFormatter("json")
    if formatter == nil {
        t.Fatal("expected non-nil formatter")
    }

    // Default fallback
    formatter = output.GetFormatter("unknown")
    if formatter == nil {
        t.Fatal("expected default formatter")
    }
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
    for i := 0; i <= len(s)-len(substr); i++ {
        if s[i:i+len(substr)] == substr {
            return true
        }
    }
    return false
}
```

---

## Running Tests

### Jalankan Semua Test

```bash
cd /root/.openclaw/workspace/aman

# Semua test
go test ./...

# Verbose
go test -v ./...

# Dengan coverage
go test -cover ./...

# Specific package
go test -v ./test/unit/...
```

### Contoh Output

```
=== RUN   TestFilesystemScanner_Scan
--- PASS: TestFilesystemScanner_Scan (0.05s)
=== RUN   TestFilesystemScanner_Name
--- PASS: TestFilesystemScanner_Name (0.00s)
PASS
ok  	aman/test/unit	0.067s
```

---

## Coverage Report

### Generate Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage di browser
go tool cover -html=coverage.out

# Text report
go tool cover -func=coverage.out
```

### Target Coverage

| Package | Target |
|---|---|
| pkg/types | 100% (simple data structures) |
| pkg/scanner | 80% |
| pkg/output | 80% |
| pkg/rule | 70% |
| pkg/detector | 70% |

---

## Integration Test

### Contoh: Integration Test Scanner

#### Buat file: test/integration/scanner_integration_test.go

```go
package integration

import (
    "context"
    "os"
    "testing"

    "aman/pkg/scanner"
)

func TestFilesystemScanner_Integration(t *testing.T) {
    // Buat temporary directory dengan test files
    tmpDir, err := os.MkdirTemp("", "aman-test")
    if err != nil {
        t.Fatalf("failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tmpDir)

    // Buat test file
    testFiles := []struct {
        path    string
        content string
    }{
        {"package.json", `{"name": "test", "version": "1.0.0"}`},
        {"requirements.txt", "requests==2.28.0\n"},
    }

    for _, tf := range testFiles {
        path := tmpDir + "/" + tf.path
        if err := os.WriteFile(path, []byte(tf.content), 0644); err != nil {
            t.Fatalf("failed to write test file: %v", err)
        }
    }

    // Test scan
    s := &scanner.FilesystemScanner{}
    packages, err := s.Scan(context.Background(), tmpDir)
    if err != nil {
        t.Fatalf("scan failed: %v", err)
    }

    if len(packages) == 0 {
        t.Log("no packages detected (acceptable for V1)")
    }

    t.Logf("detected %d packages", len(packages))
}
```

---

## Continuous Integration

### Setup CI dengan GitHub Actions

#### Buat file: .github/workflows/test.yml

```yaml
name: Test

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Download dependencies
        run: go mod tidy

      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
```

---

## Debugging Test Failures

### Tips

```
1. go test -v                  → verbose output
2. go test -race               → detect race conditions
3. go test -run TestName       → run specific test
4. go test -count=1           → disable test caching
5. go test -timeout 30s       → set timeout
```

### Common Issues

| Issue | Solution |
|---|---|
| Test timeout | Tambah timeout atau async |
| Race condition | Gunakan sync.Mutex |
| Mock not working | Verifikasi interface |
| Flaky test | Jaga test independence |

---

**TODO: Lanjut ke docs/06-API.md**
