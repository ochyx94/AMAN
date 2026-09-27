# 04 - Panduan Pengembangan

## Persiapan Lingkungan

### 1. Install Go

```bash
# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install golang-go

# macOS
brew install go

# Windows
# Download dari https://go.dev/dl/

# Verifikasi
go version
# Output: go version go1.21.x linux/amd64
```

### 2. Setup IDE

```
Rekomendasi IDE:
- VSCode + Go extension (gratis, ringan)
- GoLand (JetBrains, berbayar)
- VIM/Neovim + vim-go plugin

VSCode Setup:
1. Install VSCode
2. Install extension: "Go" oleh Go Team at Google
3. Buka folder vuln-scanner
4. Auto-complete sudah tersedia
```

### 3. Clone & Setup Project

```bash
# Clone atau buat folder
mkdir -p ~/projects/vuln-scanner
cd ~/projects/vuln-scanner

# Copy struktur folder yang sudah dibuat
# (jika ada dari backup sebelumnya)

# Initialize Go module
go mod init vuln-scanner

# Install dependencies
go mod tidy
```

---

## Langkah 1: Buat Entry Point (cmd/scanner/main.go)

### Buat file: cmd/scanner/main.go

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"

    "vuln-scanner/pkg/output"
    "vuln-scanner/pkg/scanner"
)

var (
    flagTarget   string
    flagScanType string
    flagFormat   string
    flagOutput   string
    flagVerbose  bool
)

func main() {
    // Setup cobra command
    rootCmd := &cobra.Command{
        Use:   "vuln-scanner",
        Short: "Simple vulnerability scanner",
        Long:  `VulnScanner adalah tools vulnerability scanner sederhana.

Contoh penggunaan:
  vuln-scanner scan --type filesystem --target /app
  vuln-scanner scan --type docker --target nginx:1.21`,
        Run: runScan,
    }

    // Setup flags
    rootCmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Target untuk di-scan")
    rootCmd.Flags().StringVarP(&flagScanType, "type", "y", "filesystem", "Type scan: docker, filesystem, http")
    rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "table", "Format output: json, table, sarif")
    rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output file (default: stdout)")
    rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")

    // Bind viper (untuk config file)
    viper.BindPFlag("target", rootCmd.Flags().Lookup("target"))
    viper.BindPFlag("type", rootCmd.Flags().Lookup("type"))
    viper.BindPFlag("format", rootCmd.Flags().Lookup("format"))

    // Execute
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func runScan(cmd *cobra.Command, args []string) {
    ctx := context.Background()

    // Validasi target
    if flagTarget == "" {
        fmt.Fprintln(os.Stderr, "Error: --target required")
        os.Exit(1)
    }

    // Setup logging (akan dibuat di pkg/logging)
    if flagVerbose {
        fmt.Println("[DEBUG] Starting scan...")
    }

    // Buat scanner
    scanEngine, err := scanner.NewScanner(flagScanType)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: invalid scan type: %s\n", flagScanType)
        os.Exit(1)
    }

    // Jalankan scan
    result, err := scanEngine.Scan(ctx, flagTarget)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
        os.Exit(1)
    }

    // Format output
    formatter := output.GetFormatter(flagFormat)
    outputBytes, err := formatter.Format(result)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
        os.Exit(1)
    }

    // Print
    if flagOutput != "" {
        os.WriteFile(flagOutput, outputBytes, 0644)
        fmt.Printf("Result saved to: %s\n", flagOutput)
    } else {
        fmt.Print(string(outputBytes))
    }
}
```

---

## Langkah 2: Buat Type Definitions (pkg/types)

### Buat file: pkg/types/types.go

```go
package types

import "time"

// Severity levels
type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)

// Package represents a software package
type Package struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Type     string `json:"type"` // "npm", "pip", "apt", "go", dll
    FilePath string `json:"file_path,omitempty"`
}

// Vulnerability represents a single vulnerability
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

// Result represents the complete scan result
type Result struct {
    Target         string            `json:"target"`
    ScannerType   string            `json:"scanner_type"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    ScanDuration  time.Duration     `json:"scan_duration"`
    ScannedAt     time.Time         `json:"scanned_at"`
}

// Rule represents a detection rule
type Rule struct {
    ID          string          `json:"id"`
    Title       string          `json:"title"`
    Severity    Severity        `json:"severity"`
    Description string          `json:"description"`
    Match       MatchCondition  `json:"match"`
    Reference   string          `json:"reference,omitempty"`
}

// MatchCondition defines how to match a rule
type MatchCondition struct {
    Package     string `json:"package,omitempty"`     // regex pattern
    Version     string `json:"version,omitempty"`      // e.g., "< 1.0.0"
    FilePattern string `json:"file_pattern,omitempty"` // regex for file content
}
```

---

## Langkah 3: Buat Scanner Interface (pkg/scanner)

### Buat file: pkg/scanner/scanner.go

```go
package scanner

import (
    "context"

    "vuln-scanner/pkg/types"
)

// Scanner adalah interface untuk semua scanner
type Scanner interface {
    // Scan menjalankan scan dan return list packages
    Scan(ctx context.Context, target string) ([]types.Package, error)

    // Name return nama scanner
    Name() string
}
```

### Buat file: pkg/scanner/factory.go

```go
package scanner

import "fmt"

// NewScanner membuat scanner berdasarkan type
func NewScanner(scanType string) (Scanner, error) {
    switch scanType {
    case "docker":
        return &DockerScanner{}, nil
    case "filesystem":
        return &FilesystemScanner{}, nil
    case "http":
        return &HTTPScanner{}, nil
    default:
        return nil, fmt.Errorf("unknown scan type: %s", scanType)
    }
}
```

---

## Langkah 4: Buat Filesystem Scanner (pkg/scanner)

### Buat file: pkg/scanner/filesystem.go

```go
package scanner

import (
    "context"
    "os"
    "path/filepath"
    "strings"

    "vuln-scanner/pkg/types"
)

// FilesystemScanner implements Scanner untuk filesystem
type FilesystemScanner struct{}

func (s *FilesystemScanner) Name() string {
    return "filesystem"
}

func (s *FilesystemScanner) Scan(ctx context.Context, target string) ([]types.Package, error) {
    var packages []types.Package

    // Walk directory
    err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil // skip error, continue walking
        }

        // Skip directories
        if info.IsDir() {
            return nil
        }

        // Detect package type by file extension
        pkg := detectPackageFromFile(path)
        if pkg != nil {
            packages = append(packages, *pkg)
        }

        return nil
    })

    if err != nil {
        return nil, err
    }

    return packages, nil
}

// detectPackageFromFile mendeteksi package dari file
func detectPackageFromFile(path string) *types.Package {
    ext := strings.ToLower(filepath.Ext(path))
    filename := filepath.Base(path)

    switch ext {
    case ".json":
        // package.json (npm)
        if filename == "package.json" {
            return &types.Package{
                Name:    "npm-package",
                Version: "unknown",
                Type:    "npm",
                FilePath: path,
            }
        }
        // requirements.txt (pip)
        if filename == "requirements.txt" {
            return &types.Package{
                Name:    "pip-package",
                Version: "unknown",
                Type:    "pip",
                FilePath: path,
            }
        }
    case ".txt":
        if filename == "Gemfile.lock" {
            return &types.Package{
                Name:    "ruby-gem",
                Version: "unknown",
                Type:    "gem",
                FilePath: path,
            }
        }
    case ".go":
        // go.mod
        if filename == "go.mod" {
            return &types.Package{
                Name:    "go-module",
                Version: "unknown",
                Type:    "go",
                FilePath: path,
            }
        }
    }

    return nil
}
```

---

## Langkah 5: Buat Docker Scanner Stub (pkg/scanner)

### Buat file: pkg/scanner/docker.go

```go
package scanner

import (
    "context"

    "vuln-scanner/pkg/types"
)

// DockerScanner implements Scanner untuk Docker image
type DockerScanner struct{}

func (s *DockerScanner) Name() string {
    return "docker"
}

func (s *DockerScanner) Scan(ctx context.Context, target string) ([]types.Package, error) {
    // V1: Return empty - implementasi penuh di M4
    // Untuk sekarang, return placeholder
    return []types.Package{
        {
            Name:    "docker-image",
            Version: "placeholder",
            Type:    "docker",
            FilePath: target,
        },
    }, nil
}
```

### Buat file: pkg/scanner/http.go

```go
package scanner

import (
    "context"

    "vuln-scanner/pkg/types"
)

// HTTPScanner implements Scanner untuk HTTP endpoint
type HTTPScanner struct{}

func (s *HTTPScanner) Name() string {
    return "http"
}

func (s *HTTPScanner) Scan(ctx context.Context, target string) ([]types.Package, error) {
    // V1: Return empty - implementasi penuh di M5
    return []types.Package{}, nil
}
```

---

## Langkah 6: Buat Output Formatter (pkg/output)

### Buat file: pkg/output/output.go

```go
package output

import (
    "vuln-scanner/pkg/types"
)

// OutputFormatter interface untuk semua formatter
type OutputFormatter interface {
    Format(result types.Result) ([]byte, error)
    Extension() string
}

// GetFormatter membuat formatter berdasarkan nama
func GetFormatter(formatName string) OutputFormatter {
    switch formatName {
    case "json":
        return &JSONFormatter{}
    case "table":
        return &TableFormatter{}
    case "sarif":
        return &SARIFFormatter{}
    default:
        return &TableFormatter{} // default
    }
}
```

### Buat file: pkg/output/json.go

```go
package output

import (
    "encoding/json"
    "vuln-scanner/pkg/types"
)

// JSONFormatter implements OutputFormatter untuk JSON
type JSONFormatter struct{}

func (j *JSONFormatter) Format(result types.Result) ([]byte, error) {
    return json.MarshalIndent(result, "", "  ")
}

func (j *JSONFormatter) Extension() string {
    return ".json"
}
```

### Buat file: pkg/output/table.go

```go
package output

import (
    "fmt"
    "vuln-scanner/pkg/types"
)

// TableFormatter implements OutputFormatter untuk Tabel
type TableFormatter struct{}

func (t *TableFormatter) Format(result types.Result) ([]byte, error) {
    output := fmt.Sprintf("=== VulnScanner Result ===\n")
    output += fmt.Sprintf("Target: %s\n", result.Target)
    output += fmt.Sprintf("Scanner: %s\n", result.ScannerType)
    output += fmt.Sprintf("Duration: %s\n", result.ScanDuration)
    output += fmt.Sprintf("\n")

    if len(result.Vulnerabilities) == 0 {
        output += "No vulnerabilities found.\n"
        return []byte(output), nil
    }

    output += fmt.Sprintf("%-15s %-10s %-15s %s\n", "SEVERITY", "PACKAGE", "VERSION", "ID")
    output += fmt.Sprintf("%-15s %-10s %-15s %s\n", "---------", "-------", "-------", "--")

    for _, v := range result.Vulnerabilities {
        output += fmt.Sprintf("%-15s %-10s %-15s %s\n",
            v.Severity,
            v.Package.Name,
            v.Package.Version,
            v.ID,
        )
    }

    output += fmt.Sprintf("\nTotal: %d vulnerabilities found.\n", len(result.Vulnerabilities))

    return []byte(output), nil
}

func (t *TableFormatter) Extension() string {
    return ".txt"
}
```

---

## Langkah 7: Buat SARIF Formatter (pkg/output)

### Buat file: pkg/output/sarif.go

```go
package output

import (
    "encoding/json"
    "vuln-scanner/pkg/types"
)

// SARIFFormatter implements OutputFormatter untuk SARIF
type SARIFFormatter struct{}

func (s *SARIFFormatter) Format(result types.Result) ([]byte, error) {
    // Simplified SARIF structure
    sarif := map[string]interface{}{
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": []map[string]interface{}{
            {
                "tool": map[string]interface{}{
                    "driver": map[string]interface{}{
                        "name":    "VulnScanner",
                        "version": "1.0.0",
                    },
                },
                "results": buildSARIFResults(result),
            },
        },
    }

    return json.MarshalIndent(sarif, "", "  ")
}

func buildSARIFResults(result types.Result) []map[string]interface{} {
    var results []map[string]interface{}

    for _, v := range result.Vulnerabilities {
        results = append(results, map[string]interface{}{
            "ruleId":    v.ID,
            "ruleIndex": 0,
            "level":     severityToSARIFLevel(v.Severity),
            "message": map[string]string{
                "text": v.Description,
            },
            "locations": []map[string]interface{}{
                {
                    "physicalLocation": map[string]interface{}{
                        "artifactLocation": map[string]string{
                            "uri": v.Package.FilePath,
                        },
                    },
                },
            },
        })
    }

    return results
}

func severityToSARIFLevel(severity types.Severity) string {
    switch severity {
    case types.SeverityCritical:
        return "error"
    case types.SeverityHigh:
        return "error"
    case types.SeverityMedium:
        return "warning"
    default:
        return "note"
    }
}

func (s *SARIFFormatter) Extension() string {
    return ".sarif"
}
```

---

## Langkah 8: Setup Testing & Run

### Test Basic Functionality

```bash
# Run build untuk check error
go build -o vuln-scanner ./cmd/scanner

# Run help
./vuln-scanner --help

# Run scan
./vuln-scanner scan --target /tmp --type filesystem --format table
```

### Test Expected Output

```
=== VulnScanner Result ===
Target: /tmp
Scanner: filesystem
Duration: 0s

No vulnerabilities found.

Total: 0 vulnerabilities found.
```

---

**TODO: Lanjut ke docs/05-TESTING.md**
