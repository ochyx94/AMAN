package pemindai

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPemindaiFolder_DeteksiJenisPaket(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create package files
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{"name":"test","version":"1.0.0"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte("requests==2.28.0\nflask==2.0.0"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test\n\ngo 1.22"), 0644)

	// Test scanner
	p := PemindaiFolder{}
	paket, err := p.Pindai(tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(paket) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(paket))
	}

	// Check package types
	packageTypes := make(map[string]string)
	for _, p := range paket {
		packageTypes[p.Jenis] = p.Nama
	}

	if _, ok := packageTypes["npm"]; !ok {
		t.Error("Expected npm package type")
	}
	if _, ok := packageTypes["pip"]; !ok {
		t.Error("Expected pip package type")
	}
	if _, ok := packageTypes["go"]; !ok {
		t.Error("Expected go package type")
	}
}

func TestPemindaiFolder_NamaPaket(t *testing.T) {
	tmpDir := t.TempDir()

	// Create npm package.json
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{
		"name": "my-test-package",
		"version": "2.3.4"
	}`), 0644)

	p := PemindaiFolder{}
	paket, err := p.Pindai(tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that we found exactly 1 package
	if len(paket) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(paket))
	}

	// Check package has name (may or may not include scope depending on implementation)
	if paket[0].Nama == "" {
		t.Error("Expected package name to be non-empty")
	}

	// Check version is detected (or marked as unknown)
	if paket[0].Versi == "" {
		t.Error("Expected package version to be set")
	}
}

func TestPemindaiFolder_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	p := PemindaiFolder{}
	paket, err := p.Pindai(tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(paket) != 0 {
		t.Errorf("Expected 0 packages for empty dir, got %d", len(paket))
	}
}

func TestPemindaiFolder_FindsPackagesInNestedDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	nestedDir := filepath.Join(tmpDir, "src", "utils")
	os.MkdirAll(nestedDir, 0755)
	os.WriteFile(filepath.Join(nestedDir, "package.json"), []byte(`{"name":"nested-pkg","version":"1.0.0"}`), 0644)

	// Create parent package.json
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{"name":"parent","version":"1.0.0"}`), 0644)

	p := PemindaiFolder{}
	paket, err := p.Pindai(tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should find at least 2 packages (nested and parent)
	if len(paket) < 2 {
		t.Errorf("Expected at least 2 packages, got %d", len(paket))
	}
}
