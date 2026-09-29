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

	if len(paket) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(paket))
	}

	if paket[0].Nama != "my-test-package" {
		t.Errorf("Expected package name 'my-test-package', got '%s'", paket[0].Nama)
	}

	if paket[0].Versi != "2.3.4" {
		t.Errorf("Expected version '2.3.4', got '%s'", paket[0].Versi)
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

func TestPemindaiFolder_NestedDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	nodeModules := filepath.Join(tmpDir, "node_modules", "lodash")
	os.MkdirAll(nodeModules, 0755)
	os.WriteFile(filepath.Join(nodeModules, "package.json"), []byte(`{"name":"lodash","version":"4.17.21"}`), 0644)

	// Create parent package.json
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{"name":"parent","version":"1.0.0"}`), 0644)

	p := PemindaiFolder{}
	paket, err := p.Pindai(tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should find at least the parent package
	found := false
	for _, pk := range paket {
		if pk.Nama == "parent" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find parent package")
	}
}
