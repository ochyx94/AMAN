package pemindai

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"aman/pkg/tipe"
)

// PemindaiDocker untuk memindai container images
type PemindaiDocker struct {
	ImageName string
}

// HasilDockerImage adalah hasil pemindaian image
type HasilDockerImage struct {
	Image     string
	Layers    int
	Paket     []PaketManifest
	Size      int64
	CreatedBy string
}

// PaketManifest adalah informasi paket dari image
type PaketManifest struct {
	Type     string `json:"Type"`
	Name     string `json:"Name"`
	Version  string `json:"Version"`
	Path     string `json:"Path,omitempty"`
	Ecosystem string `json:"Ecosystem"`
}

// Pindai memindai docker image
func (p *PemindaiDocker) Pindai(image string) ([]tipe.Paket, error) {
	p.ImageName = image

	var paket []tipe.Paket

	// Cek apakah docker tersedia
	if !p.isDockerAvailable() {
		return nil, fmt.Errorf("Docker tidak tersedia atau tidak bisa diakses")
	}

	// Save image sebagai tar
	tarPath, err := p.saveImage(image)
	if err != nil {
		return nil, fmt.Errorf("gagal menyimpan image: %v", err)
	}
	defer os.Remove(tarPath)

	// Extract dan parse manifest
	manifest, err := p.extractManifest(tarPath)
	if err != nil {
		return nil, fmt.Errorf("gagal extract manifest: %v", err)
	}

	// Extract dan parse semua layers
	for _, layer := range manifest {
		layerPaket, err := p.extractPackagesFromLayer(tarPath, layer)
		if err != nil {
			continue // Skip layer yang gagal
		}
		paket = append(paket, layerPaket...)
	}

	// Deduplicate
	paket = p.deduplicatePaket(paket)

	return paket, nil
}

func (p *PemindaiDocker) isDockerAvailable() bool {
	// Cek apakah docker command ada
	_, err := os.Stat("/usr/bin/docker")
	if err == nil {
		return true
	}
	_, err = os.Stat("/usr/local/bin/docker")
	if err == nil {
		return true
	}
	return false
}

func (p *PemindaiDocker) saveImage(image string) (string, error) {
	// Tarball path
	tarPath := fmt.Sprintf("/tmp/aman_docker_%d.tar", os.Getpid())

	// Execute docker save
	proc, err := os.StartProcess("/usr/bin/docker", []string{"docker", "save", image, "-o", tarPath}, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return "", err
	}
	
	ps, err := proc.Wait()
	if err != nil || !ps.Success() {
		return "", fmt.Errorf("docker save failed")
	}

	return tarPath, nil
}

func (p *PemindaiDocker) extractManifest(tarPath string) ([]map[string]interface{}, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tr := tar.NewReader(file)

	// Cari manifest.json
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if strings.Contains(header.Name, "manifest.json") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}

			var manifest []map[string]interface{}
			err = json.Unmarshal(data, &manifest)
			if err != nil {
				return nil, err
			}

			return manifest, nil
		}
	}

	return nil, fmt.Errorf("manifest.json tidak ditemukan")
}

func (p *PemindaiDocker) extractPackagesFromLayer(tarPath string, layer map[string]interface{}) ([]tipe.Paket, error) {
	// Ambil diff ID dari layer
	diffID, ok := layer["diff_id"].(string)
	if !ok {
		return nil, fmt.Errorf("diff_id tidak ditemukan")
	}

	// Convert diff ID ke hash
	diffHash := strings.TrimPrefix(diffID, "sha256:")

	file, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tr := tar.NewReader(file)

	var packages []tipe.Paket

	// Cari folder yang sesuai dengan diff ID
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Cek apakah ini adalah layer yang kita cari
		// Layer ada di: /var/lib/docker/layers/...
		if strings.Contains(header.Name, diffHash) || 
		   strings.Contains(header.Name, "layer.db") {
			continue
		}

		// Extract file yang relevant untuk package detection
		if p.isPackageFile(header.Name) {
			paket := p.parsePackageFile(header.Name, tr)
			if paket.Nama != "" {
				packages = append(packages, paket)
			}
		}
	}

	return packages, nil
}

func (p *PemindaiDocker) isPackageFile(path string) bool {
	packageFiles := []string{
		"/var/lib/dpkg/status",
		"/var/lib/rpm/Packages",
		"/var/lib/alpm/local/",
		"/usr/share/doc/*/copyright",
		"/node_modules/.package-lock.json",
		"/package-lock.json",
		"/yarn.lock",
		"/package.json",
		"/requirements.txt",
		"/Pipfile",
		"/Pipfile.lock",
		"/go.mod",
		"/go.sum",
		"/Gemfile",
		"/Gemfile.lock",
		"/Cargo.toml",
		"/Cargo.lock",
		"/pom.xml",
		"/build.gradle",
		"/packages.config",
	}

	for _, pf := range packageFiles {
		if strings.Contains(path, pf) {
			return true
		}
	}
	return false
}

func (p *PemindaiDocker) parsePackageFile(path string, tr *tar.Reader) tipe.Paket {
	paket := tipe.Paket{
		Lokasi: path,
	}

	// Tentukan ecosystem berdasarkan path
	switch {
	case strings.Contains(path, "node_modules") || strings.Contains(path, "package"):
		paket.Jenis = "npm"
		paket = p.parseNPMPackage(tr, paket)
	case strings.Contains(path, "requirements.txt") || strings.Contains(path, "Pipfile"):
		paket.Jenis = "pip"
		paket = p.parsePipPackage(tr, paket)
	case strings.Contains(path, "go.mod") || strings.Contains(path, "go.sum"):
		paket.Jenis = "go"
		paket = p.parseGoPackage(tr, paket)
	case strings.Contains(path, "Gemfile") || strings.Contains(path, ".gemspec"):
		paket.Jenis = "rubygems"
		paket = p.parseGemPackage(tr, paket)
	case strings.Contains(path, "Cargo.toml") || strings.Contains(path, "Cargo.lock"):
		paket.Jenis = "cargo"
		paket = p.parseCargoPackage(tr, paket)
	case strings.Contains(path, "dpkg/status") || strings.Contains(path, "rpm/Packages"):
		paket.Jenis = "apt"
		paket = p.parseSystemPackage(tr, paket)
	}

	return paket
}

func (p *PemindaiDocker) parseNPMPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	// Parse package.json style
	var pkgJSON struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	json.Unmarshal(data, &pkgJSON)

	if pkgJSON.Name != "" {
		paket.Nama = pkgJSON.Name
		paket.Versi = pkgJSON.Version
	} else {
		// Parse dari content untuk lock file
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			if strings.Contains(line, "\"") && strings.Contains(line, "@") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 2 {
					paket.Nama = parts[1]
					break
				}
			}
		}
	}

	paket.Jenis = "npm"
	return paket
}

func (p *PemindaiDocker) parsePipPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "==") {
			parts := strings.Split(line, "==")
			if len(parts) >= 2 {
				paket.Nama = parts[0]
				paket.Versi = parts[1]
				break
			}
		}
	}

	paket.Jenis = "pip"
	return paket
}

func (p *PemindaiDocker) parseGoPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require ") {
			continue
		}
		if strings.HasPrefix(line, ")") {
			break
		}
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if parts[0] != "" {
					paket.Nama = parts[0]
					paket.Versi = parts[1]
					break
				}
			}
		}
	}

	paket.Jenis = "go"
	return paket
}

func (p *PemindaiDocker) parseGemPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "gem '") {
			parts := strings.Split(line, "'")
			if len(parts) >= 2 {
				paket.Nama = parts[1]
				if len(parts) >= 4 {
					paket.Versi = parts[3]
				}
				break
			}
		}
	}

	paket.Jenis = "rubygems"
	return paket
}

func (p *PemindaiDocker) parseCargoPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	lines := strings.Split(content, "\n")
	inDeps := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[dependencies]") || strings.HasPrefix(line, "[dev-dependencies]") {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}
		if inDeps && line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				paket.Nama = parts[0]
				paket.Versi = parts[1]
				break
			}
		}
	}

	paket.Jenis = "cargo"
	return paket
}

func (p *PemindaiDocker) parseSystemPackage(tr *tar.Reader, paket tipe.Paket) tipe.Paket {
	data, _ := io.ReadAll(tr)
	content := string(data)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Package:") {
			paket.Nama = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		}
		if strings.HasPrefix(line, "Version:") {
			paket.Versi = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			break
		}
	}

	paket.Jenis = "apt"
	return paket
}

func (p *PemindaiDocker) deduplicatePaket(paket []tipe.Paket) []tipe.Paket {
	seen := make(map[string]bool)
	var result []tipe.Paket

	for _, p := range paket {
		key := p.Jenis + ":" + p.Nama
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result
}

// GetImageInfo mendapatkan informasi tentang image
func (p *PemindaiDocker) GetImageInfo(image string) (*HasilDockerImage, error) {
	p.ImageName = image

	info := &HasilDockerImage{
		Image: image,
	}

	// docker inspect untuk dapat info lebih
	// docker images --format '{{.Size}}' untuk size
	// docker history untuk layer count

	return info, nil
}
