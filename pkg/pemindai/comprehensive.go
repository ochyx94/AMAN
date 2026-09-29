package pemindai

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ComprehensiveScan hasil scan komprehensif
type ComprehensiveScan struct {
	ServerInfo   ServerInfo           `json:"server_info"`
	Folders     []FolderScanResult   `json:"folders"`
	DockerImages []DockerImageResult  `json:"docker_images"`
	WebServices []WebServiceResult   `json:"web_services"`
	TotalVulns  int                  `json:"total_vulnerabilities"`
}

// ServerInfo informasi tentang server
type ServerInfo struct {
	Hostname    string `json:"hostname"`
	OS         string `json:"os"`
	Kernel     string `json:"kernel"`
	Uptime     string `json:"uptime"`
	DockerVer  string `json:"docker_version"`
}

// FolderScanResult hasil scan folder
type FolderScanResult struct {
	Path      string `json:"path"`
	PackageCount int `json:"package_count"`
	Error     string `json:"error,omitempty"`
}

// DockerImageResult hasil scan docker images
type DockerImageResult struct {
	Image   string `json:"image"`
	Size    string `json:"size"`
	Tags    []string `json:"tags"`
	Error   string `json:"error,omitempty"`
}

// WebServiceResult hasil scan web service
type WebServiceResult struct {
	URL      string `json:"url"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	SSLValid bool   `json:"ssl_valid"`
}

// ComprehensiveScanner scanner untuk semua
type ComprehensiveScanner struct{}

// NewComprehensiveScanner buat scanner baru
func NewComprehensiveScanner() *ComprehensiveScanner {
	return &ComprehensiveScanner{}
}

// GetServerInfo mendapatkan informasi server
func (s *ComprehensiveScanner) GetServerInfo() ServerInfo {
	return s.getServerInfo()
}

// Run menjalankan scan komprehensif
func (s *ComprehensiveScanner) Run() (*ComprehensiveScan, error) {
	result := &ComprehensiveScan{}

	// 1. Get server info
	result.ServerInfo = s.getServerInfo()

	// 2. Scan common directories
	result.Folders = s.scanCommonDirs()

	// 3. Scan Docker images
	result.DockerImages = s.scanDockerImages()

	// 4. Scan web services
	result.WebServices = s.scanWebServices()

	return result, nil
}

func (s *ComprehensiveScanner) getServerInfo() ServerInfo {
	info := ServerInfo{}

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// OS (读取 /etc/os-release)
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Kernel
	if kernel, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(kernel))
	}

	// Docker version
	if dockerVer, err := exec.Command("docker", "--version").Output(); err == nil {
		info.DockerVer = strings.TrimSpace(string(dockerVer))
	}

	// Uptime
	if uptime, err := exec.Command("uptime", "-s").Output(); err == nil {
		info.Uptime = strings.TrimSpace(string(uptime))
	}

	return info
}

func (s *ComprehensiveScanner) scanCommonDirs() []FolderScanResult {
	commonPaths := []string{
		"/var/www",
		"/home",
		"/opt",
		"/srv",
		"/usr/local/src",
		"/root",
	}

	// Add current directory's parent project paths
	wd, _ := os.Getwd()
	if wd != "" {
		commonPaths = append(commonPaths, filepath.Dir(wd))
	}

	var results []FolderScanResult
	seen := make(map[string]bool)

	for _, path := range commonPaths {
		// Skip duplicates
		if seen[path] {
			continue
		}
		seen[path] = true

		// Skip if doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		result := FolderScanResult{
			Path: path,
		}

		// Count files
		count := s.countPackageFiles(path)
		result.PackageCount = count

		results = append(results, result)
	}

	return results
}

func (s *ComprehensiveScanner) countPackageFiles(path string) int {
	patterns := []string{
		"package.json",
		"requirements.txt",
		"go.mod",
		"Gemfile",
		"Cargo.toml",
		"pom.xml",
		"build.gradle",
		"*.cpan",
		"*.gem",
	}

	count := 0

	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			// Skip common non-package dirs
			skipDirs := []string{
				"node_modules",
				".git",
				"vendor",
				"__pycache__",
				".cache",
			}
			for _, skip := range skipDirs {
				if info.Name() == skip {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check each pattern
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, "*.") {
				ext := pattern[1:]
				if strings.HasSuffix(info.Name(), ext) {
					count++
					break
				}
			} else if info.Name() == pattern {
				count++
				break
			}
		}

		return nil
	})

	return count
}

func (s *ComprehensiveScanner) scanDockerImages() []DockerImageResult {
	var results []DockerImageResult

	// Check if docker is available
	if !isDockerAvailable() {
		return results
	}

	// Get docker images
	cmd := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}|{{.Size}}")
	output, err := cmd.Output()
	if err != nil {
		return results
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 2 {
			results = append(results, DockerImageResult{
				Image: parts[0],
				Size:  parts[1],
			})
		}
	}

	return results
}

func (s *ComprehensiveScanner) scanWebServices() []WebServiceResult {
	var results []WebServiceResult

	// Common web service ports
	ports := []int{80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 8000, 8888, 9000}

	// Check localhost
	for _, port := range ports {
		url := fmt.Sprintf("http://localhost:%d", port)
		if isPortOpen("localhost", port) {
			ssl := port == 443 || port == 8443
			results = append(results, WebServiceResult{
				URL:      url,
				Port:     port,
				Status:   "running",
				SSLValid: ssl,
			})
		}
	}

	return results
}

func isDockerAvailable() bool {
	_, err := exec.Command("docker", "version").Output()
	return err == nil
}

func isPortOpen(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := os.Create(address)
	if err != nil {
		return true // Assume open if we can create
	}
	conn.Close()
	return false
}
