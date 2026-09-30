package pemindai

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"aman/pkg/tipe"
)

// SystemPackage represents an installed system package
type SystemPackage struct {
	Name    string
	Version string
	Arch    string
	Ecosystem string  // "rpm" or "dpkg"
}

// NewSystemPackageScanner creates a new system package scanner
func NewSystemPackageScanner() *SystemPackageScanner {
	return &SystemPackageScanner{}
}

// SystemPackageScanner scans installed system packages
type SystemPackageScanner struct{}

// ScanSystemPackages scans all installed system packages
func (s *SystemPackageScanner) ScanSystemPackages() []SystemPackage {
	var packages []SystemPackage

	// Try RPM first (RHEL, CentOS, Fedora)
	if rpmPkgs := s.scanRPM(); len(rpmPkgs) > 0 {
		packages = append(packages, rpmPkgs...)
	}

	// Try DPKG (Debian, Ubuntu)
	if dpkgPkgs := s.scanDPKG(); len(dpkgPkgs) > 0 {
		packages = append(packages, dpkgPkgs...)
	}

	return packages
}

// scanRPM scans RPM packages
func (s *SystemPackageScanner) scanRPM() []SystemPackage {
	var packages []SystemPackage

	// Try rpm -qa first
	cmd := exec.Command("rpm", "-qa", "--qf", "%{NAME}|%{VERSION}|%{ARCH}\n")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 2 {
				pkg := SystemPackage{
					Name:       parts[0],
					Version:    parts[1],
					Ecosystem:  "rpm",
				}
				if len(parts) >= 3 {
					pkg.Arch = parts[2]
				}
				packages = append(packages, pkg)
			}
		}
		return packages
	}

	// Fallback: parse rpm -qa differently
	cmd = exec.Command("rpm", "-qa")
	output, err = cmd.Output()
	if err != nil {
		return packages
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Parse name-version-release.arch format
		pkg := parseRPMName(line)
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}

	return packages
}

// parseRPMName parses RPM package name with version
func parseRPMName(line string) SystemPackage {
	// RPM format: name-version-release.arch
	// Examples: openssl-1.0.2k-9.el8.x86_64
	//          python3-3.6.8-18.el8.x86_64
	
	re := regexp.MustCompile(`^([a-zA-Z0-9_+.-]+)-([0-9]+:[])?([a-zA-Z0-9_+.-]+)-([a-zA-Z0-9_+.~]+)\.([a-zA-Z0-9_]+)$`)
	matches := re.FindStringSubmatch(line)
	
	if len(matches) >= 5 {
		return SystemPackage{
			Name:      matches[1],
			Version:   matches[3],
			Arch:      matches[5],
			Ecosystem: "rpm",
		}
	}
	
	// Simpler parse: just split by first dash
	parts := strings.SplitN(line, "-", 2)
	if len(parts) >= 2 {
		return SystemPackage{
			Name:      parts[0],
			Version:   parts[1],
			Ecosystem: "rpm",
		}
	}
	
	return SystemPackage{Name: line, Ecosystem: "rpm"}
}

// scanDPKG scans DPKG packages
func (s *SystemPackageScanner) scanDPKG() []SystemPackage {
	var packages []SystemPackage

	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		return packages
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header lines
		if strings.HasPrefix(line, "ii") || strings.HasPrefix(line, "Desired=") {
			continue
		}
		if !strings.HasPrefix(line, "ii  ") {
			continue
		}
		
		// Parse: ii  package-name  version  arch  description
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			pkg := SystemPackage{
				Name:      parts[1],
				Version:   parts[2],
				Arch:      parts[3],
				Ecosystem: "dpkg",
			}
			packages = append(packages, pkg)
		}
	}

	return packages
}

// ToPaket converts SystemPackage to generic Paket for CVE matching
func (sp SystemPackage) ToPaket() tipe.Paket {
	return tipe.Paket{
		Nama:    sp.Name,
		Versi:   sp.Version,
		Jenis:   sp.Ecosystem,
		Lokasi:  fmt.Sprintf("/var/lib/%s/%s", sp.Ecosystem, sp.Name),
	}
}
