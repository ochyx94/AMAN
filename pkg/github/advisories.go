package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GitHubAdvisory adalah struktur data dari GitHub Advisories API
type GitHubAdvisory struct {
	GHSAID          string `json:"ghsa_id"`           // contoh: GHSA-xxxx-xxxx-xxxx
	Severity        string `json:"severity"`           // LOW, MEDIUM, HIGH, CRITICAL
	Summary         string `json:"summary"`            // judul singkat
	Description     string `json:"description"`         // penjelasan lengkap
	PublishedAt     string `json:"published_at"`       // tanggal publish
	UpdatedAt       string `json:"updated_at"`         // tanggal update
	Identifiers     []struct {
		Value string `json:"value"` // contoh: CVE-2024-xxxxx
		Type  string `json:"type"`  // CVE, GHSA
	} `json:"identifiers"`
	References      []struct {
		URL string `json:"url"`
	} `json:"references"`
	Vulnerabilities []struct {
		Package            PackageInfo `json:"package"`
		ecosystem         string     `json:"ecosystem"`
		VulnerableVersion string     `json:"vulnerable_version_range"`
		FirstPatchedVersion string   `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

// PackageInfo adalah info paket
type PackageInfo struct {
	Ecosystem string `json:"ecosystem"` // npm, pip, go, dll
	Name     string `json:"name"`      // nama paket
}

// Client adalah HTTP client untuk GitHub Advisories
type Client struct {
	client *http.Client
	baseURL string
}

// NewClient membuat client baru
func NewClient() *Client {
	return &Client{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.github.com/advisories",
	}
}

// FetchAdvisories mengambil daftar advisory dari GitHub
func (c *Client) FetchAdvisories(ecosystem string) ([]GitHubAdvisory, error) {
	// Buat request
	// GitHub API untuk advisories: GET /advisories
	// Query param: ?ecosystem=npm
	url := fmt.Sprintf("%s?ecosystem=%s", c.baseURL, ecosystem)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	
	// Jalankan request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status: %d", resp.StatusCode)
	}
	
	// Parse JSON
	var advisories []GitHubAdvisory
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&advisories)
	if err != nil {
		return nil, err
	}
	
	return advisories, nil
}

// SearchAdvisory mencari advisory berdasarkan nama paket
func (c *Client) SearchAdvisory(ecosystem, packageName string) (*GitHubAdvisory, error) {
	advisories, err := c.FetchAdvisories(ecosystem)
	if err != nil {
		return nil, err
	}
	
	// Cari yang match
	for i := range advisories {
		for _, v := range advisories[i].Vulnerabilities {
			if v.Package.Name == packageName {
				return &advisories[i], nil
			}
		}
	}
	
	return nil, nil // tidak ditemukan
}
