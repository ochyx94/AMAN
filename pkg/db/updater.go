package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CVEData adalah struktur dari NVD API
type CVEData struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID             string `json:"id"`
			Descriptions   []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CVSSData struct {
						BaseScore     float64 `json:"baseScore"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Updater untuk auto-update database
type Updater struct {
	httpClient *http.Client
	baseURL    string
}

// NewUpdater membuat updater baru
func NewUpdater() *Updater {
	return &Updater{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// UpdateFromNVD mengupdate database dari NVD
func (u *Updater) UpdateFromNVD(db *sql.DB, ecosystem string) error {
	// Mapping ecosystem ke keyword
	keyword := getEcosystemKeyword(ecosystem)
	
	url := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=50", u.baseURL, keyword)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	// Set headers untuk NVD API
	req.Header.Set("Accept", "application/json")
	
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	var cveData CVEData
	err = json.Unmarshal(body, &cveData)
	if err != nil {
		return err
	}
	
	// Insert CVE ke database
	for _, vuln := range cveData.Vulnerabilities {
		cve := vuln.CVE
		
		// Ambil deskripsi
		deskripsi := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				deskripsi = d.Value
				break
			}
		}
		
		// Ambil severity
		severity := "MEDIUM"
		if len(cve.Metrics.CvssMetricV31) > 0 {
			severity = cve.Metrics.CvssMetricV31[0].CVSSData.BaseSeverity
		}
		
		// Ambil referensi
		referensi := ""
		if len(cve.References) > 0 {
			referensi = cve.References[0].URL
		}
		
		// Insert ke database
		input := InsertKelemahanInput{
			ID:         cve.ID,
			Judul:      getFirstLine(deskripsi, 100),
			Penjelasan: deskripsi,
			Tingkat:    severity,
			Paket:      keyword,
			Pattern:    keyword,
			VersiAman:  "Unknown",
			Referensi:   referensi,
		}
		
		err = InsertKelemahan(db, input)
		if err != nil {
			continue // Skip jika sudah ada
		}
	}
	
	return nil
}

// UpdateFromGitHub mengupdate dari GitHub Advisories
func (u *Updater) UpdateFromGitHub(db *sql.DB, ecosystem string) error {
	// Map ecosystem name ke GitHub Advisories ecosystem
	// GitHub API: npm, pip, go, rubygems, rust, maven, nuget (cargo = rust)
	apiEcosystem := ecosystem
	if ecosystem == "cargo" {
		apiEcosystem = "rust"
	}
	
	url := fmt.Sprintf("https://api.github.com/advisories?ecosystem=%s", apiEcosystem)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned status: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	// Parse sebagai array
	var advisories []map[string]interface{}
	err = json.Unmarshal(body, &advisories)
	if err != nil {
		return err
	}
	
	for _, adv := range advisories {
		// Extract data dari advisory
		ghsaID, _ := adv["ghsa_id"].(string)
		summary, _ := adv["summary"].(string)
		
		// Get severity
		severity := "MEDIUM"
		if s, ok := adv["severity"].(string); ok {
			severity = s
		}
		
		// Get vulnerable packages
		if vulns, ok := adv["vulnerabilities"].([]interface{}); ok {
			for _, v := range vulns {
				if vm, ok := v.(map[string]interface{}); ok {
					if pkg, ok := vm["package"].(map[string]interface{}); ok {
						pkgName, _ := pkg["name"].(string)
						
						input := InsertKelemahanInput{
							ID:         ghsaID,
							Judul:      getFirstLine(summary, 100),
							Penjelasan: summary,
							Tingkat:    severity,
							Paket:      pkgName,
							Pattern:    pkgName,
							VersiAman:  "Unknown",
							Referensi:   "https://github.com/advisories/" + ghsaID,
						}
						
						InsertKelemahan(db, input)
					}
				}
			}
		}
	}
	
	return nil
}

func getEcosystemKeyword(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "nodejs"
	case "pip":
		return "python"
	case "go":
		return "golang"
	case "rubygems":
		return "ruby"
	case "cargo":
		return "rust"
	case "maven":
		return "java"
	case "nuget":
		return "dotnet"
	default:
		return ecosystem
	}
}

func getFirstLine(s string, maxLen int) string {
	if len(s) == 0 {
		return ""
	}
	// Ambil baris pertama
	for i, c := range s {
		if c == '\n' {
			s = s[:i]
			break
		}
	}
	// Potong jika terlalu panjang
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
