package pemindai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSVVuln represents a vulnerability from OSV.dev
type OSVVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Related  []string `json:"related"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// OSVClient queries OSV.dev for distro package vulnerabilities
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient creates a new OSV client
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// DetectDistroEcosystem maps /etc/os-release to OSV ecosystem name
func DetectDistroEcosystem() string {
	// Read /etc/os-release
	out := ""
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		out = string(data)
	}
	id := ""
	version := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	major := strings.Split(version, ".")[0]

	switch {
	case id == "rhel" || id == "redhat":
		// OSV does not support RHEL; use AlmaLinux data (same errata stream)
		return "AlmaLinux:" + major
	case id == "almalinux":
		return "AlmaLinux:" + major
	case id == "rocky" || strings.Contains(id, "rocky"):
		return "Rocky Linux:" + major
	case id == "ol" || id == "oraclelinux":
		return "Oracle Linux:" + major
	case id == "fedora":
		return "Fedora:" + major
	case id == "ubuntu":
		return "Ubuntu:" + version
	case id == "debian":
		return "Debian:" + major
	case id == "centos":
		return "CentOS Stream:" + major // fallback
	default:
		// RHEL-like default
		return "AlmaLinux:" + major
	}
}

// OSVQueryResponse for querybatch
type OSVQueryResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch queries OSV for multiple packages at once (up to 1000)
// Returns map[pkgname] -> list of advisory IDs (unfiltered by version)
func (c *OSVClient) QueryBatch(ecosystem string, pkgs []SystemPackage) (map[string][]string, error) {
	result := make(map[string][]string)
	if len(pkgs) == 0 {
		return result, nil
	}

	// Build queries (OSV limit: 1000 per batch)
	queries := make([]map[string]interface{}, 0, len(pkgs))
	seen := make(map[string]bool)
	for _, p := range pkgs {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		queries = append(queries, map[string]interface{}{
			"package": map[string]string{
				"name":      p.Name,
				"ecosystem": ecosystem,
			},
			// version omitted: OSV distro matching is name-based anyway;
			// we filter by version locally with rpmvercmp
		})
	}

	// Chunk into batches of 500
	batchSize := 500
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		chunk := queries[start:end]

		payload := map[string]interface{}{"queries": chunk}
		body, _ := json.Marshal(payload)

		req, err := http.NewRequest("POST", "https://api.osv.dev/v1/querybatch", bytes.NewReader(body))
		if err != nil {
			return result, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return result, err
		}
		defer resp.Body.Close()

		var qr OSVQueryResponse
		if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
			continue
		}

		for i, r := range qr.Results {
			if i >= len(chunk) {
				break
			}
			pkgName := chunk[i]["package"].(map[string]string)["name"]
			for _, v := range r.Vulns {
				result[pkgName] = append(result[pkgName], v.ID)
			}
		}
	}

	return result, nil
}

// GetVulnDetail fetches full advisory detail from OSV
func (c *OSVClient) GetVulnDetail(id string) (*OSVVuln, error) {
	req, err := http.NewRequest("GET", "https://api.osv.dev/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}

	var vuln OSVVuln
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// ExtractCVEs pulls CVE IDs from related field
func (v *OSVVuln) ExtractCVEs() []string {
	var cves []string
	seen := make(map[string]bool)
	for _, r := range v.Related {
		if strings.HasPrefix(r, "CVE-") && !seen[r] {
			cves = append(cves, r)
			seen[r] = true
		}
	}
	return cves
}

// GetFixedVersion returns fixed version for a package in this advisory
func (v *OSVVuln) GetFixedVersion(pkgName string) string {
	for _, a := range v.Affected {
		if a.Package.Name == pkgName {
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	return ""
}

// GetSeverity extracts severity word from summary ("Important: ...")
func (v *OSVVuln) GetSeverity() string {
	summary := v.Summary
	sev := strings.SplitN(summary, ":", 2)[0]
	sev = strings.TrimSpace(sev)
	switch strings.ToLower(sev) {
	case "critical":
		return "CRITICAL"
	case "important":
		return "HIGH"
	case "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// rpmvercmp compares two RPM version strings
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
// Implements the RPM version comparison algorithm
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}

	// Compare segment by segment (manual scan, no regex)

	for a != "" && b != "" {
		// Skip leading non-alphanumeric
		a = trimNonAlnum(a)
		b = trimNonAlnum(b)

		// Get next segment from each (manual scan, no regex needed)
		segA, restA := nextSegment(a)
		segB, restB := nextSegment(b)

		cmp := compareSegments(segA, segB)
		if cmp != 0 {
			return cmp
		}
		a = restA
		b = restB
	}

	// Whichever has more segments is greater (if equal so far)
	a = trimNonAlnum(a)
	b = trimNonAlnum(b)
	if a != "" && b == "" {
		return 1
	}
	if a == "" && b != "" {
		return -1
	}
	return 0
}

func trimNonAlnum(s string) string {
	for len(s) > 0 && !isAlnum(s[0]) {
		s = s[1:]
	}
	return s
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func nextSegment(s string) (seg, rest string) {
	if s == "" {
		return "", ""
	}
	// Segment continues until character type changes or non-alnum
	start := 0
	i := 0
	isDigit := isDigitByte(s[i])
	for i < len(s) && isAlnum(s[i]) && isDigitByte(s[i]) == isDigit {
		i++
	}
	if i == start {
		return "", s[1:]
	}
	return s[start:i], s[i:]
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

func compareSegments(a, b string) int {
	if a == "" && b == "" {
		return 0
	}
	// Numeric segments: numeric > alpha; higher number wins
	aNum := isNumeric(a)
	bNum := isNumeric(b)

	switch {
	case aNum && bNum:
		ai, _ := strconv.ParseInt(a, 10, 64)
		bi, _ := strconv.ParseInt(b, 10, 64)
		// Handle overflow via string compare for same length
		if len(a) > 18 || len(b) > 18 {
			if len(a) != len(b) {
				if len(a) > len(b) {
					return 1
				}
				return -1
			}
			return strings.Compare(a, b)
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
		return 0
	case aNum && !bNum:
		return 1 // numeric > alpha
	case !aNum && bNum:
		return -1
	default:
		return strings.Compare(a, b)
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigitByte(s[i]) {
			return false
		}
	}
	return true
}

// EVRToComparable strips epoch prefix "0:" from full EVR
func EVRToComparable(evr string) string {
	if idx := strings.Index(evr, ":"); idx >= 0 {
		return evr[idx+1:]
	}
	return evr
}

// IsVulnerable checks if installedVersion < fixedVersion (RPM semantics)
func IsVulnerable(installedVersion, fixedVersion string) bool {
	inst := EVRToComparable(installedVersion)
	fixed := EVRToComparable(fixedVersion)
	return rpmvercmp(inst, fixed) < 0
}

// FetchAdvisoryDetails fetches many advisory details concurrently
// Returns map[advisoryID] -> *OSVVuln (failed fetches are omitted)
func (c *OSVClient) FetchAdvisoryDetails(ids []string, maxConcurrency int) map[string]*OSVVuln {
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}

	result := make(map[string]*OSVVuln)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Dedup
	seen := make(map[string]bool)
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}

	// Worker pool
	sem := make(chan struct{}, maxConcurrency)
	for _, id := range unique {
		wg.Add(1)
		go func(advisoryID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vuln, err := c.GetVulnDetail(advisoryID)
			if err != nil || vuln == nil {
				return
			}
			mu.Lock()
			result[advisoryID] = vuln
			mu.Unlock()
		}(id)
	}
	wg.Wait()

	return result
}

// CollectAllAdvisoryIDs flattens advisory map into unique ID list
func CollectAllAdvisoryIDs(advisoryMap map[string][]string) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, list := range advisoryMap {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}
