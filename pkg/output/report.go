package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SecurityIssue mirrors pemindai.SecurityIssue for JSON export
type ReportIssue struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Description    string `json:"description,omitempty"`
	Recommendation string `json:"recommendation"`
	Port           int    `json:"port,omitempty"`
}

// ReportSysVuln represents a system package vulnerability
type ReportSysVuln struct {
	PkgName    string   `json:"package"`
	Installed  string   `json:"installed_version"`
	Fixed      string   `json:"fixed_version"`
	AdvisoryID string   `json:"advisory"`
	CVEs       []string `json:"cves"`
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
}

// FullReport is the complete scan report
type FullReport struct {
	ScanInfo     ScanMeta       `json:"scan_info"`
	Security     SecurityReport `json:"security"`
	ServerInfo   ServerMeta     `json:"server_info"`
	FolderScan   FolderReport   `json:"folder_scan"`
	SystemVulns  []ReportSysVuln `json:"system_vulnerabilities"`
	DockerImages int            `json:"docker_images_count"`
	WebPorts     []int          `json:"web_ports_open"`
	DurationSec  float64        `json:"duration_seconds"`
}

// ScanMeta describes the scan run
type ScanMeta struct {
	Tool      string `json:"tool"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Target    string `json:"target"`
}

// SecurityReport summarizes security scan results
type SecurityReport struct {
	TotalIssues int           `json:"total_issues"`
	Critical    int           `json:"critical"`
	High        int           `json:"high"`
	Medium      int           `json:"medium"`
	Low         int           `json:"low"`
	Issues      []ReportIssue `json:"issues"`
}

// ServerMeta holds server information
type ServerMeta struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
	Docker   string `json:"docker_version"`
}

// FolderReport summarizes folder scan
type FolderReport struct {
	Paths          []string `json:"paths"`
	TotalPackages  int      `json:"total_packages"`
	TotalVulns     int      `json:"total_vulnerabilities"`
}

// ExportJSON writes the report as JSON to a file
func ExportJSON(report *FullReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// severityColor for HTML badges
func sevColor(sev string) string {
	switch sev {
	case "CRITICAL":
		return "#c0392b"
	case "HIGH":
		return "#e67e22"
	case "MEDIUM":
		return "#f1c40f"
	case "LOW":
		return "#3498db"
	default:
		return "#95a5a6"
	}
}

// ExportHTML writes the report as a standalone HTML file
func ExportHTML(report *FullReport, path string) error {
	html := buildHTML(report)
	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

func buildHTML(r *FullReport) string {
	sec := r.Security

	html := `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>AMAN Security Report - ` + r.ServerInfo.Hostname + `</title>
<style>
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f4f6f8; color: #2c3e50; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
h1 { margin: 0 0 4px; }
.meta { color: #7f8c8d; font-size: 14px; margin-bottom: 24px; }
.cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.card { flex: 1; min-width: 140px; background: #fff; border-radius: 10px; padding: 18px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); text-align: center; }
.card .num { font-size: 32px; font-weight: 700; }
.card .lbl { font-size: 13px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; }
section { background: #fff; border-radius: 10px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
section h2 { margin-top: 0; font-size: 18px; border-bottom: 2px solid #eee; padding-bottom: 10px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; padding: 10px 8px; background: #fafbfc; border-bottom: 2px solid #eee; font-size: 12px; text-transform: uppercase; color: #7f8c8d; }
td { padding: 10px 8px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; color: #fff; font-size: 11px; font-weight: 700; }
.cve { font-family: monospace; font-size: 12px; background: #f0f3f6; padding: 2px 6px; border-radius: 4px; margin-right: 4px; display: inline-block; }
.ok { color: #27ae60; font-weight: 600; }
.footer { text-align: center; color: #95a5a6; font-size: 12px; margin: 30px 0 10px; }
.rec { color: #16a085; font-size: 13px; }
.num-critical { color: #c0392b; }
.num-high { color: #e67e22; }
.num-medium { color: #f39c12; }
.num-low { color: #3498db; }
.kv { display: grid; grid-template-columns: 160px 1fr; gap: 6px 16px; font-size: 14px; }
.kv .k { color: #7f8c8d; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ AMAN Security Report</h1>
<div class="meta">Generated: ` + r.ScanInfo.Timestamp + ` &nbsp;|&nbsp; Duration: ` + fmt.Sprintf("%.1f", r.DurationSec) + `s &nbsp;|&nbsp; AMAN v` + r.ScanInfo.Version + `</div>

<div class="cards">
<div class="card"><div class="num num-critical">` + fmt.Sprint(sec.Critical) + `</div><div class="lbl">Critical</div></div>
<div class="card"><div class="num num-high">` + fmt.Sprint(sec.High) + `</div><div class="lbl">High</div></div>
<div class="card"><div class="num num-medium">` + fmt.Sprint(sec.Medium) + `</div><div class="lbl">Medium</div></div>
<div class="card"><div class="num num-low">` + fmt.Sprint(sec.Low) + `</div><div class="lbl">Low</div></div>
<div class="card"><div class="num">` + fmt.Sprint(len(r.SystemVulns)) + `</div><div class="lbl">Package CVEs</div></div>
</div>

<section>
<h2>Server Information</h2>
<div class="kv">
<div class="k">Hostname</div><div>` + r.ServerInfo.Hostname + `</div>
<div class="k">OS</div><div>` + r.ServerInfo.OS + `</div>
<div class="k">Kernel</div><div>` + r.ServerInfo.Kernel + `</div>
<div class="k">Docker</div><div>` + r.ServerInfo.Docker + `</div>
<div class="k">Docker Images</div><div>` + fmt.Sprint(r.DockerImages) + `</div>
<div class="k">Open Web Ports</div><div>` + fmt.Sprint(r.WebPorts) + `</div>
</div>
</section>
`

	// Security issues table
	html += `<section><h2>Security Findings (` + fmt.Sprint(sec.TotalIssues) + `)</h2>`
	if len(sec.Issues) > 0 {
		html += `<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Recommendation</th></tr>`
		for _, iss := range sec.Issues {
			html += `<tr><td><span class="badge" style="background:` + sevColor(iss.Severity) + `">` + iss.Severity + `</span></td><td>` + iss.Category + `</td><td>` + iss.Title + `</td><td class="rec">` + iss.Recommendation + `</td></tr>`
		}
		html += `</table>`
	} else {
		html += `<p class="ok">✅ Tidak ada masalah keamanan ditemukan.</p>`
	}
	html += `</section>`

	// System CVEs table
	html += `<section><h2>System Package Vulnerabilities (` + fmt.Sprint(len(r.SystemVulns)) + `)</h2>`
	if len(r.SystemVulns) > 0 {
		html += `<table><tr><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed</th><th>CVE</th><th>Advisory</th></tr>`
		for _, v := range r.SystemVulns {
			cves := ""
			for i, c := range v.CVEs {
				if i >= 3 {
					cves += `<span class="cve">+` + fmt.Sprint(len(v.CVEs)-3) + ` more</span>`
					break
				}
				cves += `<span class="cve">` + c + `</span>`
			}
			if len(v.CVEs) == 0 {
				cves = "-"
			}
			html += `<tr><td><span class="badge" style="background:` + sevColor(v.Severity) + `">` + v.Severity + `</span></td><td><strong>` + v.PkgName + `</strong></td><td>` + v.Installed + `</td><td>` + v.Fixed + `</td><td>` + cves + `</td><td>` + v.AdvisoryID + `</td></tr>`
		}
		html += `</table>`
	} else {
		html += `<p class="ok">✅ Tidak ada kerentanan paket sistem.</p>`
	}
	html += `</section>`

	html += `<div class="footer">Generated by AMAN v` + r.ScanInfo.Version + ` — ` + time.Now().Format("2006-01-02 15:04 MST") + `</div>
</div>
</body>
</html>`

	return html
}
