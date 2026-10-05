package pemindai

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebSecurityReport holds the W1 results: headers, cookies, redirects, TLS
type WebSecurityReport struct {
	URL           string              `json:"url"`
	FinalURL      string              `json:"final_url"`
	RedirectChain []string            `json:"redirect_chain"`
	Headers       map[string]string   `json:"headers"`
	HeaderIssues  []SecurityIssue     `json:"header_issues"`
	Cookies       []WebCookieInfo     `json:"cookies"`
	TLS           *WebTLSInfo         `json:"tls,omitempty"`
}

// WebCookieInfo describes one cookie's security posture
type WebCookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	Domain   string `json:"domain"`
	Issues   []string `json:"issues,omitempty"`
}

// WebTLSInfo summarizes the TLS certificate
type WebTLSInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	DaysLeft   int    `json:"days_left"`
	Secure     bool   `json:"secure"`
	TLSVersion string `json:"tls_version"`
	Issues     []string `json:"issues,omitempty"`
}

// Required security headers with recommendations
var requiredHeaders = []struct {
	Header string
	Rec    string
	Sev    string
}{
	{"Strict-Transport-Security", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "HIGH"},
	{"Content-Security-Policy", "Add Content-Security-Policy header", "MEDIUM"},
	{"X-Content-Type-Options", "Add: X-Content-Type-Options: nosniff", "MEDIUM"},
	{"X-Frame-Options", "Add: X-Frame-Options: DENY or SAMEORIGIN", "HIGH"},
	{"Referrer-Policy", "Add: Referrer-Policy: strict-origin-when-cross-origin", "MEDIUM"},
	{"Permissions-Policy", "Add Permissions-Policy to disable unnecessary features", "LOW"},
}

// ScanWebSecurity performs the W1 security audit of a website
// (headers, cookies, redirect chain, TLS)
func ScanWebSecurity(target string) (*WebSecurityReport, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	report := &WebSecurityReport{
		URL:           target,
		Headers:       map[string]string{},
		RedirectChain: []string{},
		HeaderIssues:  []SecurityIssue{},
		Cookies:       []WebCookieInfo{},
	}

	// Client that follows redirects but records the chain.
	// InsecureSkipVerify=true here: TLS validity is checked separately in
	// analyzeTLS() which REPORTS cert problems instead of failing outright.
	chain := []string{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			for _, v := range via {
				chain = append(chain, v.URL.String())
			}
			if len(via) > 10 {
				return fmt.Errorf("terlalu banyak redirect (>10)")
			}
			return nil
		},
	}

	// Use GET directly: many servers hang/refuse HEAD (e.g. neverssl.com)
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("URL tidak valid: %v", err)
	}
	req.Header.Set("User-Agent", "AMAN-Security-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gagal akses %s: %v", target, err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) // drain small part
	resp.Body.Close()
	finalURL := resp.Request.URL.String()

	report.FinalURL = finalURL
	report.RedirectChain = chain

	// Record headers (lowercase keys for consistency)
	for k, v := range resp.Header {
		report.Headers[strings.ToLower(k)] = strings.Join(v, "; ")
	}

	// Check required headers
	scheme := "https"
	if u, err := url.Parse(target); err == nil {
		scheme = u.Scheme
	}
	for _, rh := range requiredHeaders {
		if _, ok := report.Headers[strings.ToLower(rh.Header)]; !ok {
			// HSTS only meaningful on HTTPS
			if rh.Header == "Strict-Transport-Security" && scheme != "https" {
				continue
			}
			report.HeaderIssues = append(report.HeaderIssues, SecurityIssue{
				Severity:       rh.Sev,
				Category:       "Web Headers",
				Title:          fmt.Sprintf("%s header missing on %s", rh.Header, target),
				Recommendation: rh.Rec,
			})
		}
	}

	// HSTS strength check
	if hsts, ok := report.Headers["strict-transport-security"]; ok {
		if !strings.Contains(hsts, "max-age=") {
			report.HeaderIssues = append(report.HeaderIssues, SecurityIssue{
				Severity:       "LOW",
				Category:       "Web Headers",
				Title:          "HSTS header without max-age",
				Recommendation: "Set HSTS max-age to at least 31536000",
			})
		}
	}

	// Server version disclosure
	if server, ok := report.Headers["server"]; ok {
		if containsVersion(server) {
			report.HeaderIssues = append(report.HeaderIssues, SecurityIssue{
				Severity:       "LOW",
				Category:       "Web Headers",
				Title:          fmt.Sprintf("Server header discloses version: %s", server),
				Recommendation: "Hide server version (server_tokens off in nginx, ServerTokens Prod in Apache)",
			})
		}
	}
	if powered, ok := report.Headers["x-powered-by"]; ok {
		report.HeaderIssues = append(report.HeaderIssues, SecurityIssue{
			Severity:       "LOW",
			Category:       "Web Headers",
			Title:          fmt.Sprintf("X-Powered-By discloses technology: %s", powered),
			Recommendation: "Remove X-Powered-By header (exposes tech stack)",
		})
	}

	// Cookies analysis
	for _, ck := range resp.Cookies() {
		info := WebCookieInfo{
			Name:   ck.Name,
			Secure: ck.Secure,
			Domain: ck.Domain,
		}
		if ck.HttpOnly {
			info.HttpOnly = true
		}
		switch ck.SameSite {
		case http.SameSiteLaxMode:
			info.SameSite = "lax"
		case http.SameSiteStrictMode:
			info.SameSite = "strict"
		case http.SameSiteNoneMode:
			info.SameSite = "none"
		}

		var issues []string
		if !ck.Secure {
			issues = append(issues, "missing Secure flag")
		}
		if !ck.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}
		if info.SameSite == "" {
			issues = append(issues, "missing SameSite attribute")
		}
		info.Issues = issues
		report.Cookies = append(report.Cookies, info)
	}

	// TLS analysis (only for HTTPS)
	if strings.HasPrefix(finalURL, "https://") {
		report.TLS = analyzeTLS(finalURL)
	}

	return report, nil
}

// analyzeTLS inspects the certificate of an HTTPS URL
func analyzeTLS(targetURL string) *WebTLSInfo {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}

	tlsInfo := &WebTLSInfo{Issues: []string{}}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: false, ServerName: host},
	)
	if err != nil {
		// Try InsecureSkipVerify to at least get cert info
		conn2, err2 := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp",
			host+":443",
			&tls.Config{InsecureSkipVerify: true, ServerName: host},
		)
		if err2 != nil {
			tlsInfo.Issues = append(tlsInfo.Issues, "TLS handshake gagal: "+err.Error())
			return tlsInfo
		}
		defer conn2.Close()
		tlsInfo.Issues = append(tlsInfo.Issues, "sertifikat tidak valid: "+err.Error())
		tlsInfo.Secure = false
		state := conn2.ConnectionState()
		tlsInfo.TLSVersion = tlsVersionString(state.Version)
		if len(state.PeerCertificates) > 0 {
			fillCertInfo(tlsInfo, state.PeerCertificates[0])
		}
		return tlsInfo
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsInfo.Secure = true
	tlsInfo.TLSVersion = tlsVersionString(state.Version)
	if len(state.PeerCertificates) > 0 {
		fillCertInfo(tlsInfo, state.PeerCertificates[0])
	}

	// Check expiry
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		tlsInfo.DaysLeft = days
		if days < 0 {
			tlsInfo.Issues = append(tlsInfo.Issues, "SERTIFIKAT KADALUWARSA!")
			tlsInfo.Secure = false
		} else if days < 14 {
			tlsInfo.Issues = append(tlsInfo.Issues, fmt.Sprintf("sertifikat kedaluwarsa dalam %d hari", days))
		}
	}

	return tlsInfo
}

func fillCertInfo(tlsInfo *WebTLSInfo, cert *x509.Certificate) {
	tlsInfo.Subject = cert.Subject.CommonName
	if len(cert.Issuer.Organization) > 0 {
		tlsInfo.Issuer = cert.Issuer.Organization[0]
	} else if len(cert.Issuer.CommonName) > 0 {
		tlsInfo.Issuer = cert.Issuer.CommonName
	}
	tlsInfo.NotBefore = cert.NotBefore.Format("2006-01-02")
	tlsInfo.NotAfter = cert.NotAfter.Format("2006-01-02")
	tlsInfo.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
}

// containsVersion checks if a server string looks like it has a version number
func containsVersion(s string) bool {
	for i, ch := range s {
		if ch >= '0' && ch <= '9' && i > 0 {
			// found digit after first char (e.g. "nginx/1.24.0")
			return true
		}
	}
	return false
}

// tlsVersionString converts TLS version constant to readable string
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%x)", v)
	}
}
