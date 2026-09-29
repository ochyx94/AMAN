package pemindai

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLCheck hasil pemeriksaan SSL/TLS
type SSLCheck struct {
	URL            string
	Valid          bool
	Issuer         string
	ExpirationDate string
	DaysRemaining  int
	Protocol       string
	Errors         []string
}

// CheckSSL melakukan pemeriksaan SSL/TLS pada URL
func CheckSSL(hostname string, port string) (*SSLCheck, error) {
	result := &SSLCheck{
		URL:     hostname,
		Valid:   true,
		Errors:  []string{},
	}

	if port == "" {
		port = "443"
	}

	// Connect ke host
	address := net.JoinHostPort(hostname, port)
	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
	})

	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}
	defer conn.Close()

	// Ambil state
	state := conn.ConnectionState()

	// Ambil certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		// Issuer
		if len(cert.Issuer.Organization) > 0 {
			result.Issuer = cert.Issuer.Organization[0]
		}

		// Expiration
		result.ExpirationDate = cert.NotAfter.Format("2006-01-02")
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		result.DaysRemaining = daysLeft

		// Check expiration
		if daysLeft < 0 {
			result.Valid = false
			result.Errors = append(result.Errors, "Certificate expired")
		} else if daysLeft < 30 {
			result.Errors = append(result.Errors, fmt.Sprintf("Certificate expires in %d days", daysLeft))
		}
	}

	// Ambil TLS version
	switch state.Version {
	case tls.VersionTLS10:
		result.Protocol = "TLS 1.0"
		result.Errors = append(result.Errors, "TLS 1.0 is deprecated")
	case tls.VersionTLS11:
		result.Protocol = "TLS 1.1"
		result.Errors = append(result.Errors, "TLS 1.1 is deprecated")
	case tls.VersionTLS12:
		result.Protocol = "TLS 1.2"
	case tls.VersionTLS13:
		result.Protocol = "TLS 1.3"
	default:
		result.Protocol = "Unknown"
		result.Valid = false
		result.Errors = append(result.Errors, "Unknown TLS version")
	}

	return result, nil
}

// CheckSecurityHeaders cek security headers pada response
func CheckSecurityHeaders(headers map[string]string) map[string]string {
	result := map[string]string{}

	requiredHeaders := map[string]string{
		"strict-transport-security": "HSTS - Enforces HTTPS",
		"content-security-policy":   "CSP - Prevents XSS/injection",
		"x-content-type-options":  "Prevents MIME sniffing",
		"x-frame-options":          "Prevents clickjacking",
		"x-xss-protection":         "XSS filter (legacy)",
		"referrer-policy":          "Controls referrer info",
	}

	missingHeaders := []string{}
	for header, desc := range requiredHeaders {
		if _, exists := headers[strings.ToLower(header)]; !exists {
			missingHeaders = append(missingHeaders, fmt.Sprintf("%s (%s)", header, desc))
		}
	}

	if len(missingHeaders) > 0 {
		result["missing"] = strings.Join(missingHeaders, ", ")
	}

	return result
}
