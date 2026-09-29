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
	DaysRemaining int
	Protocols      []string
	CipherSuites  []string
	Errors         []string
}

// CheckSSL melakukan pemeriksaan SSL/TLS pada URL
func CheckSSL(hostname string, port string) (*SSLCheck, error) {
	result := &SSLCheck{
		URL:       hostname,
		Valid:     true,
		Protocols: []string{},
		CipherSuites: []string{},
		Errors:    []string{},
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
		return result, nil // Tetap return, tapi valid=false
	}
	defer conn.Close()

	// Ambil state
	state := conn.ConnectionState()

	// Ambil certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		
		// Issuer
		result.Issuer = cert.Issuer.Organization[0]
		
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
		result.Protocols = append(result.Protocols, "TLS 1.0")
		result.Errors = append(result.Errors, "TLS 1.0 is deprecated")
	case tls.VersionTLS11:
		result.Protocols = append(result.Protocols, "TLS 1.1")
		result.Errors = append(result.Errors, "TLS 1.1 is deprecated")
	case tls.VersionTLS12:
		result.Protocols = append(result.Protocols, "TLS 1.2")
	case tls.VersionTLS13:
		result.Protocols = append(result.Protocols, "TLS 1.3")
	default:
		result.Protocols = append(result.Protocols, "Unknown")
		result.Valid = false
		result.Errors = append(result.Errors, "Unknown TLS version")
	}

	// Check cipher suites
	for _, cs := range state.CipherSuites {
		result.CipherSuites = append(result.CipherSuites, cipherSuiteName(cs))
	}

	// Weak cipher check
	weakCiphers := map[string]bool{
		"TLS_RSA_WITH_RC4_128_SHA":                true,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           true,
		"TLS_RSA_WITH_AES_128_CBC_SHA":             true,
		"TLS_RSA_WITH_AES_256_CBC_SHA":             true,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":          false, // OK
		"TLS_RSA_WITH_AES_256_GCM_SHA384":          false, // OK
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":           true,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     true,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":       false, // OK (PFS)
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":       false, // OK (PFS)
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":    false, // OK
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":    false, // OK
	}

	for _, cs := range result.CipherSuites {
		if weakCiphers[cs] {
			result.Errors = append(result.Errors, fmt.Sprintf("Weak cipher: %s", cs))
		}
	}

	return result, nil
}

// cipherSuiteName get name dari cipher suite ID
func cipherSuiteName(id uint16) string {
	cipherSuites := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:             "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:             "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:          "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:          "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:           "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:         "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDSA_WITH_AES_128_CBC_SHA:           "TLS_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDSA_WITH_AES_256_CBC_SHA:           "TLS_ECDSA_WITH_AES_256_CBC_SHA",
	}

	if name, ok := cipherSuites[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}

// CheckSecurityHeaders cek security headers pada response
func CheckSecurityHeaders(headers map[string]string) map[string]string {
	result := map[string]string{}
	
	requiredHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS - Enforces HTTPS",
		"Content-Security-Policy":    "CSP - Prevents XSS/injection",
		"X-Content-Type-Options":     "Prevents MIME sniffing",
		"X-Frame-Options":           "Prevents clickjacking",
		"X-XSS-Protection":          "XSS filter (legacy)",
		"Referrer-Policy":           "Controls referrer info",
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
