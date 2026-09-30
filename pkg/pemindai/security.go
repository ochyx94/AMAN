package pemindai

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SecurityIssue represents a security finding
type SecurityIssue struct {
	Severity   string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Category   string `json:"category"`
	Title      string `json:"title"`
	Description string `json:"description"`
	Service    string `json:"service,omitempty"`
	Port       int    `json:"port,omitempty"`
	Recommendation string `json:"recommendation"`
}

// SecurityScanResult result of security scan
type SecurityScanResult struct {
	Timestamp    string           `json:"timestamp"`
	TotalIssues  int             `json:"total_issues"`
	Critical     int             `json:"critical"`
	High         int             `json:"high"`
	Medium       int             `json:"medium"`
	Low          int             `json:"low"`
	Issues       []SecurityIssue `json:"issues"`
}

// SecurityScanner scanner untuk security issues
type SecurityScanner struct{}

// NewSecurityScanner buat scanner baru
func NewSecurityScanner() *SecurityScanner {
	return &SecurityScanner{}
}

// Run jalankan security scan
func (s *SecurityScanner) Run() *SecurityScanResult {
	result := &SecurityScanResult{
		Timestamp: time.Now().Format(time.RFC3339),
		Issues:    []SecurityIssue{},
	}

	// === SYSTEM SECURITY ===
	// 1. Check running services
	s.checkRunningServices(result)

	// 2. Check kernel version (outdated kernel = vulnerability)
	s.checkKernelVersion(result)

	// 3. Check outdated system packages
	s.checkOutdatedPackages(result)

	// 4. Check failed login attempts
	s.checkFailedLogins(result)

	// 5. Check user accounts (weak passwords, empty passwords)
	s.checkUserAccounts(result)

	// === FILE SYSTEM SECURITY ===
	// 6. Check world-writable files
	s.checkWorldWritableFiles(result)

	// 7. Check SUID binaries
	s.checkSUIDBinaries(result)

	// === NETWORK SECURITY ===
	// 8. Check open ports
	s.checkOpenPorts(result)

	// 9. Check SSL/TLS certificates
	s.checkSSLCertificates(result)

	// 10. Check weak SSL ciphers
	s.checkWeakSSLCiphers(result)

	// 11. Check firewall status
	s.checkFirewallStatus(result)

	// 12. Check suspicious processes
	s.checkSuspiciousProcesses(result)

	// === WEB SECURITY ===
	// 13. Check security headers on web services
	s.checkSecurityHeaders(result)

	// 14. Check exposed services (SSH, etc)
	s.checkExposedServices(result)

	// 15. Check DNS records (SPF, DKIM, DMARC)
	s.checkDNSRecords(result)

	// 16. Check Cookie Security
	s.checkCookieSecurity(result)

	// === DOCKER/CONTAINER SECURITY ===
	// 17. Check Docker security
	s.checkDockerSecurity(result)

	// === DATABASE SECURITY ===
	// 18. Check database exposure
	s.checkDatabaseExposure(result)

	// === BACKUP & TIME ===
	// 19. Check for exposed sensitive files (.git, .env, etc)
	s.checkExposedFiles(result)

	// 20. Check backup status
	// s.checkBackupStatus(result)  // Tahap 2

	// 21. Check NTP/time sync
	// s.checkTimeSync(result)  // Tahap 2

	// Count issues by severity
	for _, issue := range result.Issues {
		switch issue.Severity {
		case "CRITICAL":
			result.Critical++
		case "HIGH":
			result.High++
		case "MEDIUM":
			result.Medium++
		case "LOW":
			result.Low++
		}
	}
	result.TotalIssues = len(result.Issues)

	return result
}

func (s *SecurityScanner) checkRunningServices(result *SecurityScanResult) {
	// Check systemctl services
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		// Parse service line
		if strings.Contains(line, "loaded active running") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				service := parts[0]
				
				// Check dangerous services
				switch service {
				case "telnet", "ftpd", "rsh", "rlogin":
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "CRITICAL",
						Category:      "Insecure Service",
						Title:         "Insecure service running: " + service,
						Description:   "Service uses plaintext protocol",
						Service:       service,
						Recommendation: "Disable and use SSH/SFTP instead",
					})
				case "docker":
					// Check docker socket exposure
					if s.isDockerSocketExposed() {
						result.Issues = append(result.Issues, SecurityIssue{
							Severity:      "CRITICAL",
							Category:      "Container Security",
							Title:         "Docker socket exposed",
							Description:   "Docker socket can be accessed, allowing container escape",
							Service:       "docker",
							Recommendation: "Remove docker group from users or use TLS for docker API",
						})
					}
				}
			}
		}
	}
}

func (s *SecurityScanner) isDockerSocketExposed() bool {
	// Check if docker socket has inappropriate permissions
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		// Check socket permissions
		cmd := exec.Command("ls", "-la", "/var/run/docker.sock")
		output, _ := cmd.Output()
		if strings.Contains(string(output), "srw-rw----") || strings.Contains(string(output), "srw-rw-rw-") {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) checkOpenPorts(result *SecurityScanResult) {
	// Get listening ports using ss
	cmd := exec.Command("ss", "-tulpn")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-tulpn")
		output, err = cmd.Output()
		if err != nil {
			return
		}
	}

	dangerousPorts := map[int]string{
		21:    "FTP - plaintext protocol",
		23:    "Telnet - plaintext protocol",
		69:    "TFTP - insecure",
		135:   "Windows RPC",
		139:   "NetBIOS",
		445:   "SMB - vulnerable to exploits",
		512:   "rexec - plaintext",
		513:   "rlogin - plaintext",
		514:   "rsh - plaintext",
		515:   "LPD printer",
		1080:  "SOCKS proxy",
		1433:  "MSSQL - database",
		1521:  "Oracle DB",
		2049:  "NFS - can expose files",
		3306:  "MySQL - should not be public",
		3389:  "RDP - vulnerable to exploits",
		5432:  "PostgreSQL - should not be public",
		5900:  "VNC - weak encryption",
		5985:  "WinRM HTTP - management",
		6379:  "Redis - no auth by default",
		8080:  "HTTP proxy/common",
		8443:  "HTTPS alt",
		9200:  "Elasticsearch - no auth",
		27017: "MongoDB - no auth",
		11211: "Memcached - DDoS vector",
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse port from line
		for port, desc := range dangerousPorts {
			portStr := strconv.Itoa(port)
			if strings.Contains(line, ":"+portStr) || strings.Contains(line, ":"+portStr+" ") {
				// Check if it's listening on all interfaces
				if strings.Contains(line, "0.0.0.0:") || strings.Contains(line, "[::]:") || strings.Contains(line, "*:") {
					severity := "HIGH"
					if port == 23 || port == 512 || port == 513 || port == 514 {
						severity = "CRITICAL"
					}
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      severity,
						Category:      "Open Port",
						Title:         fmt.Sprintf("Dangerous port %d open on all interfaces", port),
						Description:   desc,
						Port:          port,
						Recommendation: fmt.Sprintf("Close port %d or restrict to localhost", port),
					})
				}
			}
		}
	}
}

func (s *SecurityScanner) checkSSLCertificates(result *SecurityScanResult) {
	// Check SSL on common ports
	ports := []int{443, 8443, 993, 995, 465, 587}
	hosts := []string{"localhost", "127.0.0.1"}
	
	// Also check common internal hosts
	internalHosts := s.getInternalHosts()
	hosts = append(hosts, internalHosts...)

	for _, host := range hosts {
		for _, port := range ports {
			cert := s.checkSSLCert(host, strconv.Itoa(port))
			if cert != nil {
				if cert.Expired {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "HIGH",
						Category:      "SSL/TLS",
						Title:         fmt.Sprintf("SSL certificate expired on %s:%d", host, port),
						Description:   fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02")),
						Port:          port,
						Recommendation: "Renew SSL certificate",
					})
				} else if cert.ExpiringSoon {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "MEDIUM",
						Category:      "SSL/TLS",
						Title:         fmt.Sprintf("SSL certificate expiring soon on %s:%d", host, port),
						Description:   fmt.Sprintf("Expires in %d days", cert.DaysUntilExpiry),
						Port:          port,
						Recommendation: "Plan certificate renewal",
					})
				}
				if cert.Version < 1.2 {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "MEDIUM",
						Category:      "SSL/TLS",
						Title:         fmt.Sprintf("Outdated TLS version on %s:%d", host, port),
						Description:   fmt.Sprintf("Using TLS %.1f", float64(cert.Version)/256.0),
						Port:          port,
						Recommendation: "Upgrade to TLS 1.2 or 1.3",
					})
				}
			}
		}
	}
}

type SSLCertInfo struct {
	Expired        bool
	ExpiringSoon  bool
	DaysUntilExpiry int
	NotAfter      time.Time
	Version       float64
}

func (s *SecurityScanner) checkSSLCert(host, port string) *SSLCertInfo {
	address := net.JoinHostPort(host, port)
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	return &SSLCertInfo{
		Expired:         time.Now().After(cert.NotAfter),
		ExpiringSoon:    daysUntilExpiry < 30,
		DaysUntilExpiry: daysUntilExpiry,
		NotAfter:       cert.NotAfter,
		Version:        float64(state.Version),
	}
}

func (s *SecurityScanner) getInternalHosts() []string {
	// Get hosts from /etc/hosts
	var hosts []string
	
	file, err := os.Open("/etc/hosts")
	if err != nil {
		return hosts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			// Only IPv4
			if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, ip); matched {
				if ip != "127.0.0.1" && ip != "0.0.0.0" {
					hosts = append(hosts, ip)
				}
			}
		}
	}
	return hosts
}

func (s *SecurityScanner) checkSecurityHeaders(result *SecurityScanResult) {
	// Check security headers on localhost - prioritize AMAN service port 8080
	urls := []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://localhost:80",
		"http://localhost:443",
	}

	for _, url := range urls {
		headers := s.fetchSecurityHeaders(url)
		if len(headers) > 0 {
			// Found a responding web service, check headers
			s.checkHeader(result, headers, "strict-transport-security", "HSTS", "HIGH",
				"HSTS header missing - Traffic not enforced HTTPS",
				"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")

			s.checkHeader(result, headers, "content-security-policy", "CSP", "MEDIUM",
				"CSP header missing - XSS/injection attacks possible",
				"Add Content-Security-Policy header")

			s.checkHeader(result, headers, "x-content-type-options", "X-Content-Type-Options", "MEDIUM",
				"MIME sniffing enabled - May allow XSS",
				"Add: X-Content-Type-Options: nosniff")

			s.checkHeader(result, headers, "x-frame-options", "X-Frame-Options", "HIGH",
				"Clickjacking attacks possible - No frame protection",
				"Add: X-Frame-Options: DENY or SAMEORIGIN")

			s.checkHeader(result, headers, "x-xss-protection", "X-XSS-Protection", "LOW",
				"Legacy XSS filter not enabled",
				"Add: X-XSS-Protection: 1; mode=block")

			s.checkHeader(result, headers, "referrer-policy", "Referrer-Policy", "MEDIUM",
				"Referrer information may leak",
				"Add: Referrer-Policy: strict-origin-when-cross-origin")

			s.checkHeader(result, headers, "permissions-policy", "Permissions-Policy", "LOW",
				"Browser features not restricted",
				"Add Permissions-Policy to disable unnecessary features")

			break // Only check first responding service
		}
	}
}

func (s *SecurityScanner) fetchSecurityHeaders(url string) map[string]string {
	headers := make(map[string]string)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Head(url)
	if err != nil {
		// Try GET if HEAD fails
		resp, err = client.Get(url)
		if err != nil {
			return headers
		}
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}

	return headers
}

func (s *SecurityScanner) checkHeader(result *SecurityScanResult, headers map[string]string, headerKey, headerName, severity, description, recommendation string) {
	if _, exists := headers[headerKey]; !exists {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      severity,
			Category:      "Security Headers",
			Title:         fmt.Sprintf("%s header missing on web service", headerName),
			Description:   description,
			Recommendation: recommendation,
		})
	}
}

func (s *SecurityScanner) checkExposedServices(result *SecurityScanResult) {
	// Check if SSH is exposed to internet
	if s.isPortOpen("0.0.0.0", 22) {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "HIGH",
			Category:      "Remote Access",
			Title:         "SSH port 22 open on all interfaces",
			Description:   "SSH accessible from internet - brute force target",
			Port:          22,
			Recommendation: "Use key-based auth, fail2ban, or restrict via firewall",
		})
	}

	// Check for password authentication
	if s.hasPasswordAuth() {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "HIGH",
			Category:      "Authentication",
			Title:         "Password authentication enabled for SSH",
			Description:   "SSH allows password authentication - vulnerable to brute force",
			Recommendation: "Disable password auth and use SSH keys",
		})
	}
}

func (s *SecurityScanner) checkDNSRecords(result *SecurityScanResult) {
	// Get local hostname and domain
	hostname, _ := os.Hostname()

	// Check if this server has domain configured
	// For localhost, check basic DNS resolution
	if hostname == "localhost" || strings.HasPrefix(hostname, "localhost") {
		// Check if /etc/resolv.conf has nameservers
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			if strings.Contains(string(data), "nameserver") {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "INFO",
					Category:      "DNS",
					Title:         "DNS resolver configured",
					Description:   "This server has DNS nameservers configured",
					Recommendation: "DNS is configured for name resolution",
				})
			}
		}
		return
	}

	// For servers with hostnames, we would typically check:
	// - SPF record: TXT record for domain
	// - DKIM record: TXT/CNAME record
	// - DMARC record: TXT record _dmarc.domain
	// Since we can't easily determine the domain from hostname alone,
	// we'll provide general guidance

	// Check for DNSSEC support hint (check if /etc/named.conf exists)
	if _, err := os.Stat("/etc/named.conf"); err == nil {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "INFO",
			Category:      "DNS",
			Title:         "DNS server (BIND) detected",
			Description:   "This server appears to run a DNS server (BIND)",
			Recommendation: "Ensure DNSSEC is enabled and properly configured",
		})
	}
}

func (s *SecurityScanner) checkCookieSecurity(result *SecurityScanResult) {
	// Check cookie security on web services
	urls := []string{
		"http://localhost:8080",
		"http://localhost:80",
	}

	for _, url := range urls {
		cookies := s.fetchCookies(url)
		if len(cookies) > 0 {
			// Check for session cookies
			for _, cookie := range cookies {
				// Check if Secure flag is missing
				if !cookie.Secure {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "MEDIUM",
						Category:      "Cookie Security",
						Title:         fmt.Sprintf("Cookie '%s' missing Secure flag", cookie.Name),
						Description:   "Cookie can be transmitted over HTTP - interception possible",
						Recommendation: "Add Secure flag to cookie to ensure HTTPS-only transmission",
					})
				}

				// Check if HttpOnly flag is missing
				if !cookie.HttpOnly {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "MEDIUM",
						Category:      "Cookie Security",
						Title:         fmt.Sprintf("Cookie '%s' missing HttpOnly flag", cookie.Name),
						Description:   "Cookie accessible via JavaScript - XSS risk",
						Recommendation: "Add HttpOnly flag to prevent JavaScript access",
					})
				}

				// Check if SameSite is not set
				if cookie.SameSite == "none" || cookie.SameSite == "" {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      "LOW",
						Category:      "Cookie Security",
						Title:         fmt.Sprintf("Cookie '%s' missing SameSite attribute", cookie.Name),
						Description:   "Cookie may be sent on cross-site requests - CSRF risk",
						Recommendation: "Add SameSite=Strict or SameSite=Lax attribute",
					})
				}
			}
			break // Only check first responding service
		}
	}
}

type cookieInfo struct {
	Name     string
	Secure   bool
	HttpOnly bool
	SameSite string
}

func (s *SecurityScanner) fetchCookies(url string) []cookieInfo {
	var cookies []cookieInfo

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return cookies
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		sameSite := "none"
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "strict"
		case http.SameSiteLaxMode:
			sameSite = "lax"
		case http.SameSiteDefaultMode:
			sameSite = "default"
		}
		cookies = append(cookies, cookieInfo{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: sameSite,
		})
	}

	return cookies
}

func (s *SecurityScanner) isPortOpen(host string, port int) bool {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *SecurityScanner) hasPasswordAuth() bool {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "PasswordAuthentication yes")
}

func (s *SecurityScanner) checkDockerSecurity(result *SecurityScanResult) {
	// Check running containers
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	containers := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, container := range containers {
		if container == "" {
			continue
		}

		// Check if container runs as root
		cmd = exec.Command("docker", "inspect", "--format", "{{.Config.User}}", container)
		userOutput, _ := cmd.Output()
		user := strings.TrimSpace(string(userOutput))
		if user == "" || user == "root" {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "MEDIUM",
				Category:      "Container Security",
				Title:         "Container runs as root: " + container,
				Description:   "Container is running with root privileges",
				Service:       container,
				Recommendation: "Run container with non-root user",
			})
		}

		// Check for privileged container
		cmd = exec.Command("docker", "inspect", "--format", "{{.HostConfig.Privileged}}", container)
		privOutput, _ := cmd.Output()
		if strings.TrimSpace(string(privOutput)) == "true" {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "CRITICAL",
				Category:      "Container Security",
				Title:         "Privileged container: " + container,
				Description:   "Container has full host access - container escape possible",
				Service:       container,
				Recommendation: "Remove --privileged flag",
			})
		}
	}
}

func (s *SecurityScanner) checkDatabaseExposure(result *SecurityScanResult) {
	// Check for exposed database ports
	dbPorts := map[int]string{
		3306: "MySQL/MariaDB",
		5432: "PostgreSQL",
		6379: "Redis",
		27017: "MongoDB",
		9042: "Cassandra",
		5433: "PostgreSQL alternate",
		33060: "MySQL X Protocol",
	}

	for port, dbType := range dbPorts {
		if s.isPortOpen("0.0.0.0", port) {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "CRITICAL",
				Category:      "Database Security",
				Title:         fmt.Sprintf("%s port %d exposed to all interfaces", dbType, port),
				Description:   "Database accessible from internet without firewall",
				Port:          port,
				Recommendation: "Restrict database port to localhost or internal network only",
			})
		} else if s.isPortOpen("127.0.0.1", port) {
			// OK - only localhost
		}
	}

	// Check Redis password
	if s.isPortOpen("127.0.0.1", 6379) {
		if !s.hasRedisPassword() {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "HIGH",
				Category:      "Database Security",
				Title:         "Redis has no password",
				Description:   "Redis is accessible without authentication",
				Port:          6379,
				Recommendation: "Set password in redis.conf or use AUTH command",
			})
		}
	}
}

func (s *SecurityScanner) checkExposedFiles(result *SecurityScanResult) {
	// Check if .git, .env, backup files are accessible on web services
	sensitivePaths := []string{
		".git/config",
		".git/HEAD",
		".env",
		".env.backup",
		".wp-config.php",
		"config.php.bak",
		"database.yml",
		".htaccess.old",
		"backup.sql",
	}

	// Check common web directories
	webRoots := []string{
		"/var/www/html",
		"/opt",
		"/home",
	}

	 for _, webRoot := range webRoots {
		if _, err := os.Stat(webRoot); os.IsNotExist(err) {
			continue
		}

		for _, sensitivePath := range sensitivePaths {
			fullPath := webRoot + "/" + sensitivePath

			if _, err := os.Stat(fullPath); err == nil {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "INFO",
					Category:      "File Exposure",
					Title:         fmt.Sprintf("Sensitive file found: %s", sensitivePath),
					Description:   "Sensitive file exists in web directory - verify it's not publicly accessible",
					Recommendation: "Ensure sensitive files are outside web root or properly protected",
				})
			}
		}
	}

	// Check if .git directory is in any project
	if output, err := exec.Command("find", "/opt", "/home", "/var/www", "-name", ".git", "-type", "d", "2>/dev/null").Output(); err == nil {
		gitDirs := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, gitDir := range gitDirs {
			if gitDir != "" {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "MEDIUM",
					Category:      "File Exposure",
					Title:         "Git repository found in project directory",
					Description:   fmt.Sprintf(".git directory found at: %s", gitDir),
					Recommendation: "Ensure .git directory is not publicly accessible via web server",
				})
			}
		}
	}
}

func (s *SecurityScanner) hasRedisPassword() bool {
	// Check redis config
	data, err := os.ReadFile("/etc/redis/redis.conf")
	if err != nil {
		// Try other paths
		data, err = os.ReadFile("/etc/redis.conf")
		if err != nil {
			return false
		}
	}
	return strings.Contains(string(data), "requirepass")
}

// === NEW SYSTEM SECURITY CHECKS ===

func (s *SecurityScanner) checkKernelVersion(result *SecurityScanResult) {
	// Check if kernel is outdated
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return
	}

	versionStr := string(data)
	
	// Check for known old kernels (example: pre-5.x or specific CVEs)
	// This is a simplified check - production would have more comprehensive version checking
	oldKernels := []string{
		"2.6.", // Very old
		"3.",    // Old
		"4.",    // Old LTS ended
	}
	
	for _, oldKernel := range oldKernels {
		if strings.Contains(versionStr, oldKernel) {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "HIGH",
				Category:      "System Security",
				Title:         "Outdated kernel version detected",
				Description:   fmt.Sprintf("Kernel version is old and may have unpatched vulnerabilities"),
				Recommendation: "Update kernel to latest stable version",
			})
			return
		}
	}
}

func (s *SecurityScanner) checkOutdatedPackages(result *SecurityScanResult) {
	// Check for yum/dnf updates
	if _, err := exec.LookPath("yum"); err == nil {
		output, err := exec.Command("yum", "check-update", "--security").Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			secUpdates := 0
			for _, line := range lines {
				if strings.Contains(line, ".x86_64") || strings.Contains(line, ".noarch") {
					secUpdates++
				}
			}
			if secUpdates > 0 {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "HIGH",
					Category:      "System Security",
					Title:         fmt.Sprintf("%d security updates available", secUpdates),
					Description:   "System packages have pending security updates",
					Recommendation: "Run: yum update --security",
				})
			}
		}
	}
	
	// Check for apt (Debian/Ubuntu)
	if _, err := exec.LookPath("apt"); err == nil {
		output, err := exec.Command("sh", "-c", "apt list --upgradable 2>/dev/null | grep -i security").Output()
		if err == nil && len(output) > 0 {
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			secUpdates := len(lines)
			if secUpdates > 0 {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "HIGH",
					Category:      "System Security",
					Title:         fmt.Sprintf("%d security updates available", secUpdates),
					Description:   "System packages have pending security updates",
					Recommendation: "Run: apt update && apt upgrade --security",
				})
			}
		}
	}
}

func (s *SecurityScanner) checkFailedLogins(result *SecurityScanResult) {
	// Check for failed SSH login attempts
	authLogPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/messages",
	}
	
	totalFailed := 0
	for _, logPath := range authLogPaths {
		data, err := os.ReadFile(logPath)
		if err != nil {
			continue
		}
		
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		failedCount := 0
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())
			if strings.Contains(line, "failed password") && strings.Contains(line, "ssh") {
				failedCount++
			}
		}
		totalFailed += failedCount
	}
	
	if totalFailed > 10 {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "MEDIUM",
			Category:      "Authentication",
			Title:         fmt.Sprintf("%d failed SSH login attempts detected", totalFailed),
			Description:   "Multiple failed login attempts may indicate brute force attack",
			Recommendation: "Consider enabling fail2ban or restricting SSH access",
		})
	}
}

func (s *SecurityScanner) checkUserAccounts(result *SecurityScanResult) {
	// Check for users with empty passwords
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			// Check for empty password (second field is empty or *)
			if parts[1] == "" || parts[1] == "*" || parts[1] == "!" {
				// Valid entries with * or ! are locked accounts - OK
				continue
			}
			// Empty password field is a serious issue
			if parts[1] == "NP" || parts[1] == "!!" {
				username := parts[0]
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "CRITICAL",
					Category:      "Authentication",
					Title:         fmt.Sprintf("User '%s' has no password", username),
					Description:   "User account has no password set - can be accessed by anyone",
					Recommendation: "Set a strong password: passwd " + username,
				})
			}
		}
	}
	
	// Check for root SSH access
	if output, err := exec.Command("grep", "-E", "^PermitRootLogin|^PasswordAuthentication", "/etc/ssh/sshd_config").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if strings.Contains(line, "PermitRootLogin yes") {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "HIGH",
					Category:      "Authentication",
					Title:         "Root SSH login enabled",
					Description:   "Root can login via SSH - high security risk",
					Recommendation: "Set PermitRootLogin no in /etc/ssh/sshd_config",
				})
			}
		}
	}
}

// === FILE SYSTEM SECURITY CHECKS ===

func (s *SecurityScanner) checkWorldWritableFiles(result *SecurityScanResult) {
	// Check for world-writable files in common directories
	dirs := []string{"/etc", "/var", "/tmp", "/home"}
	
	for _, dir := range dirs {
		cmd := exec.Command("find", dir, "-perm", "-0002", "-type", "f", "-not", "-path", "*/proc/*")
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		
		files := strings.Split(strings.TrimSpace(string(output)), "\n")
		count := 0
		hasFiles := false
		for _, file := range files {
			if file == "" {
				continue
			}
			hasFiles = true
			count++
			// Report first 5 files individually
			if count <= 5 {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "MEDIUM",
					Category:      "File Permissions",
					Title:         fmt.Sprintf("World-writable file: %s", file),
					Description:   "File can be written by any user - security risk",
					Recommendation: "Remove world write permission: chmod o-w " + file,
				})
			}
		}
		if hasFiles && count > 5 {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "MEDIUM",
				Category:      "File Permissions",
				Title:         fmt.Sprintf("%d world-writable files found in %s", count, dir),
				Description:   "Multiple world-writable files found (showing first 5)",
				Recommendation: "Review and restrict permissions: chmod o-w <file>",
			})
		}
	}
}

func (s *SecurityScanner) checkSUIDBinaries(result *SecurityScanResult) {
	// Check for SUID binaries (potential privilege escalation)
	// Known safe SUID binaries
	safeSUID := map[string]bool{
		"/usr/bin/passwd": true,
		"/usr/bin/sudo": true,
		"/bin/su": true,
		"/usr/bin/su": true,
		"/usr/bin/newgrp": true,
		"/usr/bin/chfn": true,
		"/usr/bin/chsh": true,
		"/usr/bin/gpasswd": true,
	}
	
	cmd := exec.Command("find", "/usr", "-perm", "-4000", "-type", "f")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	suidFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
	
	suspiciousCount := 0
	for _, suidFile := range suidFiles {
		if suidFile == "" {
			continue
		}
		if !safeSUID[suidFile] {
			suspiciousCount++
			if suspiciousCount <= 10 {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "MEDIUM",
					Category:      "File Permissions",
					Title:         fmt.Sprintf("Non-standard SUID binary: %s", suidFile),
					Description:   "SUID binary that is not commonly needed - potential privilege escalation",
					Recommendation: "Review if this SUID bit is necessary: ls -la " + suidFile,
				})
			}
		}
	}
	
	if suspiciousCount > 10 {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "MEDIUM",
			Category:      "File Permissions",
			Title:         fmt.Sprintf("%d non-standard SUID binaries found", suspiciousCount),
			Description:   "Multiple SUID binaries that are not in the known-safe list",
			Recommendation: "Review all SUID binaries and remove unnecessary ones",
		})
	}
}

// === NETWORK SECURITY CHECKS ===

func (s *SecurityScanner) checkWeakSSLCiphers(result *SecurityScanResult) {
	// Check for weak SSL/TLS ciphers on local ports
	ports := []int{443, 8443, 993, 995}
	hosts := []string{"localhost", "127.0.0.1"}

	for _, host := range hosts {
		for _, port := range ports {
			address := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := tls.Dial("tcp", address, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				continue
			}
			defer conn.Close()

			state := conn.ConnectionState()
			// Check TLS version
			if state.Version < tls.VersionTLS12 {
				result.Issues = append(result.Issues, SecurityIssue{
					Severity:      "HIGH",
					Category:      "Network Security",
					Title:         fmt.Sprintf("Outdated TLS version on %s:%d", host, port),
					Description:   fmt.Sprintf("Using TLS %d.%d - deprecated and insecure", state.Version/256, state.Version%256),
					Port:          port,
					Recommendation: "Upgrade to TLS 1.2 or 1.3",
				})
			}
		}
	}
}

func (s *SecurityScanner) checkFirewallStatus(result *SecurityScanResult) {
	// Check if firewall is enabled
	foundFirewall := false
	hasRules := false

	// Check for firewalld
	if _, err := exec.LookPath("firewalld"); err == nil {
		foundFirewall = true
		if !s.isServiceRunning("firewalld") {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "HIGH",
				Category:      "Network Security",
				Title:         "Firewalld installed but not active",
				Description:   "Firewall is not actively filtering network traffic",
				Recommendation: "Enable firewalld: systemctl enable --now firewalld",
			})
		}
	}

	// Check for iptables (rules indicate active firewall)
	if _, err := exec.LookPath("iptables"); err == nil {
		foundFirewall = true
		cmd := exec.Command("sh", "-c", "iptables -L -n 2>/dev/null | grep -c DROP")
		output, _ := cmd.Output()
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" && outputStr != "0" {
			hasRules = true
		}
		// Check if iptables service exists and is running
		if !hasRules && !s.isServiceRunning("iptables") {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "HIGH",
				Category:      "Network Security",
				Title:         "iptables has no active rules",
				Description:   "Firewall has no DROP/ACCEPT rules configured",
				Recommendation: "Configure iptables rules or enable firewalld",
			})
		}
	}

	// Check for nftables
	if _, err := exec.LookPath("nft"); err == nil {
		foundFirewall = true
		// nftables is more complex, check if there are active rules
		cmd := exec.Command("sh", "-c", "nft list tables 2>/dev/null")
		output, _ := cmd.Output()
		if strings.TrimSpace(string(output)) == "" {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:      "HIGH",
				Category:      "Network Security",
				Title:         "nftables installed but no active rules",
				Description:   "nftables has no active tables/rules",
				Recommendation: "Configure nftables rules",
			})
		}
	}

	if !foundFirewall {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:      "MEDIUM",
			Category:      "Network Security",
			Title:         "No firewall detected",
			Description:   "No firewall (firewalld/iptables/nft) is installed",
			Recommendation: "Install and configure a firewall",
		})
	}
}

func (s *SecurityScanner) isServiceRunning(name string) bool {
	cmd := exec.Command("systemctl", "is-active", name)
	err := cmd.Run()
	return err == nil
}

func (s *SecurityScanner) checkSuspiciousProcesses(result *SecurityScanResult) {
	// Check for suspicious processes
	suspiciousPatterns := []struct {
		pattern string
		severity string
		description string
	}{
		{"nc -l", "HIGH", "Network listener (potential backdoor)"},
		{"ncat -l", "HIGH", "Netcat listener (potential backdoor)"},
		{"/dev/tcp", "HIGH", "Direct TCP manipulation (potential reverse shell)"},
		{"msfconsole", "HIGH", "Metasploit framework detected"},
		{"nikto", "MEDIUM", "Vulnerability scanner detected"},
		{"sqlmap", "HIGH", "SQL injection tool detected"},
		{"hydra", "HIGH", "Password brute-force tool detected"},
		{"john", "MEDIUM", "Password cracking tool detected"},
		{"hashcat", "MEDIUM", "Password cracking tool detected"},
		{"tcpdump", "LOW", "Network sniffer running"},
		{"wireshark", "LOW", "Network analyzer running"},
		{"nmap", "LOW", "Network scanner running"},
	}

	// Get running processes
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // Skip header
		for _, sp := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(line), strings.ToLower(sp.pattern)) {
				parts := strings.Fields(line)
				if len(parts) > 10 {
					result.Issues = append(result.Issues, SecurityIssue{
						Severity:      sp.severity,
						Category:      "Process Security",
						Title:         fmt.Sprintf("Suspicious process: %s", parts[10]),
						Description:   sp.description,
						Recommendation: "Investigate this process if not expected",
					})
				}
			}
		}
	}
}
