package pemindai

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
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

	// 1. Check running services
	s.checkRunningServices(result)

	// 2. Check open ports
	s.checkOpenPorts(result)

	// 3. Check SSL/TLS certificates
	s.checkSSLCertificates(result)

	// 4. Check exposed services
	s.checkExposedServices(result)

	// 5. Check Docker security
	s.checkDockerSecurity(result)

	// 6. Check database exposure
	s.checkDatabaseExposure(result)

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
