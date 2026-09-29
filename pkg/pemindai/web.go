package pemindai

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"aman/pkg/tipe"
)

// PemindaiWeb untuk memindai websites
type PemindaiWeb struct {
	TargetURL string
	Client    *http.Client
}

// HasilWebScan adalah hasil pemindaian website
type HasilWebScan struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	TechStack  []string
	Links      []string
	Paket      []tipe.Paket
}

// NewPemindaiWeb membuat scanner baru
func NewPemindaiWeb() *PemindaiWeb {
	return &PemindaiWeb{
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

// Pindai memindai website
func (p *PemindaiWeb) Pindai(target string) (*HasilWebScan, error) {
	p.TargetURL = target

	// Normalize URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// Parse URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("URL tidak valid: %v", err)
	}

	// Buat hasil
	hasil := &HasilWebScan{
		URL:     target,
		Paket:   []tipe.Paket{},
		Links:   []string{},
		TechStack: []string{},
	}

	// Fetch homepage
	resp, err := p.Client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("Gagal fetch website: %v", err)
	}
	defer resp.Body.Close()

	hasil.StatusCode = resp.StatusCode

	// Ambil header info
	hasil.Server = resp.Header.Get("Server")
	if hasil.Server == "" {
		hasil.Server = "Unknown"
	}

	// Baca content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Gagal baca response: %v", err)
	}
	content := string(body)

	// Parse title
	hasil.Title = p.parseTitle(content)

	// Detect tech stack
	hasil.TechStack = p.detectTechStack(content, resp.Header, target)

	// Extract links
	hasil.Links = p.extractLinks(content, parsedURL)

	// Deteksi packages dari HTML/meta tags
	hasil.Paket = p.detectPackagesFromWeb(content, target)

	return hasil, nil
}

func (p *PemindaiWeb) parseTitle(content string) string {
	// Cari <title>
	re := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return "No Title"
}

func (p *PemindaiWeb) detectTechStack(content string, headers http.Header, baseURL string) []string {
	var techs []string

	contentLower := strings.ToLower(content)

	// JavaScript Frameworks
	if strings.Contains(contentLower, "react") || strings.Contains(contentLower, "reactjs") {
		techs = append(techs, "React")
	}
	if strings.Contains(contentLower, "vue") || strings.Contains(contentLower, "vuejs") {
		techs = append(techs, "Vue.js")
	}
	if strings.Contains(contentLower, "angular") || strings.Contains(contentLower, "ng-app") {
		techs = append(techs, "Angular")
	}
	if strings.Contains(contentLower, "next.js") || strings.Contains(contentLower, "__next") {
		techs = append(techs, "Next.js")
	}
	if strings.Contains(contentLower, "nuxt") {
		techs = append(techs, "Nuxt.js")
	}

	// Backend Frameworks
	if strings.Contains(contentLower, "express") || strings.Contains(contentLower, "expressjs") {
		techs = append(techs, "Express.js")
	}
	if strings.Contains(contentLower, "django") || strings.Contains(contentLower, "djangoproject") {
		techs = append(techs, "Django")
	}
	if strings.Contains(contentLower, "flask") || strings.Contains(contentLower, "jinja") {
		techs = append(techs, "Flask")
	}
	if strings.Contains(contentLower, "fastapi") {
		techs = append(techs, "FastAPI")
	}
	if strings.Contains(contentLower, "laravel") {
		techs = append(techs, "Laravel")
	}
	if strings.Contains(contentLower, "rails") || strings.Contains(contentLower, "rubyonrails") {
		techs = append(techs, "Ruby on Rails")
	}
	if strings.Contains(contentLower, "spring") || strings.Contains(contentLower, "springboot") {
		techs = append(techs, "Spring Boot")
	}
	if strings.Contains(contentLower, "gatsby") {
		techs = append(techs, "Gatsby")
	}

	// CMS
	if strings.Contains(contentLower, "wordpress") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(contentLower, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(contentLower, "joomla") {
		techs = append(techs, "Joomla")
	}
	if strings.Contains(contentLower, "ghost") {
		techs = append(techs, "Ghost CMS")
	}
	if strings.Contains(contentLower, "hubspot") {
		techs = append(techs, "HubSpot")
	}

	// E-commerce
	if strings.Contains(contentLower, "shopify") {
		techs = append(techs, "Shopify")
	}
	if strings.Contains(contentLower, "woocommerce") {
		techs = append(techs, "WooCommerce")
	}
	if strings.Contains(contentLower, "magento") {
		techs = append(techs, "Magento")
	}
	if strings.Contains(contentLower, "prestashop") {
		techs = append(techs, "PrestaShop")
	}

	// CDN & Cloud
	if strings.Contains(contentLower, "cloudflare") {
		techs = append(techs, "Cloudflare")
	}
	if strings.Contains(contentLower, "akamai") {
		techs = append(techs, "Akamai")
	}
	if strings.Contains(contentLower, "aws-sdk") || strings.Contains(contentLower, "amazon aws") {
		techs = append(techs, "AWS")
	}
	if strings.Contains(contentLower, "google analytics") || strings.Contains(contentLower, "gtag") {
		techs = append(techs, "Google Analytics")
	}
	if strings.Contains(contentLower, "facebook.net") || strings.Contains(contentLower, "fbq") {
		techs = append(techs, "Facebook Pixel")
	}

	// Check headers
	serverHeader := strings.ToLower(headers.Get("Server"))
	xPoweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	xAspNetVersion := headers.Get("X-AspNet-Version")

	if strings.Contains(serverHeader, "nginx") {
		techs = append(techs, "Nginx")
	}
	if strings.Contains(serverHeader, "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(serverHeader, "iis") || strings.Contains(serverHeader, "microsoft") {
		techs = append(techs, "IIS")
	}
	if strings.Contains(xPoweredBy, "php") {
		techs = append(techs, "PHP")
	}
	if strings.Contains(xPoweredBy, "asp.net") {
		techs = append(techs, "ASP.NET")
	}
	if xAspNetVersion != "" {
		techs = append(techs, "ASP.NET "+xAspNetVersion)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, t := range techs {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}

	return unique
}

func (p *PemindaiWeb) extractLinks(content string, baseURL *url.URL) []string {
	var links []string

	// Regex untuk href
	re := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) >= 2 {
			href := match[1]

			// Skip empty, javascript, mailto, tel
			if href == "" ||
			   strings.HasPrefix(href, "javascript:") ||
			   strings.HasPrefix(href, "mailto:") ||
			   strings.HasPrefix(href, "tel:") {
				continue
			}

			// Resolve relative URLs
			if strings.HasPrefix(href, "/") {
				href = baseURL.Scheme + "://" + baseURL.Host + href
			}

			// Deduplicate
			if !seen[href] {
				seen[href] = true
				links = append(links, href)
			}
		}
	}

	return links
}

func (p *PemindaiWeb) detectPackagesFromWeb(content string, target string) []tipe.Paket {
	var packages []tipe.Paket

	// Cek meta tags untuk version info
	metaPattern := regexp.MustCompile(`<meta[^>]+(name|property)=["']([^"']+)["'][^>]+content=["']([^"']+)["']`)
	matches := metaPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			name := match[2]
			content := match[3]

			// Deteksi framework/version dari meta
			if strings.Contains(strings.ToLower(name), "generator") {
				paket := p.parseGeneratorMeta(content)
				if paket.Nama != "" {
					packages = append(packages, paket)
				}
			}
		}
	}

	// Cek script tags untuk JS libraries
	scriptPattern := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	scriptMatches := scriptPattern.FindAllStringSubmatch(content, -1)

	seen := make(map[string]bool)
	for _, match := range scriptMatches {
		if len(match) >= 2 {
			src := match[1]

			// Parse CDN links
			paket := p.parseCDNScript(src)
			if paket.Nama != "" && !seen[paket.Nama] {
				seen[paket.Nama] = true
				packages = append(packages, paket)
			}
		}
	}

	return packages
}

func (p *PemindaiWeb) parseGeneratorMeta(content string) tipe.Paket {
	paket := tipe.Paket{}

	contentLower := strings.ToLower(content)

	if strings.Contains(contentLower, "wordpress") {
		paket.Nama = "WordPress"
		paket.Jenis = "cms"
		// Extract version
		re := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
		v := re.FindString(content)
		if v != "" {
			paket.Versi = v
		}
	} else if strings.Contains(contentLower, "drupal") {
		paket.Nama = "Drupal"
		paket.Jenis = "cms"
	} else if strings.Contains(contentLower, "joomla") {
		paket.Nama = "Joomla"
		paket.Jenis = "cms"
	} else if strings.Contains(contentLower, "gatsby") {
		paket.Nama = "Gatsby"
		paket.Jenis = "framework"
	} else if strings.Contains(contentLower, "next.js") {
		paket.Nama = "Next.js"
		paket.Jenis = "framework"
	} else if strings.Contains(contentLower, "wix") {
		paket.Nama = "Wix"
		paket.Jenis = "cms"
	} else if strings.Contains(contentLower, "squarespace") {
		paket.Nama = "Squarespace"
		paket.Jenis = "cms"
	} else if strings.Contains(contentLower, "shopify") {
		paket.Nama = "Shopify"
		paket.Jenis = "ecommerce"
	}

	return paket
}

func (p *PemindaiWeb) parseCDNScript(src string) tipe.Paket {
	paket := tipe.Paket{}

	srcLower := strings.ToLower(src)

	// jQuery
	if strings.Contains(srcLower, "jquery") {
		paket.Nama = "jQuery"
		paket.Jenis = "npm"
		// Extract version from path
		re := regexp.MustCompile(`jquery[-/]?([\d.]+)?`)
		v := re.FindStringSubmatch(srcLower)
		if len(v) >= 2 && v[1] != "" {
			paket.Versi = v[1]
		}
	}

	// React
	if strings.Contains(srcLower, "react") && strings.Contains(srcLower, "umd") {
		paket.Nama = "React"
		paket.Jenis = "npm"
	}

	// Vue
	if strings.Contains(srcLower, "vue") && !strings.Contains(srcLower, "avuetify") {
		paket.Nama = "Vue.js"
		paket.Jenis = "npm"
	}

	// Bootstrap
	if strings.Contains(srcLower, "bootstrap") {
		paket.Nama = "Bootstrap"
		paket.Jenis = "npm"
	}

	// lodash
	if strings.Contains(srcLower, "lodash") {
		paket.Nama = "Lodash"
		paket.Jenis = "npm"
	}

	// moment
	if strings.Contains(srcLower, "moment") {
		paket.Nama = "Moment.js"
		paket.Jenis = "npm"
	}

	// axios
	if strings.Contains(srcLower, "axios") {
		paket.Nama = "Axios"
		paket.Jenis = "npm"
	}

	// Chart.js
	if strings.Contains(srcLower, "chart") && strings.Contains(srcLower, "js") {
		paket.Nama = "Chart.js"
		paket.Jenis = "npm"
	}

	return paket
}
