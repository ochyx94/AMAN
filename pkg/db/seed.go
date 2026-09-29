package db

import (
	"database/sql"
)

// SeedData menambahkan kelemahan umum ke database
func SeedData(db *sql.DB) error {
	// Kelemahan umum untuk Node.js/npm
	npmKelemahan := []InsertKelemahanInput{
		{
			ID:         "CVE-2021-23343",
			Judul:      "Command Injection in lodash",
			Penjelasan: "Lodash versions before 4.17.21 are vulnerable to Command Injection via the template function",
			Tingkat:    "HIGH",
			Paket:      "lodash",
			Pattern:    `lodash`,
			VersiAman:  "4.17.21",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2021-23343",
		},
		{
			ID:         "CVE-2020-28469",
			Judul:      "Directory Traversal in glob-parent",
			Penjelasan: "This affects the package glob-parent before 5.1.2. The vulnerability is present in the walk function",
			Tingkat:    "HIGH",
			Paket:      "glob-parent",
			Pattern:    `glob-parent`,
			VersiAman:  "5.1.2",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2020-28469",
		},
	}

	// Kelemahan umum untuk Python/pip
	pipKelemahan := []InsertKelemahanInput{
		{
			ID:         "CVE-2021-23336",
			Judul:      "Web cache poisoning in django",
			Penjelasan: "Django 2.2 before 2.2.19 and 3.0 before 3.0.14 allows URL validation via django.conf.settings",
			Tingkat:    "MEDIUM",
			Paket:      "django",
			Pattern:    `django`,
			VersiAman:  "3.0.14",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2021-23336",
		},
		{
			ID:         "CVE-2022-42969",
			Judul:      "Denial of Service in py",
			Penjelasan: "Python before 3.11.0a7 allows arbitrary code execution via exec",
			Tingkat:    "CRITICAL",
			Paket:      "py",
			Pattern:    `py`,
			VersiAman:  "3.11.0",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2022-42969",
		},
	}

	// Kelemahan umum untuk Go
	goKelemahan := []InsertKelemahanInput{
		{
			ID:         "CVE-2022-32189",
			Judul:      "JWT validation bypass in golang-jwt/jwt",
			Penjelasan: " golang-jwt/jwt before 3.2.2 allows attackers to bypass intended access restrictions",
			Tingkat:    "HIGH",
			Paket:      "golang-jwt/jwt",
			Pattern:    `golang-jwt/jwt`,
			VersiAman:  "3.2.2",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2022-32189",
		},
	}

	// Kelemahan umum untuk Ruby
	rubyKelemahan := []InsertKelemahanInput{
		{
			ID:         "CVE-2020-8163",
			Judul:      "Code injection in actionview",
			Penjelasan: "ActionView before 5.2.4.5, 6.0.3.4 allows code injection via Rails tag helpers",
			Tingkat:    "CRITICAL",
			Paket:      "actionview",
			Pattern:    `actionview`,
			VersiAman:  "6.0.3.4",
			Referensi:   "https://nvd.nist.gov/vuln/detail/CVE-2020-8163",
		},
	}

	// Masukkan semua kelemahan
	allKelemahan := append(append(append(npmKelemahan, pipKelemahan...), goKelemahan...), rubyKelemahan...)
	
	for _, k := range allKelemahan {
		err := InsertKelemahan(db, k)
		if err != nil {
			return err
		}
	}

	// Kelemahan konfigurasi (non-CVE)
	konfigurasiSalah := []struct {
		nama        string
		penjelasan  string
		tingkat     string
		filePattern string
		matcher     string
		referensi   string
	}{
		{
			nama:        "Debug Mode Aktif",
			penjelasan:  "Debug mode dalam aplikasi production sangat berbahaya",
			tingkat:     "HIGH",
			filePattern: "*.env",
			matcher:     "DEBUG=true",
			referensi:   "https://owasp.org/www-project-web-security-testing-guide/",
		},
		{
			nama:        "Default Credentials",
			penjelasan:  "Menggunakan default username/password sangat berbahaya",
			tingkat:     "CRITICAL",
			filePattern: "*.conf,*.config,*.yaml,*.yml",
			matcher:     "admin:admin,user:password,root:root",
			referensi:   "https://owasp.org/www-project-top-ten/",
		},
		{
			nama:        "SQL Injection Risk",
			penjelasan:  "Kode rentan SQL injection ditemukan",
			tingkat:     "CRITICAL",
			filePattern: "*.py,*.js,*.go,*.java",
			matcher:     "cursor.execute,query,SELECT * FROM",
			referensi:   "https://owasp.org/www-community/attacks/SQL_Injection",
		},
		{
			nama:        "Hardcoded Secret",
			penjelasan:  "Secret/key/password hardcoded dalam kode",
			tingkat:     "CRITICAL",
			filePattern: "*.py,*.js,*.go,*.java,*.yaml,*.yml",
			matcher:     "api_key,apikey,secret_key,password,token",
			referensi:   "https://owasp.org/www-project-top-ten/",
		},
		{
			nama:        "Insecure CORS",
			penjelasan:  "CORS policy terlalu longgar",
			tingkat:     "MEDIUM",
			filePattern: "*.js,*.py,*.go",
			matcher:     "Access-Control-Allow-Origin:*",
			referensi:   "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
		},
	}

	// Masukkan konfigurasi salah
	for _, k := range konfigurasiSalah {
		err := InsertKonfigurasiSalah(db, k.nama, k.penjelasan, k.tingkat, k.filePattern, k.matcher, k.referensi)
		if err != nil {
			return err
		}
	}

	return nil
}
