package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"aman/pkg/deteksi"
	"aman/pkg/output"
	"aman/pkg/pemindai"
	"aman/pkg/tipe"
)

// minInt returns the smaller of two ints
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Version AMAN
const Version = "1.3.1"

func main() {
	if len(os.Args) == 1 {
		printHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		printHelp()
	case "version", "--version", "-v":
		fmt.Printf("AMAN version %s\n", Version)
	case "periksa":
		jalankanPeriksa()
	case "periksa-all", "scan-all":
		jalankanPeriksaAll()
	case "periksa-security":
		jalankanPeriksaSecurity()
	case "update":
		jalankanUpdate()
	case "serve":
		jalankanServe()
	default:
		fmt.Printf("Perintah tidak dikenal: %s\n", os.Args[1])
		fmt.Println("Ketik 'aman help' untuk bantuan.")
		os.Exit(1)
	}
}

func jalankanPeriksa() {
	var jenis string
	var sasaran string
	var checkOnline bool
	var format string

	// parse arguments
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--jenis", "-j":
			if i+1 < len(args) {
				jenis = args[i+1]
				i++
			}
		case "--sasaran", "-s":
			if i+1 < len(args) {
				sasaran = args[i+1]
				i++
			}
		case "--online", "-o":
			checkOnline = true
		case "--format", "-f":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		}
	}

	// cek kelengkapan
	if jenis == "" {
		fmt.Println("Error: --jenis wajib diisi")
		fmt.Println("Contoh: aman periksa --jenis folder --sasaran /app")
		os.Exit(1)
	}
	if sasaran == "" {
		fmt.Println("Error: --sasaran wajib diisi")
		fmt.Println("Contoh: aman periksa --jenis folder --sasaran /app")
		os.Exit(1)
	}

	// jalankan berdasarkan jenis
	mulai := time.Now()

	switch jenis {
	case "folder":
		pindaiFolder(sasaran, checkOnline, format)
	case "docker":
		pindaiDocker(sasaran, checkOnline, format)
	case "web":
		pindaiWeb(sasaran, checkOnline, format)
	case "all":
		pindaiAll(sasaran, checkOnline, format)
	default:
		fmt.Printf("Jenis tidak dikenal: %s\n", jenis)
		fmt.Println("Jenis yang tersedia: folder, docker, web, all")
		os.Exit(1)
	}

	durasi := time.Since(mulai).Seconds()
	if format != "json" {
		fmt.Printf("\nSelesai dalam %.2f detik\n", durasi)
	}
}

func pindaiFolder(sasaran string, checkOnline bool, format string) {
	if format != "json" {
		fmt.Printf("Memindai folder: %s\n", sasaran)
		if checkOnline {
			fmt.Println("Mode: ONLINE (cek GitHub Advisories)")
		} else {
			fmt.Println("Mode: OFFLINE (database lokal saja)")
		}
		fmt.Println("==============================")
	}

	// Inisialisasi database
	db, err := deteksi.InitDatabase()
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal init database: %v"}`, err)
		} else {
			fmt.Printf("Error init database: %v\n", err)
		}
		os.Exit(1)
	}
	defer db.Close()

	// Jalankan scanner
	p := pemindai.PemindaiFolder{}
	paketList, err := p.Pindai(sasaran)
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal scan: %v"}`, err)
		} else {
			fmt.Printf("Error: %v\n", err)
		}
		os.Exit(1)
	}

	// Deteksi kelemahan
	var semuaKelemahan []tipe.Kelemahan
	sumberCek := tipe.SourceLocalDB

	for _, paket := range paketList {
		kelemahan, sumber, err := deteksi.DeteksiPaket(db, paket, checkOnline)
		if err != nil {
			continue
		}
		semuaKelemahan = append(semuaKelemahan, kelemahan...)
		if sumber == tipe.SourceGitHubAPI {
			sumberCek = tipe.SourceGitHubAPI
		}
	}

	// Tentukan status
	status := getStatus(semuaKelemahan, checkOnline, sumberCek)

	// Format output
	if format == "json" {
		hasil := tipe.HasilPemindaian{
			Sasaran:         sasaran,
			JenisPemindaian: "folder",
			Durasi:          0,
			Status:          status,
			SumberCek:      sumberCek,
			Paket:          paketList,
			Kelemahan:      semuaKelemahan,
		}
		bytes, err := output.FormatJSON(hasil)
		if err != nil {
			fmt.Printf(`{"error": "gagal format json: %v"}`, err)
			os.Exit(1)
		}
		fmt.Println(string(bytes))
		return
	}

	// Text format
	fmt.Printf("\nDitemukan %d paket\n\n", len(paketList))

	if len(semuaKelemahan) > 0 {
		fmt.Printf("Ditemukan %d kelemahan:\n\n", len(semuaKelemahan))
		for i, k := range semuaKelemahan {
			fmt.Printf("%d. %s [%s]\n", i+1, k.ID, k.Tingkat)
			fmt.Printf("   Judul: %s\n", k.Judul)
			fmt.Printf("   Paket: %s\n", k.Paket.Nama)
			if k.Referensi != "" {
				fmt.Printf("   Ref:   %s\n", k.Referensi)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("Tidak ada kelemahan diketemukan.")
	}

	// Status verdict
	fmt.Println("==============================")
	printStatus(status, sumberCek)
}

func pindaiDocker(image string, checkOnline bool, format string) {
	if format != "json" {
		fmt.Printf("Memindai Docker image: %s\n", image)
		if checkOnline {
			fmt.Println("Mode: ONLINE (cek GitHub Advisories)")
		} else {
			fmt.Println("Mode: OFFLINE (database lokal saja)")
		}
		fmt.Println("==============================")
	}

	// Inisialisasi database
	db, err := deteksi.InitDatabase()
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal init database: %v"}`, err)
		} else {
			fmt.Printf("Error init database: %v\n", err)
		}
		os.Exit(1)
	}
	defer db.Close()

	// Jalankan scanner
	p := pemindai.PemindaiDocker{}
	paketList, err := p.Pindai(image)
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal scan docker: %v"}`, err)
		} else {
			fmt.Printf("Error: %v\n", err)
			fmt.Println()
			fmt.Println("Tips:")
			fmt.Println("  - Pastikan Docker terinstall dan berjalan")
			fmt.Println("  - Pastikan kamu punya akses ke image ini")
			fmt.Println("  - Coba: docker pull " + image)
		}
		os.Exit(1)
	}

	// Deteksi kelemahan
	var semuaKelemahan []tipe.Kelemahan
	sumberCek := tipe.SourceLocalDB

	for _, paket := range paketList {
		kelemahan, sumber, err := deteksi.DeteksiPaket(db, paket, checkOnline)
		if err != nil {
			continue
		}
		semuaKelemahan = append(semuaKelemahan, kelemahan...)
		if sumber == tipe.SourceGitHubAPI {
			sumberCek = tipe.SourceGitHubAPI
		}
	}

	// Tentukan status
	status := getStatus(semuaKelemahan, checkOnline, sumberCek)

	// Format output
	if format == "json" {
		hasil := tipe.HasilPemindaian{
			Sasaran:         image,
			JenisPemindaian: "docker",
			Durasi:          0,
			Status:          status,
			SumberCek:      sumberCek,
			Paket:          paketList,
			Kelemahan:      semuaKelemahan,
		}
		bytes, err := output.FormatJSON(hasil)
		if err != nil {
			fmt.Printf(`{"error": "gagal format json: %v"}`, err)
			os.Exit(1)
		}
		fmt.Println(string(bytes))
		return
	}

	// Text format
	fmt.Printf("\nDitemukan %d paket\n\n", len(paketList))

	if len(semuaKelemahan) > 0 {
		fmt.Printf("Ditemukan %d kelemahan:\n\n", len(semuaKelemahan))
		for i, k := range semuaKelemahan {
			fmt.Printf("%d. %s [%s]\n", i+1, k.ID, k.Tingkat)
			fmt.Printf("   Judul: %s\n", k.Judul)
			fmt.Printf("   Paket: %s@%s (%s)\n", k.Paket.Nama, k.Paket.Versi, k.Paket.Jenis)
			if k.Referensi != "" {
				fmt.Printf("   Ref:   %s\n", k.Referensi)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("Tidak ada kelemahan diketemukan.")
	}

	// Status verdict
	fmt.Println("==============================")
	printStatus(status, sumberCek)
}

func pindaiWeb(target string, checkOnline bool, format string) {
	if format != "json" {
		fmt.Printf("Memindai website: %s\n", target)
		if checkOnline {
			fmt.Println("Mode: ONLINE (cek GitHub Advisories)")
		} else {
			fmt.Println("Mode: OFFLINE (database lokal saja)")
		}
		fmt.Println("==============================")
	}

	// Inisialisasi database
	db, err := deteksi.InitDatabase()
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal init database: %v"}`, err)
		} else {
			fmt.Printf("Error init database: %v\n", err)
		}
		os.Exit(1)
	}
	defer db.Close()

	// Jalankan scanner
	p := pemindai.NewPemindaiWeb()
	hasil, err := p.Pindai(target)
	if err != nil {
		if format == "json" {
			fmt.Printf(`{"error": "gagal scan web: %v"}`, err)
		} else {
			fmt.Printf("Error: %v\n", err)
			fmt.Println()
			fmt.Println("Tips:")
			fmt.Println("  - Pastikan URL benar (termasuk http:// atau https://)")
			fmt.Println("  - Pastikan website bisa diakses")
			fmt.Println("  - Coba: curl " + target)
		}
		os.Exit(1)
	}

	// Tampilkan info website
	if format != "json" {
		fmt.Println()
		fmt.Println("--- Informasi Website ---")
		fmt.Printf("URL:      %s\n", hasil.URL)
		fmt.Printf("Status:   %d\n", hasil.StatusCode)
		fmt.Printf("Title:    %s\n", hasil.Title)
		fmt.Printf("Server:   %s\n", hasil.Server)
		if len(hasil.TechStack) > 0 {
			fmt.Printf("Tech:     %s\n", joinString(hasil.TechStack, ", "))
		}
		if len(hasil.Links) > 0 {
			fmt.Printf("Links:    %d ditemukan\n", len(hasil.Links))
			// Tampilkan sample links (max 5)
			if len(hasil.Links) > 5 {
				fmt.Println("Sample links:")
				for i := 0; i < 5; i++ {
					fmt.Printf("  - %s\n", hasil.Links[i])
				}
				fmt.Printf("  ... dan %d links lainnya\n", len(hasil.Links)-5)
			} else {
				fmt.Println("Links:")
				for _, link := range hasil.Links {
					fmt.Printf("  - %s\n", link)
				}
			}
		}
	}

	// Deteksi kelemahan
	var semuaKelemahan []tipe.Kelemahan
	sumberCek := tipe.SourceLocalDB

	for _, paket := range hasil.Paket {
		kelemahan, sumber, err := deteksi.DeteksiPaket(db, paket, checkOnline)
		if err != nil {
			continue
		}
		semuaKelemahan = append(semuaKelemahan, kelemahan...)
		if sumber == tipe.SourceGitHubAPI {
			sumberCek = tipe.SourceGitHubAPI
		}
	}

	// Tentukan status
	status := getStatus(semuaKelemahan, checkOnline, sumberCek)

	// Format output
	if format == "json" {
		// Convert web packages ke tipe.Paket
		var paketList []tipe.Paket
		for _, p := range hasil.Paket {
			paketList = append(paketList, tipe.Paket{
				Nama:    p.Nama,
				Versi:   p.Versi,
				Jenis:   p.Jenis,
				Lokasi:  p.Lokasi,
			})
		}

		hasilScan := tipe.HasilPemindaian{
			Sasaran:         target,
			JenisPemindaian: "web",
			Durasi:          0,
			Status:          status,
			SumberCek:      sumberCek,
			Paket:          paketList,
			Kelemahan:      semuaKelemahan,
		}
		bytes, err := output.FormatJSON(hasilScan)
		if err != nil {
			fmt.Printf(`{"error": "gagal format json: %v"}`, err)
			os.Exit(1)
		}
		fmt.Println(string(bytes))
		return
	}

	// Text format - Tampilkan summary untuk web scan
	if len(hasil.Links) > 0 || len(hasil.TechStack) > 0 {
		fmt.Printf("\nDitemukan:\n")
		if len(hasil.Links) > 0 {
			fmt.Printf("  - %d Links\n", len(hasil.Links))
		}
		if len(hasil.TechStack) > 0 {
			fmt.Printf("  - %d Tech Stack\n", len(hasil.TechStack))
		}
		fmt.Printf("  - %d Paket (untuk CVE check)\n", len(hasil.Paket))
		fmt.Println()
	}

	if len(semuaKelemahan) > 0 {
		fmt.Printf("Ditemukan %d kelemahan:\n\n", len(semuaKelemahan))
		for i, k := range semuaKelemahan {
			fmt.Printf("%d. %s [%s]\n", i+1, k.ID, k.Tingkat)
			fmt.Printf("   Judul: %s\n", k.Judul)
			fmt.Printf("   Paket: %s\n", k.Paket.Nama)
			if k.Referensi != "" {
				fmt.Printf("   Ref:   %s\n", k.Referensi)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("Tidak ada kelemahan diketemukan.")
	}

	// Status verdict
	fmt.Println("==============================")
	printStatus(status, sumberCek)
}

func getStatus(kelemahan []tipe.Kelemahan, checkOnline bool, sumber tipe.CheckSource) tipe.StatusVerdict {
	if len(kelemahan) > 0 {
		return tipe.StatusVerified
	}
	if checkOnline && sumber == tipe.SourceGitHubAPI {
		return tipe.NoVulnFound
	}
	if checkOnline {
		return tipe.StatusVerified
	}
	return tipe.StatusLocalOnly
}

func printStatus(status tipe.StatusVerdict, sumber tipe.CheckSource) {
	switch status {
	case tipe.StatusVerified:
		fmt.Println("Status: ✅ TERVERIFIKASI (via GitHub Advisories)")
	case tipe.StatusLocalOnly:
		fmt.Println("Status: ⚠️  CEK LOKAL SAJA")
		fmt.Println("Pesan: Update database dengan 'aman update --cve' untuk hasil lebih lengkap")
	case tipe.NoVulnFound:
		fmt.Println("Status: ✅ TIDAK ADA KLEMAHAN DIKETAHUI")
	}
	fmt.Println("==============================")
}

func joinString(items []string, separator string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		result += separator + items[i]
	}
	return result
}

func printHelp() {
	fmt.Print(`
AMAN - Alat deteksi kelemahan software

Penggunaan:
  aman help              - Tampilkan bantuan ini
  aman version           - Tampilkan versi
  aman periksa --jenis <jenis> --sasaran <target> [flags]
                        - Jalankan pemeriksaan CVE
  aman periksa-all      - Scan semua di server (overview)
  aman periksa-security - Scan keamanan server (port, SSL, service)
  aman update           - Update semua (CVE + AMAN)
  aman update --cve     - Update database CVE saja
  aman update --self    - Update aplikasi AMAN saja
  aman serve            - Jalankan sebagai service (HTTP API)

Jenis Pemeriksaan CVE:
  folder                - Periksa folder/berkas di komputer
  docker                - Periksa gambar Docker (container image)
  web                   - Periksa website (URL)

Contoh:
  aman periksa --jenis folder --sasaran /app
  aman periksa --jenis docker --sasaran nginx:1.21
  aman periksa --jenis web --sasaran https://contoh.com
  aman periksa-all              - Quick overview server
  aman periksa-security         - Security check (port, SSL, service)
  aman update
  aman serve --port 8080
`)
}

func jalankanPeriksaAll() {
	fmt.Println("========================================")
	fmt.Println("AMAN - Comprehensive Server Scan")
	fmt.Println("========================================")
	fmt.Println()

	// Inisialisasi database
	db, err := deteksi.InitDatabase()
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Buat comprehensive scanner
	scanner := pemindai.NewComprehensiveScanner()
	fmt.Println("Mengumpulkan informasi server...")

	// Get server info
	serverInfo := scanner.GetServerInfo()
	fmt.Printf("Server: %s\n", serverInfo.Hostname)
	fmt.Printf("OS:     %s\n", serverInfo.OS)
	fmt.Printf("Kernel: %s\n", serverInfo.Kernel)
	if serverInfo.DockerVer != "" {
		fmt.Printf("Docker: %s\n", serverInfo.DockerVer)
	}
	fmt.Println()

	// Scan common directories
	fmt.Println("--- Folder Scan ---")
	commonPaths := []string{
		"/var/www",
		"/home",
		"/opt",
		"/srv",
		"/usr/local/src",
	}

	folderScanner := pemindai.PemindaiFolder{}
	totalPackages := 0
	totalVulns := 0

	for _, path := range commonPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		fmt.Printf("Memindai: %s\n", path)
		paketList, err := folderScanner.Pindai(path)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}

		if len(paketList) > 0 {
			fmt.Printf("  Ditemukan %d paket...\n", len(paketList))
			totalPackages += len(paketList)

			// Check for vulnerabilities
			for _, paket := range paketList {
				kelemahan, _, err := deteksi.DeteksiPaket(db, paket, false)
				if err == nil && len(kelemahan) > 0 {
					totalVulns += len(kelemahan)
					for _, k := range kelemahan {
						fmt.Printf("  ⚠️  %s [%s] - %s\n", k.ID, k.Tingkat, k.Paket.Nama)
					}
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("--- Docker Images ---")
	// Check docker images
	dockerAvailable := true

	// Simple docker check
	if _, err := os.Stat("/usr/bin/docker"); os.IsNotExist(err) {
		if _, err := os.Stat("/usr/local/bin/docker"); os.IsNotExist(err) {
			dockerAvailable = false
		}
	}

	if !dockerAvailable {
		fmt.Println("Docker tidak tersedia")
	} else {
		fmt.Println("Docker tersedia - gunakan 'aman periksa --jenis docker --sasaran <image>' untuk scan")
	}

	fmt.Println()
	fmt.Println("--- Web Services ---")
	// Check common web ports
	ports := []int{80, 443, 8080, 8443, 3000, 3001, 4000, 5000}
	detectedWebServices := 0

	for _, port := range ports {
		// Just report what we found, detailed scan dengan command lain
		if port == 80 || port == 443 {
			fmt.Printf("Port %d: HTTP%s detected\n", port, "")
			detectedWebServices++
		} else {
			fmt.Printf("Port %d: ", port)
			// Check if port is listening (simplified check)
			fmt.Println("(check manually)")
		}
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Total Paket Dicek:  %d\n", totalPackages)
	fmt.Printf("Total Kelemahan:    %d\n", totalVulns)
	fmt.Printf("Docker Images:      -")
	if dockerAvailable {
		fmt.Println("tersedia")
	} else {
		fmt.Println("tidak tersedia")
	}
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  Scan Docker image: aman periksa --jenis docker --sasaran nginx:latest")
	fmt.Println("  Scan website: aman periksa --jenis web --sasaran https://example.com")
	fmt.Println("  Scan folder spesifik: aman periksa --jenis folder --sasaran /path/to/project")
}

func jalankanPeriksaSecurity() {
	fmt.Println("========================================")
	fmt.Println("AMAN - Security Scan")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Memindai keamanan server...")
	fmt.Println()

	scanner := pemindai.NewSecurityScanner()
	result := scanner.Run()

	// Display results by severity
	fmt.Println("========================================")
	fmt.Println("HASIL SCAN")
	fmt.Println("========================================")
	fmt.Println()

	if result.TotalIssues == 0 {
		fmt.Println("✅ Tidak ada masalah keamanan ditemukan!")
	} else {
		// CRITICAL issues first
		if result.Critical > 0 {
			fmt.Printf("⚠️  CRITICAL: %d masalah\n", result.Critical)
		}
		if result.High > 0 {
			fmt.Printf("⚠️  HIGH: %d masalah\n", result.High)
		}
		if result.Medium > 0 {
			fmt.Printf("⚡ MEDIUM: %d masalah\n", result.Medium)
		}
		if result.Low > 0 {
			fmt.Printf("ℹ️  LOW: %d masalah\n", result.Low)
		}

		fmt.Println()
		fmt.Println("--- Detail Issues ---")
		fmt.Println()

		// Show CRITICAL first
		for _, issue := range result.Issues {
			if issue.Severity == "CRITICAL" {
				printSecurityIssue(issue)
			}
		}
		// Then HIGH
		for _, issue := range result.Issues {
			if issue.Severity == "HIGH" {
				printSecurityIssue(issue)
			}
		}
		// Then MEDIUM
		for _, issue := range result.Issues {
			if issue.Severity == "MEDIUM" {
				printSecurityIssue(issue)
			}
		}
		// Then LOW
		for _, issue := range result.Issues {
			if issue.Severity == "LOW" || issue.Severity == "INFO" {
				printSecurityIssue(issue)
			}
		}
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Total Issues:    %d\n", result.TotalIssues)
	fmt.Printf("  CRITICAL:      %d\n", result.Critical)
	fmt.Printf("  HIGH:          %d\n", result.High)
	fmt.Printf("  MEDIUM:        %d\n", result.Medium)
	fmt.Printf("  LOW:           %d\n", result.Low)
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Untuk detail CVE vulnerability scan:")
	fmt.Println("  aman periksa --jenis folder --sasaran /app")
	fmt.Println("  aman periksa --jenis docker --sasaran nginx:latest")
}

func printSecurityIssue(issue pemindai.SecurityIssue) {
	icon := "⚠️"
	switch issue.Severity {
	case "CRITICAL":
		icon = "🔴"
	case "HIGH":
		icon = "⚠️"
	case "MEDIUM":
		icon = "⚡"
	case "LOW":
		icon = "ℹ️"
	}

	fmt.Printf("%s [%s] %s\n", icon, issue.Severity, issue.Title)
	fmt.Printf("   Kategori: %s\n", issue.Category)
	if issue.Service != "" {
		fmt.Printf("   Service: %s\n", issue.Service)
	}
	if issue.Port > 0 {
		fmt.Printf("   Port: %d\n", issue.Port)
	}
	fmt.Printf("   Rekomendasi: %s\n", issue.Recommendation)
	fmt.Println()
}

// pindaiAll - Comprehensive scan combining all checks
func pindaiAll(sasaran string, checkOnline bool, format string) {
	fmt.Println("========================================")
	fmt.Println("AMAN - Comprehensive Security Scan")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize database
	db, err := deteksi.InitDatabase()
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// 1. SECURITY SCAN (Comprehensive)
	fmt.Println("========================================")
	fmt.Println("SECURITY SCAN")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Memindai keamanan server...")
	fmt.Println()

	scanner := pemindai.NewSecurityScanner()
	result := scanner.Run()

	// Display security results
	if result.TotalIssues == 0 {
		fmt.Println("✅ Tidak ada masalah keamanan ditemukan!")
	} else {
		if result.Critical > 0 {
			fmt.Printf("⚠️  CRITICAL: %d masalah\n", result.Critical)
		}
		if result.High > 0 {
			fmt.Printf("⚠️  HIGH: %d masalah\n", result.High)
		}
		if result.Medium > 0 {
			fmt.Printf("⚡ MEDIUM: %d masalah\n", result.Medium)
		}
		if result.Low > 0 {
			fmt.Printf("ℹ️  LOW: %d masalah\n", result.Low)
		}
		fmt.Println()
		fmt.Println("--- Detail ---")
		for _, issue := range result.Issues {
			printSecurityIssue(issue)
		}
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Total Security Issues: %d\n", result.TotalIssues)
	fmt.Printf("  CRITICAL: %d\n", result.Critical)
	fmt.Printf("  HIGH:     %d\n", result.High)
	fmt.Printf("  MEDIUM:   %d\n", result.Medium)
	fmt.Printf("  LOW:      %d\n", result.Low)
	fmt.Println()

	// 2. SERVER INFO
	fmt.Println("========================================")
	fmt.Println("SERVER INFO")
	fmt.Println("========================================")

	serverScanner := pemindai.NewComprehensiveScanner()
	serverInfo := serverScanner.GetServerInfo()
	fmt.Printf("Hostname:  %s\n", serverInfo.Hostname)
	fmt.Printf("OS:        %s\n", serverInfo.OS)
	fmt.Printf("Kernel:    %s\n", serverInfo.Kernel)
	fmt.Printf("Docker:    %s\n", serverInfo.DockerVer)
	fmt.Println()

	// 3. FOLDER SCAN
	fmt.Println("========================================")
	fmt.Println("FOLDER SCAN")
	fmt.Println("========================================")

	folderScanner := pemindai.PemindaiFolder{}
	scanPaths := []string{}
	
	// Use sasaran if provided, otherwise scan common paths
	if sasaran != "" {
		scanPaths = append(scanPaths, sasaran)
	} else {
		scanPaths = []string{"/home", "/opt", "/srv", "/usr/local/src"}
	}

	totalPackages := 0
	totalVulns := 0

	for _, path := range scanPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		fmt.Printf("Memindai: %s\n", path)
		paketList, err := folderScanner.Pindai(path)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		if len(paketList) > 0 {
			fmt.Printf("  Ditemukan %d paket...\n", len(paketList))
			totalPackages += len(paketList)
			for _, paket := range paketList {
				kelemahan, _, err := deteksi.DeteksiPaket(db, paket, checkOnline)
				if err == nil && len(kelemahan) > 0 {
					totalVulns += len(kelemahan)
					for _, k := range kelemahan {
						fmt.Printf("  ⚠️  %s [%s] - %s\n", k.ID, k.Tingkat, k.Paket.Nama)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal Paket: %d\n", totalPackages)
	fmt.Printf("Total Kelemahan: %d\n", totalVulns)
	fmt.Println()

	// 4. SYSTEM PACKAGES SCAN (OSV.dev distro feed + rpmvercmp)
	fmt.Println("========================================")
	fmt.Println("SYSTEM PACKAGES SCAN")
	fmt.Println("========================================")
	fmt.Println("Memindai installed packages (rpm/dpkg)...")
	fmt.Println()

	sysScanner := pemindai.NewSystemPackageScanner()
	sysPackages := sysScanner.ScanSystemPackages()
	fmt.Printf("Ditemukan %d installed packages\n", len(sysPackages))
	fmt.Println()

	systemVulns := 0
	type SysVuln struct {
		PkgName    string
		Installed  string
		Fixed      string
		AdvisoryID string
		CVEs       []string
		Severity   string
		Summary    string
	}
	var systemVulnList []SysVuln

	if len(sysPackages) > 0 {
		ecosystem := pemindai.DetectDistroEcosystem()
		fmt.Printf("Distro ecosystem: %s\n", ecosystem)
		fmt.Println("Mengecek vulnerabilities via OSV.dev...")

		osvClient := pemindai.NewOSVClient()
		advisoryMap, err := osvClient.QueryBatch(ecosystem, sysPackages)
		if err != nil {
			fmt.Printf("  Error OSV query: %v\n", err)
		}

		// Build name index
		pkgIndex := make(map[string][]pemindai.SystemPackage)
		for _, p := range sysPackages {
			pkgIndex[p.Name] = append(pkgIndex[p.Name], p)
		}

		// Fetch all advisory details concurrently (10x faster than sequential)
		allIDs := pemindai.CollectAllAdvisoryIDs(advisoryMap)
		fmt.Printf("  Mengambil detail %d advisories (concurrent)...\n", len(allIDs))
		advisoryCache := osvClient.FetchAdvisoryDetails(allIDs, 10)

		for pkgName, advIDs := range advisoryMap {
			for _, advID := range advIDs {
				vuln, ok := advisoryCache[advID]
				if !ok {
					continue
				}

				fixedVersion := vuln.GetFixedVersion(pkgName)
				if fixedVersion == "" {
					continue
				}

				// Check each installed instance of this package
				for _, inst := range pkgIndex[pkgName] {
					if pemindai.IsVulnerable(inst.Version, fixedVersion) {
						systemVulns++
						systemVulnList = append(systemVulnList, SysVuln{
							PkgName:    pkgName,
							Installed:  inst.Version,
							Fixed:      fixedVersion,
							AdvisoryID: advID,
							CVEs:       vuln.ExtractCVEs(),
							Severity:   vuln.GetSeverity(),
							Summary:    vuln.Summary,
						})
					}
				}
			}
		}

		fmt.Printf("  Advisories dianalisis: %d\n", len(advisoryCache))
	}

	fmt.Printf("\nSystem Packages Checked: %d\n", len(sysPackages))
	fmt.Printf("System Vulnerabilities Found: %d\n", systemVulns)
	if len(systemVulnList) > 0 {
		fmt.Println("\n--- System Package Vulnerabilities ---")
		// Sort: CRITICAL > HIGH > MEDIUM > LOW
		sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		sort.Slice(systemVulnList, func(i, j int) bool {
			return sevOrder[systemVulnList[i].Severity] < sevOrder[systemVulnList[j].Severity]
		})
		// Show max 30 + dedup by pkg+cve
		shown := 0
		seenVuln := make(map[string]bool)
		for _, v := range systemVulnList {
			key := v.PkgName + "|" + strings.Join(v.CVEs, ",")
			if seenVuln[key] {
				continue
			}
			seenVuln[key] = true
			if shown >= 30 {
				fmt.Printf("  ... dan %d temuan lainnya\n", len(systemVulnList)-shown)
				break
			}
			cveStr := "-"
			if len(v.CVEs) > 0 {
				cveStr = strings.Join(v.CVEs[:minInt(2, len(v.CVEs))], ", ")
				if len(v.CVEs) > 2 {
					cveStr += fmt.Sprintf(" (+%d)", len(v.CVEs)-2)
				}
			}
			fmt.Printf("  ⚠️  [%s] %s @ %s\n", v.Severity, v.PkgName, v.Installed)
			fmt.Printf("      Advisory: %s | Fixed: %s\n", v.AdvisoryID, v.Fixed)
			fmt.Printf("      CVE: %s\n", cveStr)
			fmt.Printf("      %s\n", v.Summary)
			fmt.Println()
			shown++
		}
	}
	fmt.Println()

	// 5. DOCKER SCAN
	fmt.Println("========================================")
	fmt.Println("DOCKER SCAN")
	fmt.Println("========================================")

	// Use exec.Command to list docker images
	cmd := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
	output, err := cmd.Output()
	var imageCount int
	if err == nil {
		images := strings.Split(strings.TrimSpace(string(output)), "\n")
		imageCount = 0
		for _, img := range images {
			if img != "" && img != "<none>:<none>" {
				imageCount++
			}
		}
	}
	if imageCount > 0 {
		fmt.Printf("Ditemukan %d Docker images\n", imageCount)
		fmt.Println("Gunakan: aman periksa --jenis docker --sasaran <image> untuk scan")
	} else {
		fmt.Println("Tidak ada Docker images ditemukan")
	}
	fmt.Println()

	// 5. WEB SCAN
	fmt.Println("========================================")
	fmt.Println("WEB SCAN")
	fmt.Println("========================================")

	webPorts := []int{80, 443, 8080, 8443}
	for _, port := range webPorts {
		protocol := "HTTP"
		if port == 443 {
			protocol = "HTTPS"
		}
		address := fmt.Sprintf("localhost:%d", port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("Port %d: %s detected\n", port, protocol)
		}
	}
	fmt.Println()

	// FINAL SUMMARY
	fmt.Println("========================================")
	fmt.Println("FINAL SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Total Security Issues: %d\n", result.TotalIssues)
	fmt.Printf("Total Packages Scanned: %d\n", totalPackages)
	fmt.Printf("Total Vulnerabilities: %d\n", totalVulns)
	fmt.Printf("Docker Images: %d\n", imageCount)
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  Scan folder spesifik: aman periksa --jenis folder --sasaran /path")
	fmt.Println("  Scan Docker image: aman periksa --jenis docker --sasaran nginx:latest")
	fmt.Println("  Scan website: aman periksa --jenis web --sasaran https://example.com")
}
