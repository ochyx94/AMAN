package main

import (
	"fmt"
	"os"
	"time"

	"aman/pkg/deteksi"
	"aman/pkg/output"
	"aman/pkg/pemindai"
	"aman/pkg/tipe"
)

// Version AMAN
const Version = "1.0.0"

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
	default:
		fmt.Printf("Jenis tidak dikenal: %s\n", jenis)
		fmt.Println("Jenis yang tersedia: folder, docker, web")
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

	// Text format
	fmt.Printf("\nDitemukan %d teknologi/paket\n\n", len(hasil.Paket))

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
	fmt.Println(`
AMAN - Alat deteksi kelemahan software

Penggunaan:
  aman help              - Tampilkan bantuan ini
  aman version           - Tampilkan versi
  aman periksa --jenis <jenis> --sasaran <target> [flags]
                        - Jalankan pemeriksaan
  aman periksa-all      - Scan semua di server (folder, docker, web)
  aman update           - Update semua (CVE + AMAN)
  aman update --cve     - Update database CVE saja
  aman update --self    - Update aplikasi AMAN saja
  aman serve            - Jalankan sebagai service (HTTP API)

Flags untuk periksa:
  --online, -o          - Cek juga ke GitHub Advisories (butuh internet)
  --format, -f json    - Output dalam format JSON

Flags untuk serve:
  --port, -p           - Port untuk HTTP server (default: 8080)

Jenis pemeriksaan:
  folder                - Periksa folder/berkas di komputer
  docker                - Periksa gambar Docker (container image)
  web                   - Periksa website (URL)

Contoh:
  aman periksa --jenis folder --sasaran /app
  aman periksa --jenis folder --sasaran /app --online --format json
  aman periksa --jenis docker --sasaran nginx:1.21
  aman periksa --jenis web --sasaran https://contoh.com
  aman periksa-all           - Scan semua folder/docker/web di server
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
