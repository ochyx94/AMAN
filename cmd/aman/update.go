package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"aman/pkg/db"
	"aman/pkg/output"
)

// Ecosystems yang didukung
var ecosystems = []string{
	"npm",
	"pip",
	"go",
	"rubygems",
	"cargo",
	"maven",
	"nuget",
}

func jalankanUpdate() {
	var ecosystem string
	var updateCVE bool
	var updateSelf bool
	var updateAll bool

	// Parse arguments
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ecosystem", "-e":
			if i+1 < len(args) {
				ecosystem = args[i+1]
				i++
			}
		case "--cve", "--db":
			updateCVE = true
		case "--self", "--aman":
			updateSelf = true
		case "--all", "-a":
			updateAll = true
		}
	}

	// Default: jika tidak ada flag, tampilkan help
	if !updateCVE && !updateSelf && !updateAll && ecosystem == "" {
		printUpdateHelp()
		return
	}

	// Update All jika --all atau tidak ada flag khusus
	if updateAll || (ecosystem == "" && !updateCVE && !updateSelf) {
		// Update semua: CVE + AMAN
		updateCVE = true
		updateSelf = true
	}

	fmt.Println("==========================================")
	fmt.Println("AMAN Updater")
	fmt.Println("==========================================")
	fmt.Println()

	// Update CVE Database
	if updateCVE || ecosystem != "" {
		updateCVEDatabase(ecosystem)
	}

	// Update AMAN Application
	if updateSelf {
		updateAmanSelf()
	}

	fmt.Println("==========================================")
	fmt.Println("Update selesai")
	fmt.Println("==========================================")
}

func updateCVEDatabase(ecosystem string) {
	fmt.Println("[1] UPDATE DATABASE CVE")
	fmt.Println("------------------------------")

	// Inisialisasi database
	database, err := db.InitDB("aman.db")
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		return
	}
	defer database.Close()

	// Buat updater
	updater := db.NewUpdater()

	// Tentukan ekosistem yang akan diupdate
	var toUpdate []string
	if ecosystem != "" {
		toUpdate = []string{ecosystem}
		fmt.Printf("Mengupdate ecosystem: %s\n\n", ecosystem)
	} else {
		toUpdate = ecosystems
		fmt.Println("Mengupdate semua ecosystem...")
		fmt.Println()
	}

	totalCVE := 0
	mulaiTotal := time.Now()

	for _, eco := range toUpdate {
		fmt.Printf("[%s] ", eco)
		mulai := time.Now()

		// Update dari GitHub
		err := updater.UpdateFromGitHub(database, eco)
		if err != nil {
			fmt.Printf("GAGAL: %v\n", err)
			continue
		}

		// Hitung jumlah CVE
		var jumlah int
		database.QueryRow("SELECT COUNT(*) FROM kelemahan").Scan(&jumlah)

		durasi := time.Since(mulai).Seconds()
		fmt.Printf("OK (%d CVE, %.1fs)\n", jumlah, durasi)
		totalCVE += jumlah
	}

	durasiTotal := time.Since(mulaiTotal).Seconds()

	fmt.Println()
	fmt.Printf("CVE Database update selesai dalam %.2f detik\n", durasiTotal)
	fmt.Println()
}

func updateAmanSelf() {
	fmt.Println("[2] UPDATE APPLICATION AMAN")
	fmt.Println("------------------------------")

	// Cek versi terbaru
	fmt.Println("Mengecek versi terbaru...")

	latestVersion, downloadURL, err := cekVersiTerbaru()
	if err != nil {
		fmt.Printf("Gagal cek versi: %v\n", err)
		fmt.Println(" Pastikan koneksi internet aktif.")
		return
	}

	currentVersion := output.Version

	// Bandingkan versi
	if latestVersion == "" {
		fmt.Println("Tidak bisa mendapatkan versi terbaru.")
		return
	}

	fmt.Printf("Versi saat ini: %s\n", currentVersion)
	fmt.Printf("Versi terbaru:  %s\n", latestVersion)

	// Parse dan bandingkan versi
	if compareVersions(currentVersion, latestVersion) >= 0 {
		fmt.Println()
		fmt.Println(" Anda sudah menggunakan versi terbaru!")
		return
	}

	fmt.Println()
	fmt.Printf("Versi baru tersedia! Downloading...\n")

	// Download versi terbaru
	err = downloadDanInstall(latestVersion, downloadURL)
	if err != nil {
		fmt.Printf("Gagal download: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Printf(" Berhasil! AMAN sekarang versi %s\n", latestVersion)
}

func printUpdateHelp() {
	fmt.Print(`
AMAN Update - Update Database CVE dan Aplikasi

Penggunaan:
  aman update                  - Update semua (CVE + AMAN)
  aman update --all           - Update semua (CVE + AMAN)
  aman update --cve           - Update database CVE saja
  aman update --self          - Update aplikasi AMAN saja
  aman update --ecosystem npm - Update CVE untuk ecosystem tertentu

Contoh:
  aman update                 # Update semuanya
  aman update --cve           # Hanya CVE database
  aman update --self          # Hanya AMAN aplikasi
  aman update --ecosystem npm # Hanya CVE untuk npm
`)
}

func cekVersiTerbaru() (string, string, error) {
	// Cek GitHub API untuk releases terbaru
	url := "https://api.github.com/repos/ochyx94/AMAN/releases/latest"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", "", fmt.Errorf("belum ada release di GitHub (hubungi admin atau update manual)")
	}
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	err = json.Unmarshal(body, &release)
	if err != nil {
		return "", "", err
	}

	// Cari binary untuk Linux amd64
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == "aman" || asset.Name == "aman_linux_amd64" {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	return release.TagName, downloadURL, nil
}

func compareVersions(current, latest string) int {
	// Simple version comparison
	// Returns: -1 if current < latest, 0 if equal, 1 if current > latest

	re := regexp.MustCompile(`[vV]?(\d+)\.(\d+)\.(\d+)`)

	cMatch := re.FindStringSubmatch(current)
	lMatch := re.FindStringSubmatch(latest)

	if cMatch == nil || lMatch == nil {
		return 0
	}

	c1, _ := strconv.Atoi(cMatch[1])
	c2, _ := strconv.Atoi(cMatch[2])
	c3, _ := strconv.Atoi(cMatch[3])

	l1, _ := strconv.Atoi(lMatch[1])
	l2, _ := strconv.Atoi(lMatch[2])
	l3, _ := strconv.Atoi(lMatch[3])

	if c1 < l1 {
		return -1
	}
	if c1 > l1 {
		return 1
	}
	if c2 < l2 {
		return -1
	}
	if c2 > l2 {
		return 1
	}
	if c3 < l3 {
		return -1
	}
	if c3 > l3 {
		return 1
	}
	return 0
}

func downloadDanInstall(version, url string) error {
	if url == "" {
		// Fallback: build dari source
		fmt.Println("  Downloading source code...")
		return nil
	}

	fmt.Printf("  Downloading from: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Download failed: %d", resp.StatusCode)
	}

	// Simpan ke file temporary
	tmpFile := "/tmp/aman_new"
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// Set executable
	os.Chmod(tmpFile, 0755)

	// Replace binary lama
	currentBinary, err := os.Executable()
	if err != nil {
		return err
	}

	err = os.Rename(tmpFile, currentBinary)
	if err != nil {
		return err
	}

	return nil
}
