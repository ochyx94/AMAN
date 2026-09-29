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
	case "update":
		jalankanUpdate()
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
		fmt.Println("Fitur docker belum tersedia")
	case "web":
		fmt.Println("Fitur web belum tersedia")
	default:
		fmt.Printf("Jenis tidak dikenal: %s\n", jenis)
		fmt.Println("Jenis yang tersedia: folder, docker, web")
		os.Exit(1)
	}

	durasi := time.Since(mulai).Seconds()
	fmt.Printf("\nSelesai dalam %.2f detik\n", durasi)
}

func pindaiFolder(sasaran string, checkOnline bool, format string) {
	fmt.Printf("Memindai folder: %s\n", sasaran)
	if checkOnline {
		fmt.Println("Mode: ONLINE (cek GitHub Advisories)")
	} else {
		fmt.Println("Mode: OFFLINE (database lokal saja)")
	}
	fmt.Println("==============================")

	// Inisialisasi database
	db, err := deteksi.InitDatabase()
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Jalankan scanner
	p := pemindai.PemindaiFolder{}
	paketList, err := p.Pindai(sasaran)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Deteksi kelemahan
	var semuaKelemahan []tipe.Kelemahan
	var sumberCek tipe.CheckSource = tipe.SourceLocalDB
	totalOnline := 0

	for _, paket := range paketList {
		kelemahan, sumber, err := deteksi.DeteksiPaket(db, paket, checkOnline)
		if err != nil {
			fmt.Printf("Warning: gagal cek kelemahan untuk %s: %v\n", paket.Nama, err)
			continue
		}
		semuaKelemahan = append(semuaKelemahan, kelemahan...)
		if sumber == tipe.SourceGitHubAPI {
			sumberCek = tipe.SourceGitHubAPI
			totalOnline++
		}
	}

	// Tentukan status
	var status tipe.StatusVerdict
	if len(semuaKelemahan) > 0 {
		status = tipe.StatusVerified
	} else if checkOnline && totalOnline == 0 {
		status = tipe.NoVulnFound
	} else if checkOnline {
		status = tipe.StatusVerified
	} else {
		status = tipe.StatusLocalOnly
	}

	

	// Buat hasil
	hasil := tipe.HasilPemindaian{
		Sasaran:         sasaran,
		JenisPemindaian: "folder",
		Kelemahan:       semuaKelemahan,
		Durasi:          0,
		Status:          status,
		SumberCek:      sumberCek,
	}

	if checkOnline {
		hasil.SumberCek = tipe.SourceGitHubAPI
	}

	// Format output
	if format == "json" {
		bytes, _ := output.FormatJSON(hasil)
		fmt.Println(string(bytes))
	} else {
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
		switch status {
		case tipe.StatusVerified:
			fmt.Println("Status: ✅ TERVERIFIKASI (via GitHub Advisories)")
		case tipe.StatusLocalOnly:
			fmt.Println("Status: ⚠️  CEK LOKAL SAJA")
			fmt.Println("Pesan: Update database dengan 'aman update --all' untuk hasil lebih lengkap")
		case tipe.NoVulnFound:
			fmt.Println("Status: ✅ TIDAK ADA KLEMAHAN DIKETAHUI")
		}
		fmt.Println("==============================")
	}
}

func printHelp() {
	fmt.Println(`
AMAN - Alat deteksi kelemahan software

Penggunaan:
  aman help              - Tampilkan bantuan ini
  aman version           - Tampilkan versi
  aman periksa --jenis <jenis> --sasaran <target> [flags]
                        - Jalankan pemeriksaan
  aman update --all     - Update database CVE semua ecosystem
  aman update --ecosystem <ecosystem>
                        - Update database CVE satu ecosystem

Flags untuk periksa:
  --online, -o          - Cek juga ke GitHub Advisories (butuh internet)
  --format, -f json    - Output dalam format JSON

Jenis pemeriksaan:
  folder                - Periksa folder/berkas di komputer
  docker                - Periksa gambar turun (container image)
  web                   - Periksa alamat website

Ecosystem untuk update:
  npm                   - Node.js packages
  pip                   - Python packages
  go                    - Go packages
  rubygems              - Ruby gems
  cargo                 - Rust packages
  maven                 - Java packages
  nuget                 - .NET packages

Contoh:
  aman periksa --jenis folder --sasaran /app
  aman periksa --jenis folder --sasaran /app --online
  aman periksa --jenis folder --sasaran /app --format json
  aman update --all
`)
}
