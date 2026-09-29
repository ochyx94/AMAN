package main

import (
	"fmt"
	"os"
	"time"

	"aman/pkg/deteksi"
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
	default:
		fmt.Printf("Perintah tidak dikenal: %s\n", os.Args[1])
		fmt.Println("Ketik 'aman help' untuk bantuan.")
		os.Exit(1)
	}
}

func jalankanPeriksa() {
	var jenis string
	var sasaran string

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
		pindaiFolder(sasaran)
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

func pindaiFolder(sasaran string) {
	fmt.Printf("Memindai folder: %s\n", sasaran)
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
	for _, paket := range paketList {
		kelemahan, err := deteksi.DeteksiPaket(db, paket)
		if err != nil {
			fmt.Printf("Warning: gagal cek kelemahan untuk %s: %v\n", paket.Nama, err)
			continue
		}
		semuaKelemahan = append(semuaKelemahan, kelemahan...)
	}

	// Tampilkan hasil
	fmt.Printf("Ditemukan %d paket\n\n", len(paketList))

	if len(semuaKelemahan) > 0 {
		fmt.Printf("Ditemukan %d kelemahan:\n\n", len(semuaKelemahan))
		for i, k := range semuaKelemahan {
			fmt.Printf("%d. %s\n", i+1, k.ID)
			fmt.Printf("   Judul: %s\n", k.Judul)
			fmt.Printf("   Tingkat: %s\n", k.Tingkat)
			fmt.Printf("   Paket: %s\n\n", k.Paket.Nama)
		}
	} else {
		fmt.Println("Tidak ada kelemahan diketemukan di database lokal.")
		fmt.Println("Catatan: Hasil ini berdasarkan database lokal saja.")
		fmt.Println("Untuk hasil lebih lengkap, butuh koneksi ke GitHub Advisories.")
	}

	fmt.Println("==============================")
}

func printHelp() {
	fmt.Println(`
AMAN - Alat deteksi kelemahan software

Penggunaan:
  aman help              - Tampilkan bantuan ini
  aman version           - Tampilkan versi
  aman periksa --jenis <jenis> --sasaran <target>
                        - Jalankan pemeriksaan

Jenis pemeriksaan:
  folder                - Periksa folder/berkas di komputer
  docker                - Periksa gambar turun (container image)
  web                   - Periksa alamat website

Contoh:
  aman periksa --jenis folder --sasaran /app
  aman periksa --jenis docker --sasaran nginx:1.21
  aman periksa --jenis web --sasaran https://contoh.com
`)
}
