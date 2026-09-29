package main

import (
	"fmt"
	"os"
	"time"

	"aman/pkg/pemindai"
)

// Version AMAN
const Version = "1.0.0"

func main() {
	// kalau tidak ada argument, tampilkan bantuan
	if len(os.Args) == 1 {
		printHelp()
		os.Exit(0)
	}

	// cek argument
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

	// hitung durasi
	durasi := time.Since(mulai).Seconds()
	fmt.Printf("\nSelesai dalam %.2f detik\n", durasi)
}

func pindaiFolder(sasaran string) {
	fmt.Printf("Memindai folder: %s\n", sasaran)
	fmt.Println("==============================")

	p := pemindai.PemindaiFolder{}
	paketList, err := p.Pindai(sasaran)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(paketList) == 0 {
		fmt.Println("Tidak ditemukan paket.")
		return
	}

	fmt.Printf("Ditemukan %d paket:\n\n", len(paketList))

	for i, pake := range paketList {
		fmt.Printf("%d. %s (%s)\n", i+1, pake.Nama, pake.Jenis)
		fmt.Printf("   Lokasi: %s\n", pake.Lokasi)
		fmt.Printf("   Versi: %s\n\n", pake.Versi)
	}

	// Untuk sekarang, tampilkan placeholder kelemahan
	fmt.Println("==============================")
	fmt.Println("Kelemahan: (belum ada deteksi)")
	fmt.Println("Untuk deteksi kelemahan, perlu tambahan database kelemahan.")
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
