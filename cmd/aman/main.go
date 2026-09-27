package main

import (
	"fmt"
	"os"
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
	default:
		fmt.Printf("Perintah tidak dikenal: %s\n", os.Args[1])
		fmt.Println("Ketik 'aman help' untuk bantuan.")
		os.Exit(1)
	}
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
  docker                - Periksa gambar turun (container image)
  folder                - Periksa folder/berkas di komputer
  web                   - Periksa alamat website

Contoh:
  aman periksa --jenis folder --sasaran /app
  aman periksa --jenis docker --sasaran nginx:1.21
  aman periksa --jenis web --sasaran https://contoh.com
`)
}
