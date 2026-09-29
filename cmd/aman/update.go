package main

import (
	"fmt"
	"os"
	"time"

	"aman/pkg/db"
)

func jalankanUpdate() {
	var ecosystem string

	// Parse arguments
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ecosystem", "-e":
			if i+1 < len(args) {
				ecosystem = args[i+1]
				i++
			}
		}
	}

	if ecosystem == "" {
		fmt.Println("Error: --ecosystem wajib diisi")
		fmt.Println("Contoh: aman update --ecosystem npm")
		fmt.Println("Ecosystem yang tersedia: npm, pip, go, rubygems, cargo, maven, nuget")
		os.Exit(1)
	}

	fmt.Printf("Mengupdate database untuk ecosystem: %s\n", ecosystem)
	fmt.Println("==============================")

	// Inisialisasi database
	database, err := db.InitDB("aman.db")
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Buat updater
	updater := db.NewUpdater()

	mulai := time.Now()

	// Update dari GitHub (lebih cepat dan gratis)
	fmt.Println("Mengupdate dari GitHub Advisories...")
	err = updater.UpdateFromGitHub(database, ecosystem)
	if err != nil {
		fmt.Printf("Warning: Gagal update dari GitHub: %v\n", err)
		fmt.Println("Mencoba NVD...")
		
		err = updater.UpdateFromNVD(database, ecosystem)
		if err != nil {
			fmt.Printf("Error: Gagal update dari NVD: %v\n", err)
			os.Exit(1)
		}
	}

	durasi := time.Since(mulai).Seconds()

	// Hitung jumlah CVE
	var jumlah int
	database.QueryRow("SELECT COUNT(*) FROM kelemahan WHERE LOWER(paket) LIKE LOWER(?)", "%"+ecosystem+"%").Scan(&jumlah)

	fmt.Println("==============================")
	fmt.Printf("Update selesai dalam %.2f detik\n", durasi)
	fmt.Printf("Total kelemahan untuk %s: %d\n", ecosystem, jumlah)
	fmt.Println()
	fmt.Println("Catatan: Gunakan 'aman periksa --jenis folder --sasaran /app' untuk scan")
}
