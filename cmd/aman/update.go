package main

import (
	"fmt"
	"os"
	"time"

	"aman/pkg/db"
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
	var all bool

	// Parse arguments
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ecosystem", "-e":
			if i+1 < len(args) {
				ecosystem = args[i+1]
				i++
			}
		case "--all", "-a":
			all = true
		}
	}

	// Inisialisasi database
	database, err := db.InitDB("aman.db")
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Buat updater
	updater := db.NewUpdater()

	// Tentukan ekosistem yang akan diupdate
	var toUpdate []string
	if all || ecosystem == "" {
		toUpdate = ecosystems
		fmt.Println("Mengupdate SEMUA ecosystem...")
	} else {
		toUpdate = []string{ecosystem}
		fmt.Printf("Mengupdate ecosystem: %s\n", ecosystem)
	}

	fmt.Println("==============================")
	fmt.Printf("Total: %d ecosystem\n\n", len(toUpdate))

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

		// Hitung jumlah CVE untuk ecosystem ini
		var jumlah int
		database.QueryRow("SELECT COUNT(*) FROM kelemahan WHERE LOWER(?) LIKE LOWER('%' || LOWER(paket) || '%')", eco).Scan(&jumlah)
		// Alternative query
		database.QueryRow("SELECT COUNT(*) FROM kelemahan").Scan(&jumlah)

		durasi := time.Since(mulai).Seconds()
		fmt.Printf("OK (%d CVE, %.1fs)\n", jumlah, durasi)
		totalCVE += jumlah
	}

	durasiTotal := time.Since(mulaiTotal).Seconds()

	fmt.Println()
	fmt.Println("==============================")
	fmt.Printf("Update selesai dalam %.2f detik\n", durasiTotal)
	fmt.Printf("Total CVE di database: %d\n", totalCVE)
	fmt.Println()
	fmt.Println("Contoh penggunaan:")
	fmt.Println("  aman periksa --jenis folder --sasaran /app")
}
