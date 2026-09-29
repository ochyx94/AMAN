package deteksi

import (
	"database/sql"

	"aman/pkg/db"
	"aman/pkg/tipe"
)

// DeteksiPaket mengecek paket terhadap database
func DeteksiPaket(databaseConn *sql.DB, paket tipe.Paket) ([]tipe.Kelemahan, error) {
	var kelemahan []tipe.Kelemahan

	// Cek database lokal
	dbKelemahan, err := db.QueryKelemahan(databaseConn, paket.Nama)
	if err != nil {
		return nil, err
	}
	kelemahan = append(kelemahan, dbKelemahan...)

	return kelemahan, nil
}

// DeteksiFile mengecek file terhadap konfigurasi salah
func DeteksiFile(databaseConn *sql.DB, filePath string) ([]tipe.Kelemahan, error) {
	var kelemahan []tipe.Kelemahan

	// Cek konfigurasi salah
	dbKelemahan, err := db.QueryKonfigurasiSalah(databaseConn, filePath)
	if err != nil {
		return nil, err
	}
	kelemahan = append(kelemahan, dbKelemahan...)

	return kelemahan, nil
}

// InitDatabase inisialisasi database dan seed data
func InitDatabase() (*sql.DB, error) {
	database, err := db.InitDB("aman.db")
	if err != nil {
		return nil, err
	}

	// Seed data jika belum ada
	err = db.SeedData(database)
	if err != nil {
		return nil, err
	}

	return database, nil
}
