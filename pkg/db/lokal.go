package db

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// InitDB membuat database SQLite dan tabel jika belum ada
func InitDB(namaFile string) (*sql.DB, error) {
	// Buat folder jika belum ada
	folder := os.Getenv("HOME") + "/.aman"
	os.MkdirAll(folder, 0755)

	// Buka atau buat database
	db, err := sql.Open("sqlite3", folder+"/"+namaFile)
	if err != nil {
		return nil, err
	}

	// Buat tabel jika belum ada
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS kelemahan (
			id TEXT PRIMARY KEY,
			judul TEXT NOT NULL,
			penjelasan TEXT,
			tingkat TEXT NOT NULL,
			paket TEXT NOT NULL,
			pattern TEXT,
			versi_aman TEXT,
			referensi TEXT
		);

		CREATE TABLE IF NOT EXISTS konfigurasi_salah (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			nama TEXT NOT NULL,
			penjelasan TEXT NOT NULL,
			tingkat TEXT NOT NULL,
			file_pattern TEXT NOT NULL,
			matcher TEXT NOT NULL,
			referensi TEXT
		);
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// InsertKelemahanInput adalah data untuk input kelemahan
type InsertKelemahanInput struct {
	ID         string
	Judul      string
	Penjelasan string
	Tingkat    string
	Paket      string
	Pattern     string
	VersiAman  string
	Referensi   string
}

// InsertKelemahan menambahkan kelemahan ke database
func InsertKelemahan(db *sql.DB, input InsertKelemahanInput) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO kelemahan 
		(id, judul, penjelasan, tingkat, paket, pattern, versi_aman, referensi)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		input.ID, input.Judul, input.Penjelasan, input.Tingkat,
		input.Paket, input.Pattern, input.VersiAman, input.Referensi)
	return err
}

// InsertKonfigurasiSalah menambahkan kelemahan konfigurasi
func InsertKonfigurasiSalah(db *sql.DB, nama, penjelasan, tingkat, filePattern, matcher, referensi string) error {
	_, err := db.Exec(`
		INSERT INTO konfigurasi_salah 
		(nama, penjelasan, tingkat, file_pattern, matcher, referensi)
		VALUES (?, ?, ?, ?, ?, ?)`,
		nama, penjelasan, tingkat, filePattern, matcher, referensi)
	return err
}
