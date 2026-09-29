package db

import (
	"database/sql"
	"strings"

	"aman/pkg/tipe"
)

// QueryKelemahan mencari kelemahan berdasarkan nama paket
func QueryKelemahan(database *sql.DB, paketNama string) ([]tipe.Kelemahan, error) {
	rows, err := database.Query(`
		SELECT id, judul, penjelasan, tingkat, paket, versi_aman, referensi
		FROM kelemahan
		WHERE LOWER(paket) = LOWER(?)
	`, paketNama)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var kelemahan []tipe.Kelemahan
	for rows.Next() {
		var k tipe.Kelemahan
		var versiAman, refs sql.NullString
		err := rows.Scan(&k.ID, &k.Judul, &k.Penjelasan, &k.Tingkat, &k.Paket.Nama, &versiAman, &refs)
		if err != nil {
			return nil, err
		}
		if versiAman.Valid {
			k.VersiAman = versiAman.String
		}
		if refs.Valid {
			k.Referensi = refs.String
		}
		k.Tingkat = tipe.TingkatDanger(k.Tingkat)
		kelemahan = append(kelemahan, k)
	}

	return kelemahan, nil
}

// QueryKonfigurasiSalah mencari kelemahan konfigurasi
func QueryKonfigurasiSalah(database *sql.DB, filePath string) ([]tipe.Kelemahan, error) {
	// Cek apakah file match dengan pattern
	rows, err := database.Query(`
		SELECT id, nama, penjelasan, tingkat, matcher, referensi
		FROM konfigurasi_salah
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var kelemahan []tipe.Kelemahan
	for rows.Next() {
		var id, nama, penjelasan, tingkat, matcher, refs string
		err := rows.Scan(&id, &nama, &penjelasan, &tingkat, &matcher, &refs)
		if err != nil {
			return nil, err
		}

		// Cek pattern
		if matchFilePattern(filePath, matcher) {
			kelemahan = append(kelemahan, tipe.Kelemahan{
				ID:         id,
				Judul:      nama,
				Penjelasan: penjelasan,
				Tingkat:    tipe.TingkatDanger(tingkat),
				Referensi:  refs,
			})
		}
	}

	return kelemahan, nil
}

// matchFilePattern cek apakah file cocok dengan pattern
func matchFilePattern(filePath, pattern string) bool {
	// Pattern bisa: "*.env", "*.py,*.js", dll
	patterns := strings.Split(pattern, ",")
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "*.") {
			ext := p[1:] // ".env"
			if strings.HasSuffix(filePath, ext) {
				return true
			}
		}
	}
	return false
}
