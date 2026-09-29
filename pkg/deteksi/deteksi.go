package deteksi

import (
	"database/sql"

	"aman/pkg/db"
	"aman/pkg/github"
	"aman/pkg/tipe"
)

// DeteksiPaket mengecek paket terhadap database lokal + GitHub
func DeteksiPaket(database *sql.DB, paket tipe.Paket, checkOnline bool) ([]tipe.Kelemahan, tipe.CheckSource, error) {
	var kelemahan []tipe.Kelemahan
	sumber := tipe.SourceLocalDB

	// Cek database lokal dulu
	dbKelemahan, err := db.QueryKelemahan(database, paket.Nama)
	if err != nil {
		return nil, tipe.SourceNone, err
	}
	kelemahan = append(kelemahan, dbKelemahan...)

	// Jika tidak ada di lokal dan checkOnline=true, cek GitHub
	if len(kelemahan) == 0 && checkOnline {
		sumber = tipe.SourceGitHubAPI
		
		// Buat GitHub client
		client := github.NewClient()
		
		// Cari advisory berdasarkan ecosystem
		ecosystem := getEcosystemAlias(paket.Jenis)
		if ecosystem == "" {
			ecosystem = "npm" // default
		}
		
		// Search advisory
		advisory, err := client.SearchAdvisory(ecosystem, paket.Nama)
		if err == nil && advisory != nil {
			// Convert ke Kelemahan
			for _, v := range advisory.Vulnerabilities {
				kel := tipe.Kelemahan{
					ID:          advisory.GHSAID,
					Judul:      advisory.Summary,
					Penjelasan: advisory.Description,
					Tingkat:    tipe.TingkatDanger(advisory.Severity),
					Paket:      paket,
					VersiAman:  v.FirstPatchedVersion,
					Referensi:  getFirstReference(advisory.References),
					Sumber:     tipe.SourceGitHubAPI,
				}
				kelemahan = append(kelemahan, kel)
			}
		}
		
		// Jika tidak ada hasil dari GitHub, kosongkan sumber
		if len(kelemahan) == 0 {
			sumber = tipe.SourceNone
		}
	}

	// Set sumber untuk semua kelemahan
	for i := range kelemahan {
		kelemahan[i].Sumber = sumber
	}

	return kelemahan, sumber, nil
}

// DeteksiFile mengecek file terhadap konfigurasi salah
func DeteksiFile(database *sql.DB, filePath string) ([]tipe.Kelemahan, error) {
	var kelemahan []tipe.Kelemahan

	dbKelemahan, err := db.QueryKonfigurasiSalah(database, filePath)
	if err != nil {
		return nil, err
	}
	kelemahan = append(kelemahan, dbKelemahan...)

	return kelemahan, nil
}

// getEcosystemAlias konversi jenis paket ke ecosystem GitHub
func getEcosystemAlias(jenis string) string {
	switch jenis {
	case "npm":
		return "npm"
	case "pip":
		return "pip"
	case "go":
		return "go"
	case "gem", "rubygems":
		return "rubygems"
	case "cargo", "rust":
		return "cargo"
	case "maven", "java":
		return "maven"
	case "nuget", "dotnet":
		return "nuget"
	default:
		return ""
	}
}

// getFirstReference ambil referensi pertama
func getFirstReference(refs []struct {
	URL string `json:"url"`
}) string {
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}

// InitDatabase inisialisasi database dan seed data
func InitDatabase() (*sql.DB, error) {
	database, err := db.InitDB("aman.db")
	if err != nil {
		return nil, err
	}

	err = db.SeedData(database)
	if err != nil {
		return nil, err
	}

	return database, nil
}
