package tipe

// TingkatDanger menunjukkan seberapa parah kelemahan
type TingkatDanger string

const (
	DangerRendah       TingkatDanger = "Rendah"
	DangerSedang       TingkatDanger = "Sedang"
	DangerParah        TingkatDanger = "Parah"
	DangerSangatParah TingkatDanger = "Sangat Parah"
)

// StatusVerdict adalah status hasil scan
type StatusVerdict string

const (
	// Verified = dicek dari GitHub Advisories (paling akurat)
	StatusVerified StatusVerdict = "VERIFIED"
	// LocalOnly = hanya dari database lokal
	StatusLocalOnly StatusVerdict = "LOCAL_ONLY"
	// Unchecked = belum dicek (belum ada koneksi)
	StatusUnchecked StatusVerdict = "UNCHECKED"
	// NoVulnFound = tidak ada kelemahan ditemukan setelah dicek
	NoVulnFound StatusVerdict = "NO_KNOWN_VULNERABILITIES"
	// Error = ada error saat scan
	StatusError StatusVerdict = "ERROR"
)

// CheckSource menunjukkan darimana data kelemahan berasal
type CheckSource string

const (
	SourceGitHubAPI  CheckSource = "GitHub Advisories"
	SourceLocalDB    CheckSource = "Local Database"
	SourceNone       CheckSource = "None"
)

// Paket adalah informasi tentang satu paket software
type Paket struct {
	Nama    string
	Versi   string
	Jenis   string // "npm", "pip", "apt", "go", dll
	Lokasi string // path ke file paket
}

// Kelemahan adalah satu kelemahan yang ditemukan
type Kelemahan struct {
	ID          string
	Judul      string
	Penjelasan string
	Tingkat    TingkatDanger
	Paket      Paket
	VersiAman string // versi yang sudah diperbaiki
	Referensi  string // link ke informasi
	Sumber     CheckSource // dari mana dideteksi
}

// HasilPemindaian adalah hasil dari satu kali scan
type HasilPemindaian struct {
	Sasaran         string
	JenisPemindaian string
	Kelemahan       []Kelemahan
	Durasi          float64    // dalam detik
	Status          StatusVerdict
	SumberCek       CheckSource
	Pesan           string     // pesan tambahan jika ada
}
