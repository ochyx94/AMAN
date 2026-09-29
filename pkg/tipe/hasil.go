package tipe

// TingkatDanger menunjukkan seberapa parah kelemahan
type TingkatDanger string

const (
	DangerRendah   TingkatDanger = "Rendah"
	DangerSedang   TingkatDanger = "Sedang"
	DangerParah    TingkatDanger = "Parah"
	DangerSangatParah TingkatDanger = "Sangat Parah"
)

// Paket adalah informasi tentang satu paket software
type Paket struct {
	Nama     string
	Versi   string
	Jenis    string // "npm", "pip", "apt", "go", dll
	Lokasi  string // path ke file paket
}

// Kelemahan adalah satu kelemahan yang ditemukan
type Kelemahan struct {
	ID            string
	Judul        string
	Penjelasan   string
	Tingkat      TingkatDanger
	Paket        Paket
	VersiAman    string // versi yang sudah diperbaiki
	Referensi    string // link ke informasi
}

// HasilPemindaian adalah hasil dari satu kali scan
type HasilPemindaian struct {
	Sasaran      string
	JenisPemindaian string
	Kelemahan    []Kelemahan
	Durasi       float64 // dalam detik
}
