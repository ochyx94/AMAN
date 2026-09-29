package output

import (
	"encoding/json"
	"fmt"
	"time"

	"aman/pkg/tipe"
)

// FormatJSON mengubah hasil scan ke format JSON
func FormatJSON(hasil tipe.HasilPemindaian) ([]byte, error) {
	// Ubah struct ke map agar bisa tambahkan metadata
	output := map[string]interface{}{
		"aman_version": "1.0.0",
		"scan_time":    time.Now().Format(time.RFC3339),
		"sasaran":      hasil.Sasaran,
		"jenis":        hasil.JenisPemindaian,
		"durasi_detik": hasil.Durasi,
		"jumlah_paket": len(hasil.Kelemahan),
		"kelemahan":    hasil.Kelemahan,
	}

	return json.MarshalIndent(output, "", "  ")
}

// FormatTable mengubah hasil scan ke format teks tabel
func FormatTable(hasil tipe.HasilPemindaian) string {
	output := fmt.Sprintf("=== AMAN Scan Result ===\n")
	output += fmt.Sprintf("Sasaran: %s\n", hasil.Sasaran)
	output += fmt.Sprintf("Jenis:   %s\n", hasil.JenisPemindaian)
	output += fmt.Sprintf("Durasi:  %.2f detik\n\n", hasil.Durasi)

	if len(hasil.Kelemahan) == 0 {
		output += "Tidak ada kelemahan ditemukan.\n"
		return output
	}

	output += fmt.Sprintf("%-5s %-20s %-10s %s\n", "No", "Paket", "Tingkat", "ID")
	output += fmt.Sprintf("%-5s %-20s %-10s %s\n", "---", "------", "-------", "--")

	for i, k := range hasil.Kelemahan {
		output += fmt.Sprintf("%-5d %-20s %-10s %s\n", i+1, k.Paket.Nama, k.Tingkat, k.ID)
	}

	output += fmt.Sprintf("\nTotal: %d kelemahan ditemukan.\n", len(hasil.Kelemahan))
	return output
}
