package output

import (
	"encoding/json"
	"fmt"
	"time"

	"aman/pkg/tipe"
)

// FormatJSON mengubah hasil scan ke format JSON
func FormatJSON(hasil tipe.HasilPemindaian) ([]byte, error) {
	output := map[string]interface{}{
		"aman_version":   "1.0.0",
		"scan_time":      time.Now().Format(time.RFC3339),
		"sasaran":        hasil.Sasaran,
		"jenis":         hasil.JenisPemindaian,
		"durasi_detik":   hasil.Durasi,
		"status":         hasil.Status,
		"sumber_cek":     hasil.SumberCek,
		"jumlah_kelemahan": len(hasil.Kelemahan),
		"kelemahan":      hasil.Kelemahan,
	}

	if hasil.Pesan != "" {
		output["pesan"] = hasil.Pesan
	}

	return json.MarshalIndent(output, "", "  ")
}

// FormatTable mengubah hasil scan ke format teks tabel
func FormatTable(hasil tipe.HasilPemindaian) string {
	output := fmt.Sprintf("=== AMAN Scan Result ===\n")
	output += fmt.Sprintf("Sasaran: %s\n", hasil.Sasaran)
	output += fmt.Sprintf("Jenis:   %s\n", hasil.JenisPemindaian)
	output += fmt.Sprintf("Durasi:  %.2f detik\n", hasil.Durasi)
	output += fmt.Sprintf("Status:  %s\n", formatStatus(hasil.Status))
	output += fmt.Sprintf("Sumber:  %s\n\n", hasil.SumberCek)

	// Tampilkan verdict
	output += fmt.Sprintf("%s\n", formatVerdict(hasil.Status, len(hasil.Kelemahan)))

	// Detail jika ada kelemahan
	if len(hasil.Kelemahan) > 0 {
		output += fmt.Sprintf("\n--- Detail Kelemahan ---\n\n")
		output += fmt.Sprintf("%-5s %-10s %-15s %-15s %s\n", "No", "Tingkat", "Paket", "ID", "Judul")
		output += fmt.Sprintf("%-5s %-10s %-15s %-15s %s\n", "---", "-------", "-----", "--", "-----")

		for i, k := range hasil.Kelemahan {
			output += fmt.Sprintf("%-5d %-10s %-15s %-15s %s\n",
				i+1, k.Tingkat, k.Paket.Nama, k.ID, k.Judul)
		}
	}

	// Pesan jika ada
	if hasil.Pesan != "" {
		output += fmt.Sprintf("\n--- Catatan ---\n%s\n", hasil.Pesan)
	}

	return output
}

// formatStatus ubah status ke teks Indonesia
func formatStatus(s tipe.StatusVerdict) string {
	switch s {
	case tipe.StatusVerified:
		return "✅ TERVERIFIKASI"
	case tipe.StatusLocalOnly:
		return "⚠️ CEK LOKAL SAJA"
	case tipe.StatusUnchecked:
		return "❌ BELUM Dicek"
	case tipe.NoVulnFound:
		return "✅ TIDAK ADA KLEMAHAN"
	case tipe.StatusError:
		return "❌ ERROR"
	default:
		return string(s)
	}
}

// formatVerdict ubah verdict ke teks Indonesia
func formatVerdict(status tipe.StatusVerdict, jumlah int) string {
	switch status {
	case tipe.StatusVerified:
		if jumlah > 0 {
			return "⚠️  DITEMUKAN KLEMAHAN (" + fmt.Sprintf("%d", jumlah) + ")"
		}
		return "✅ TIDAK ADA KLEMAHAN DIKETAHUI (TERVERIFIKASI)"
	case tipe.StatusLocalOnly:
		if jumlah > 0 {
			return "⚠️  DITEMUKAN KLEMAHAN (" + fmt.Sprintf("%d", jumlah) + ") - CEK LOKAL SAJA"
		}
		return "⚠️  TIDAK ADA KLEMAHAN DI DATABASE LOKAL"
	case tipe.StatusUnchecked:
		return "❌ BELUM DICEK - hasil mungkin tidak lengkap"
	case tipe.NoVulnFound:
		return "✅ TIDAK ADA KLEMAHAN DIKETAHUI"
	case tipe.StatusError:
		return "❌ ERROR SAAT MEMINDAIAN"
	default:
		return "❓ STATUS TIDAK DIKETAHUI"
	}
}
