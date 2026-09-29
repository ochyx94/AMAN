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
		"aman_version":     "1.0.0",
		"scan_time":        time.Now().Format(time.RFC3339),
		"sasaran":          hasil.Sasaran,
		"jenis":           hasil.JenisPemindaian,
		"durasi_detik":     hasil.Durasi,
		"status":           hasil.Status,
		"sumber_cek":       hasil.SumberCek,
		"jumlah_paket":     len(hasil.Paket),
		"jumlah_kelemahan": len(hasil.Kelemahan),
	}

	// Summary berdasarkan tingkat
	summary := hitungSummary(hasil.Kelemahan)
	output["ringkasan"] = summary

	// Paket yang ditemukan
	if len(hasil.Paket) > 0 {
		var paketOutput []map[string]string
		for _, p := range hasil.Paket {
			paketOutput = append(paketOutput, map[string]string{
				"nama":   p.Nama,
				"versi":  p.Versi,
				"jenis":  p.Jenis,
				"lokasi": p.Lokasi,
			})
		}
		output["paket"] = paketOutput
	}

	// Kelemahan yang ditemukan
	if len(hasil.Kelemahan) > 0 {
		var vulnOutput []map[string]interface{}
		for _, k := range hasil.Kelemahan {
			vulnOutput = append(vulnOutput, map[string]interface{}{
				"id":           k.ID,
				"judul":        k.Judul,
				"penjelasan":   k.Penjelasan,
				"tingkat":      k.Tingkat,
				"paket":        k.Paket.Nama,
				"paket_versi":  k.Paket.Versi,
				"versi_aman":   k.VersiAman,
				"referensi":    k.Referensi,
				"sumber":       k.Sumber,
			})
		}
		output["kelemahan"] = vulnOutput
	}

	if hasil.Pesan != "" {
		output["pesan"] = hasil.Pesan
	}

	return json.MarshalIndent(output, "", "  ")
}

// FormatJSONCompact menghasilkan JSON yang compact (minified)
func FormatJSONCompact(hasil tipe.HasilPemindaian) ([]byte, error) {
	type CompactResult struct {
		V   string `json:"v"`
		T   string `json:"t"`
		S   string `json:"s"`
		St  string `json:"st"`
		Sr  string `json:"sr"`
		Pk  int    `json:"pk"`
		Vl  int    `json:"vl"`
		Vns []struct {
			ID  string `json:"id"`
			Lv  string `json:"lv"`
			Pk  string `json:"pk"`
			Ref string `json:"ref,omitempty"`
		} `json:"vns,omitempty"`
	}

	result := CompactResult{
		V:  "1.0",
		T:  hasil.Sasaran,
		S:  hasil.JenisPemindaian,
		St: string(hasil.Status),
		Sr: string(hasil.SumberCek),
		Pk: len(hasil.Paket),
		Vl: len(hasil.Kelemahan),
	}

	for _, k := range hasil.Kelemahan {
		result.Vns = append(result.Vns, struct {
			ID  string `json:"id"`
			Lv  string `json:"lv"`
			Pk  string `json:"pk"`
			Ref string `json:"ref,omitempty"`
		}{
			ID:  k.ID,
			Lv:  string(k.Tingkat),
			Pk:  k.Paket.Nama,
			Ref: k.Referensi,
		})
	}

	return json.Marshal(result)
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

type Summary struct {
	Total       int `json:"total"`
	Rendah      int `json:"rendah"`
	Sedang      int `json:"sedang"`
	Parah       int `json:"parah"`
	SangatParah int `json:"sangat_parah"`
}

func hitungSummary(kelemahan []tipe.Kelemahan) Summary {
	var s Summary
	s.Total = len(kelemahan)

	for _, k := range kelemahan {
		switch k.Tingkat {
		case tipe.DangerRendah:
			s.Rendah++
		case tipe.DangerSedang:
			s.Sedang++
		case tipe.DangerParah:
			s.Parah++
		case tipe.DangerSangatParah:
			s.SangatParah++
		}
	}

	return s
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
