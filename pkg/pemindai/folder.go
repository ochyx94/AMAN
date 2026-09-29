package pemindai

import (
	"fmt"
	"os"
	"path/filepath"

	"aman/pkg/tipe"
)

// PemindaiFolder untuk memindai folder dan berkas
type PemindaiFolder struct{}

// Nama mengembalikan nama pemindai
func (p *PemindaiFolder) Nama() string {
	return "folder"
}

// Pindai memindai folder dan mengembalikan daftar paket
func (p *PemindaiFolder) Pindai(sasaran string) ([]tipe.Paket, error) {
	var paketList []tipe.Paket

	// cek apakah sasaran ada
	info, err := os.Stat(sasaran)
	if err != nil {
		return nil, fmt.Errorf("sasaran tidak ditemukan: %s", sasaran)
	}

	// kalau sasaran adalah file, proses satu file
	if !info.IsDir() {
		paket := deteksiPaket(sasaran)
		if paket.Nama != "" {
			paketList = append(paketList, paket)
		}
		return paketList, nil
	}

	// walk directory
	err = filepath.Walk(sasaran, func(alamat string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip error, lanjut
		}

		// kalau direktori, skip
		if info.IsDir() {
			return nil
		}

		// deteksi paket dari file
		paket := deteksiPaket(alamat)
		if paket.Nama != "" {
			paketList = append(paketList, paket)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return paketList, nil
}

// deteksiPaket mendeteksi jenis paket dari nama file
func deteksiPaket(alamat string) tipe.Paket {
	nama := filepath.Base(alamat)

	switch nama {
	case "package.json":
		return tipe.Paket{
			Nama:    "npm-package",
			Versi:   "tidak diketahui",
			Jenis:   "npm",
			Lokasi:  alamat,
		}
	case "requirements.txt":
		return tipe.Paket{
			Nama:    "pip-package",
			Versi:   "tidak diketahui",
			Jenis:   "pip",
			Lokasi:  alamat,
		}
	case "go.mod":
		return tipe.Paket{
			Nama:    "go-module",
			Versi:   "tidak diketahui",
			Jenis:   "go",
			Lokasi:  alamat,
		}
	case "Gemfile", "Gemfile.lock":
		return tipe.Paket{
			Nama:    "ruby-gem",
			Versi:   "tidak diketahui",
			Jenis:   "gem",
			Lokasi:  alamat,
		}
	case "Cargo.toml":
		return tipe.Paket{
			Nama:    "rust-crate",
			Versi:   "tidak diketahui",
			Jenis:   "cargo",
			Lokasi:  alamat,
		}
	case "pom.xml":
		return tipe.Paket{
			Nama:    "maven-package",
			Versi:   "tidak diketahui",
			Jenis:   "maven",
			Lokasi:  alamat,
		}
	case "build.gradle", "build.gradle.kts":
		return tipe.Paket{
			Nama:    "gradle-package",
			Versi:   "tidak diketahui",
			Jenis:   "gradle",
			Lokasi:  alamat,
		}
	default:
		// cek ekstensi
		ekstensi := filepath.Ext(nama)
		switch ekstensi {
		case ".json":
			if nama != "package-lock.json" && nama != "tsconfig.json" {
				return tipe.Paket{
					Nama:    "file-json",
					Versi:   "tidak diketahui",
					Jenis:   "json",
					Lokasi:  alamat,
				}
			}
		case ".py":
			return tipe.Paket{
				Nama:    "python-script",
				Versi:   "tidak diketahui",
				Jenis:   "python",
				Lokasi:  alamat,
			}
		case ".js":
			return tipe.Paket{
				Nama:    "javascript-file",
				Versi:   "tidak diketahui",
				Jenis:   "javascript",
				Lokasi:  alamat,
			}
		case ".go":
			return tipe.Paket{
				Nama:    "golang-file",
				Versi:   "tidak diketahui",
				Jenis:   "go",
				Lokasi:  alamat,
			}
		}
	}

	return tipe.Paket{}
}
