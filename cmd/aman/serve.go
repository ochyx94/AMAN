package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"aman/pkg/db"
	"aman/pkg/deteksi"
	"aman/pkg/pemindai"
	"aman/pkg/tipe"
)

var httpServer *http.Server

func jalankanServe() {
	var port string

	// Parse arguments
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port", "-p":
			if i+1 < len(args) {
				port = args[i+1]
				i++
			}
		}
	}

	if port == "" {
		port = "8080"
	}

	// Inisialisasi database
	database, err := deteksi.InitDatabase()
	if err != nil {
		fmt.Printf("Error init database: %v\n", err)
		os.Exit(1)
	}

	// Setup routes
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/v1/scan", scanHandler(database))
	http.HandleFunc("/api/v1/update", updateHandler(database))

	// Start server
	fmt.Printf("AMAN Service starting on port %s\n", port)
	fmt.Println("==============================")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /health        - Health check")
	fmt.Println("  POST /api/v1/scan   - Scan folder")
	fmt.Println("  POST /api/v1/update - Update database")
	fmt.Println()

	httpServer = &http.Server{
		Addr:         ":" + port,
		Handler:      nil,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	err = httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"service": "AMAN",
		"version": Version,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func scanHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Path        string `json:"path"`
			CheckOnline bool   `json:"check_online"`
		}

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Path == "" {
			http.Error(w, "Path is required", http.StatusBadRequest)
			return
		}

		// Scan
		scanner := pemindai.PemindaiFolder{}
		paketList, err := scanner.Pindai(req.Path)
		if err != nil {
			http.Error(w, fmt.Sprintf("Scan error: %v", err), http.StatusInternalServerError)
			return
		}

		// Detect
		var kelemahan []tipe.Kelemahan
		for _, paket := range paketList {
			k, _, err := deteksi.DeteksiPaket(database, paket, req.CheckOnline)
			if err != nil {
				log.Printf("Detection error for %s: %v", paket.Nama, err)
				continue
			}
			kelemahan = append(kelemahan, k...)
		}

		// Response
		response := map[string]interface{}{
			"path":          req.Path,
			"packages_found": len(paketList),
			"vulnerabilities": kelemahan,
			"vuln_count":    len(kelemahan),
			"status":        "completed",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func updateHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Ecosystem string `json:"ecosystem"`
			All       bool   `json:"all"`
		}

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Start async update
		go func() {
			updater := db.NewUpdater()
			if req.All {
				// Update all ecosystems
				ecosystems := []string{"npm", "pip", "go", "rubygems", "cargo", "maven", "nuget"}
				for _, eco := range ecosystems {
					updater.UpdateFromGitHub(database, eco)
				}
			} else if req.Ecosystem != "" {
				updater.UpdateFromGitHub(database, req.Ecosystem)
			}
		}()

		response := map[string]interface{}{
			"status":  "updating",
			"message": "Update started in background",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
