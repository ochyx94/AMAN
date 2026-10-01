package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"aman/pkg/db"
	"aman/pkg/deteksi"
	"aman/pkg/output"
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
	http.HandleFunc("/api/v1/scan-all", scanAllHandler)
	http.HandleFunc("/api/v1/security", securityScanHandler)
	http.HandleFunc("/api/v1/scan-web", scanWebHandler(database))

	// Serve dashboard static files
	dashboardFS := http.Dir("dashboard")
	http.Handle("/dashboard/", http.StripPrefix("/dashboard/", http.FileServer(dashboardFS)))

	// Serve index.html at root
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			// Redirect to dashboard
			http.ServeFile(w, r, "dashboard/index.html")
			return
		}
		http.NotFound(w, r)
	})

	// Start server
	fmt.Printf("AMAN Service starting on port %s\n", port)
	fmt.Println("==============================")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /                        - Dashboard UI")
	fmt.Println("  GET  /health                  - Health check")
	fmt.Println("  POST /api/v1/scan             - Scan folder")
	fmt.Println("  GET  /api/v1/scan-all        - Scan all server overview")
	fmt.Println("  GET  /api/v1/security         - Security scan")
	fmt.Println("  POST /api/v1/update           - Update database")
	fmt.Println()
	fmt.Printf("Dashboard: http://localhost:%s\n", port)

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
		"version": output.Version,
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
			"path":            req.Path,
			"packages_found":  len(paketList),
			"vulnerabilities": kelemahan,
			"vuln_count":      len(kelemahan),
			"status":          "completed",
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

func scanAllHandler(w http.ResponseWriter, r *http.Request) {
	scanner := pemindai.NewComprehensiveScanner()
	result, err := scanner.Run()
	if err != nil {
		http.Error(w, fmt.Sprintf("Scan error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func securityScanHandler(w http.ResponseWriter, r *http.Request) {
	scanner := pemindai.NewSecurityScanner()
	result := scanner.Run()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func scanWebHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			URL         string `json:"url"`
			CheckOnline bool   `json:"check_online"`
		}

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.URL == "" {
			http.Error(w, "URL is required", http.StatusBadRequest)
			return
		}

		// Validate URL
		if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
			req.URL = "https://" + req.URL
		}

		// Scan website
		scanner := pemindai.NewPemindaiWeb()
		hasil, err := scanner.Pindai(req.URL)
		if err != nil {
			http.Error(w, fmt.Sprintf("Web scan error: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hasil)
	}
}
