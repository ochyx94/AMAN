package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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
	http.HandleFunc("/api/v1/history", historyHandler(database))
	http.HandleFunc("/api/v1/findings", findingsHandler(database))
	http.HandleFunc("/api/v1/fullscan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fullScanHandler()(w, r)
		} else {
			fullScanStatusHandler(database)(w, r)
		}
	})

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

		// W1 security audit runs independently of page fetch
		secReport, secErr := pemindai.ScanWebSecurity(req.URL)

		if err != nil && secErr != nil {
			http.Error(w, fmt.Sprintf("Web scan error: %v (audit: %v)", err, secErr), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{}
		if hasil != nil {
			response["URL"] = hasil.URL
			response["StatusCode"] = hasil.StatusCode
			response["Title"] = hasil.Title
			response["Server"] = hasil.Server
			response["TechStack"] = hasil.TechStack
			response["Links"] = hasil.Links
			response["Paket"] = hasil.Paket
		} else {
			response["page_error"] = err.Error()
		}
		if secErr == nil {
			response["security_audit"] = secReport
		} else {
			response["audit_error"] = secErr.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// historyHandler GET /api/v1/history?limit=20
// Returns list of past scans (newest first)
func historyHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := 20
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 50 {
				limit = n
			}
		}

		scans, err := db.ListScans(database, limit)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Compute diffs between consecutive scans (newest vs previous)
		type ScanWithDiff struct {
			db.ScanSummary
			New   int `json:"new_count"`
			Fixed int `json:"fixed_count"`
		}
		result := make([]ScanWithDiff, 0, len(scans))
		for i, s := range scans {
			wd := ScanWithDiff{ScanSummary: s}
			// scans[i] is newer than scans[i+1]
			if i+1 < len(scans) {
				curFindings, err1 := db.LoadFindings(database, s.ID)
				prevFindings, err2 := db.LoadFindings(database, scans[i+1].ID)
				if err1 == nil && err2 == nil {
					diff := db.DiffScans(prevFindings, curFindings)
					wd.New = len(diff.New)
					wd.Fixed = len(diff.Fixed)
				}
			}
			result = append(result, wd)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scans": result,
		})
	}
}

// findingsHandler GET /api/v1/findings?scan=<id>
// Returns findings of a specific scan, grouped summary
func findingsHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		scanIDStr := r.URL.Query().Get("scan")
		if scanIDStr == "" {
			http.Error(w, "scan parameter required", http.StatusBadRequest)
			return
		}
		scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid scan id", http.StatusBadRequest)
			return
		}

		findings, err := db.LoadFindings(database, scanID)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Severity summary
		sevCount := map[string]int{}
		for _, f := range findings {
			sevCount[f.Severity]++
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scan_id":  scanID,
			"total":    len(findings),
			"summary":  sevCount,
			"findings": findings,
		})
	}
}

// === Full Scan API (background scan with status polling) ===

var (
	fullScanMu       sync.Mutex
	fullScanRunning  = false
	fullScanStarted  time.Time
	fullScanFinished time.Time
	fullScanErr      error
)

// fullScanHandler POST /api/v1/fullscan - start background scan
func fullScanHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		fullScanMu.Lock()
		if fullScanRunning {
			fullScanMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "already_running",
				"started": fullScanStarted,
			})
			return
		}
		fullScanRunning = true
		fullScanStarted = time.Now()
		fullScanErr = nil
		fullScanMu.Unlock()

		// Optional target from body
		target := ""
		var req struct {
			Target string `json:"target"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				target = req.Target
			}
		}

		// Run in background
		go func(tgt string) {
			defer func() {
				fullScanMu.Lock()
				fullScanRunning = false
				fullScanFinished = time.Now()
				fullScanMu.Unlock()
			}()
			defer func() {
				if rec := recover(); rec != nil {
					fullScanMu.Lock()
					fullScanErr = fmt.Errorf("scan panic: %v", rec)
					fullScanMu.Unlock()
				}
			}()
			// Redirect stdout during scan to suppress terminal noise
			oldStdout := os.Stdout
			devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err == nil {
				os.Stdout = devnull
				defer func() {
					os.Stdout = oldStdout
					devnull.Close()
				}()
			}
			pindaiAll(tgt, false, "") // offline, text output (suppressed)
		}(target)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "started",
			"started": fullScanStarted,
			"message": "Scan berjalan di background. Poll /api/v1/fullscan untuk status.",
		})
	}
}

// fullScanStatusHandler GET /api/v1/fullscan - status + latest result
func fullScanStatusHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		fullScanMu.Lock()
		running := fullScanRunning
		started := fullScanStarted
		finished := fullScanFinished
		scanErr := fullScanErr
		fullScanMu.Unlock()

		resp := map[string]interface{}{
			"running": running,
		}
		if running {
			resp["started"] = started
			resp["elapsed_seconds"] = time.Since(started).Seconds()
		} else if !finished.IsZero() {
			resp["finished"] = finished
			if scanErr != nil {
				resp["error"] = scanErr.Error()
			}

			// Latest scan result from history
			scanID, ts, err := db.LoadLatestScan(database, 0)
			if err == nil && scanID > 0 {
				findings, _ := db.LoadFindings(database, scanID)
				sevCount := map[string]int{}
				for _, f := range findings {
					sevCount[f.Severity]++
				}
				resp["last_scan_id"] = scanID
				resp["last_scan_time"] = ts
				resp["total_findings"] = len(findings)
				resp["severity_summary"] = sevCount
			}

			// Security issues count from latest scan record
			scans, _ := db.ListScans(database, 1)
			if len(scans) > 0 {
				resp["last_security_issues"] = scans[0].SecurityIssues
			}
		} else {
			resp["message"] = "Belum ada scan sejak server start. POST /api/v1/fullscan untuk mulai."
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
