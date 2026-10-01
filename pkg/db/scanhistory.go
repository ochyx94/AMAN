package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ScanFinding is one vulnerability finding in a scan
type ScanFinding struct {
	Package   string
	Installed string
	Fixed     string
	Advisory  string
	CVE       string // joined CVEs
	Severity  string
	Summary   string
}

// InitScanHistory creates the scan history tables if not exist
func InitScanHistory(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			total_findings INTEGER NOT NULL,
			security_issues INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS scan_findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL REFERENCES scan_history(id),
			package TEXT NOT NULL,
			installed TEXT,
			fixed TEXT,
			advisory TEXT,
			cves TEXT,
			severity TEXT,
			summary TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
		CREATE INDEX IF NOT EXISTS idx_scan_findings_pkg ON scan_findings(package, advisory);
	`)
	return err
}

// SaveScan stores a completed scan and returns its ID
func SaveScan(db *sql.DB, securityIssues int, findings []ScanFinding) (int64, error) {
	ts := time.Now().Format(time.RFC3339)

	res, err := db.Exec(
		"INSERT INTO scan_history (timestamp, total_findings, security_issues) VALUES (?, ?, ?)",
		ts, len(findings), securityIssues,
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan_history: %w", err)
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return scanID, err
	}
	stmt, err := tx.Prepare("INSERT INTO scan_findings (scan_id, package, installed, fixed, advisory, cves, severity, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return scanID, err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.Exec(scanID, f.Package, f.Installed, f.Fixed, f.Advisory, f.CVE, f.Severity, f.Summary); err != nil {
			tx.Rollback()
			return scanID, fmt.Errorf("insert finding: %w", err)
		}
	}

	return scanID, tx.Commit()
}

// ScanDiff is the comparison between two scans
type ScanDiff struct {
	PrevScanID  int64
	PrevTime    time.Time
	New         []ScanFinding // in current, not in previous
	Fixed       []ScanFinding // in previous, not in current
	StillThere  int           // present in both
	PrevCount   int
	CurCount    int
}

// LoadLatestScan returns the most recent scan ID and timestamp (excluding excludeScanID)
func LoadLatestScan(db *sql.DB, excludeScanID int64) (int64, time.Time, error) {
	var id int64
	var tsStr string
	var err error

	if excludeScanID > 0 {
		err = db.QueryRow(
			"SELECT id, timestamp FROM scan_history WHERE id != ? ORDER BY id DESC LIMIT 1",
			excludeScanID,
		).Scan(&id, &tsStr)
	} else {
		err = db.QueryRow(
			"SELECT id, timestamp FROM scan_history ORDER BY id DESC LIMIT 1",
		).Scan(&id, &tsStr)
	}

	if err == sql.ErrNoRows {
		return 0, time.Time{}, nil // no previous scan
	}
	if err != nil {
		return 0, time.Time{}, err
	}

	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return id, time.Time{}, nil
	}
	return id, ts, nil
}

// LoadFindings returns all findings for a scan
func LoadFindings(db *sql.DB, scanID int64) ([]ScanFinding, error) {
	rows, err := db.Query(
		"SELECT package, installed, fixed, advisory, cves, severity, summary FROM scan_findings WHERE scan_id = ?",
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanFinding
	for rows.Next() {
		var f ScanFinding
		if err := rows.Scan(&f.Package, &f.Installed, &f.Fixed, &f.Advisory, &f.CVE, &f.Severity, &f.Summary); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// findingKey identifies a unique finding (package + advisory)
func findingKey(f ScanFinding) string {
	return f.Package + "|" + f.Advisory
}

// DiffScans compares current findings against previous scan findings
func DiffScans(prev, cur []ScanFinding) ScanDiff {
	prevMap := make(map[string]ScanFinding, len(prev))
	for _, f := range prev {
		prevMap[findingKey(f)] = f
	}
	curMap := make(map[string]ScanFinding, len(cur))
	for _, f := range cur {
		curMap[findingKey(f)] = f
	}

	var diff ScanDiff
	diff.PrevCount = len(prev)
	diff.CurCount = len(cur)

	for k, f := range curMap {
		if _, ok := prevMap[k]; ok {
			diff.StillThere++
		} else {
			diff.New = append(diff.New, f)
		}
		_ = k
	}
	for k, f := range prevMap {
		if _, ok := curMap[k]; !ok {
			diff.Fixed = append(diff.Fixed, f)
		}
		_ = k
	}

	return diff
}

// CleanupOldScans keeps only the N most recent scans
func CleanupOldScans(db *sql.DB, keep int) error {
	if keep < 1 {
		keep = 1
	}
	_, err := db.Exec(`
		DELETE FROM scan_history WHERE id NOT IN (
			SELECT id FROM scan_history ORDER BY id DESC LIMIT ?
		)`, keep)
	if err != nil {
		return err
	}
	// Orphan findings cleanup
	_, err = db.Exec(`
		DELETE FROM scan_findings WHERE scan_id NOT IN (SELECT id FROM scan_history)`)
	return err
}
