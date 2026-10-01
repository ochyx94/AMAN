package db

import (
	"testing"
	"time"
)

func TestDiffScans(t *testing.T) {
	prev := []ScanFinding{
		{Package: "sudo", Advisory: "ALSA-2026:69123", Severity: "HIGH"},
		{Package: "git", Advisory: "ALSA-2025:11462", Severity: "HIGH"},
		{Package: "rsync", Advisory: "ALSA-2024:1000", Severity: "MEDIUM"},
	}
	cur := []ScanFinding{
		{Package: "sudo", Advisory: "ALSA-2026:69123", Severity: "HIGH"}, // still there
		{Package: "rsync", Advisory: "ALSA-2024:1000", Severity: "MEDIUM"}, // still there
		{Package: "kernel", Advisory: "ALSA-2026:99999", Severity: "CRITICAL"}, // NEW
	}
	// git fixed (missing from cur)

	diff := DiffScans(prev, cur)
	if len(diff.New) != 1 || diff.New[0].Package != "kernel" {
		t.Errorf("New: want [kernel], got %v", diff.New)
	}
	if len(diff.Fixed) != 1 || diff.Fixed[0].Package != "git" {
		t.Errorf("Fixed: want [git], got %v", diff.Fixed)
	}
	if diff.StillThere != 2 {
		t.Errorf("StillThere: want 2, got %d", diff.StillThere)
	}
	if diff.PrevCount != 3 || diff.CurCount != 3 {
		t.Errorf("Counts: want 3/3, got %d/%d", diff.PrevCount, diff.CurCount)
	}
}

func TestScanRoundtrip(t *testing.T) {
	database, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer database.Close()

	if err := InitScanHistory(database); err != nil {
		t.Fatalf("init history: %v", err)
	}

	findings := []ScanFinding{
		{Package: "sudo", Installed: "1.9.5", Fixed: "1.9.9", Advisory: "ALSA-2026:1", CVE: "CVE-2026-1", Severity: "HIGH"},
		{Package: "git", Installed: "2.43", Fixed: "2.47", Advisory: "ALSA-2025:2", CVE: "CVE-2024-1", Severity: "MEDIUM"},
	}

	id, err := SaveScan(database, 36, findings)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadFindings(database, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("want 2 findings, got %d", len(loaded))
	}
	if loaded[0].Package != "sudo" || loaded[0].CVE != "CVE-2026-1" {
		t.Errorf("finding mismatch: %+v", loaded[0])
	}

	scanID, ts, err := LoadLatestScan(database, 0)
	if err != nil || scanID != id {
		t.Errorf("latest: id=%d err=%v want %d", scanID, err, id)
	}
	if ts.IsZero() {
		t.Error("timestamp zero")
	}
	_ = time.Now()

	// Cleanup test
	if err := CleanupOldScans(database, 1); err != nil {
		t.Errorf("cleanup: %v", err)
	}
}
