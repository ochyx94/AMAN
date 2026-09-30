package pemindai

import (
	"testing"
)

func TestRpmVerCmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Equal
		{"3.0.12", "3.0.12", 0},
		{"1.0", "1.0", 0},

		// Basic numeric
		{"3.0.12", "3.0.1", 1},   // 12 > 1
		{"3.0.1", "3.0.12", -1},
		{"2.0", "10.0", -1},      // numeric not alpha compare
		{"10.0", "9.0", 1},

		// Release suffix
		{"3.0.12-26", "3.0.1-41", 1},
		{"3.0.1-25", "3.0.12-26", -1},
		{"3.5.8-1.el9_8", "3.5.5-2.el9_8", 1},
		{"3.2.2-6.el9_5.1", "3.2.2-6.el9_5", 1},

		// Alpha segments
		{"1.0a", "1.0", 1},       // alpha suffix > none
		{"1.0", "1.0a", -1},
		{"1.0.1z", "1.0.1", 1},

		// Epoch-like strip handled separately
		{"1:3.0.1", "2:1.0", -1}, // raw string compare: 1: < 2:

		// Real-world openssl cases
		{"3.0.12-26.oc9", "3.0.1-41.el9_0", 1},   // installed newer than fix
		{"3.0.1-25.el9_0", "3.0.1-43.el9_0", -1}, // installed older than fix
		{"3.2.2-6.el9_5", "3.2.2-6.el9_5.1", -1}, // .1 increment
	}

	for _, tt := range tests {
		got := rpmvercmp(tt.a, tt.b)
		// Normalize sign
		want := tt.want
		if (got < 0 && want > 0) || (got > 0 && want < 0) || (got == 0 && want != 0) || (got != 0 && want == 0) {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", tt.a, tt.b, got, want)
		}
	}
}

func TestIsVulnerable(t *testing.T) {
	tests := []struct {
		installed string
		fixed     string
		want      bool
	}{
		{"3.0.12-26.oc9", "3.0.1-41.el9_0", false},  // installed > fixed
		{"3.0.1-25.el9_0", "3.0.1-43.el9_0", true},  // installed < fixed
		{"3.5.8-1.el9_8", "3.5.5-2.el9_8", false},   // installed > fixed
		{"3.2.2-6.el9_5", "3.2.2-6.el9_5.1", true},  // installed < fixed (.1 missing)
		{"1.0.0", "1.0.0", false},                    // equal = not vulnerable
		{"6.6.117-45.1.oc9", "6.6.119-49.23.oc9", true},
	}

	for _, tt := range tests {
		got := IsVulnerable(tt.installed, tt.fixed)
		if got != tt.want {
			t.Errorf("IsVulnerable(%q, %q) = %v, want %v", tt.installed, tt.fixed, got, tt.want)
		}
	}
}

func TestEVRToComparable(t *testing.T) {
	if got := EVRToComparable("0:3.0.12-26"); got != "3.0.12-26" {
		t.Errorf("EVRToComparable = %q", got)
	}
	if got := EVRToComparable("1:3.0.1-43.el9_0"); got != "3.0.1-43.el9_0" {
		t.Errorf("EVRToComparable = %q", got)
	}
}

func TestDetectDistroEcosystem(t *testing.T) {
	eco := DetectDistroEcosystem()
	t.Logf("Detected ecosystem: %s", eco)
	if eco == "" {
		t.Error("ecosystem empty")
	}
}
