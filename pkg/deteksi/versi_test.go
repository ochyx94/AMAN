package deteksi

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	testCases := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{"equal", "1.0.0", "1.0.0", 0},
		{"v1 less", "1.0.0", "2.0.0", -1},
		{"v1 greater", "2.0.0", "1.0.0", 1},
		{"with v prefix", "v1.0.0", "1.0.0", 0},
		{"different major", "2.0.0", "1.0.0", 1},
		{"different minor", "1.2.0", "1.1.0", 1},
		{"different patch", "1.0.2", "1.0.1", 1},
		// Note: Alpha/beta suffix comparison is simplified
		// For production, use semver library
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := CompareVersions(tc.v1, tc.v2)
			if result != tc.expected {
				t.Errorf("CompareVersions(%s, %s) = %d, expected %d", tc.v1, tc.v2, result, tc.expected)
			}
		})
	}
}

func TestIsVersionAffected(t *testing.T) {
	testCases := []struct {
		name     string
		current  string
		vulnExpr string
		expected bool
	}{
		{"less than", "1.0.0", "<2.0.0", true},
		{"less than equal", "2.0.0", "<=2.0.0", true},
		{"less than not affected", "2.0.0", "<2.0.0", false},
		{"greater than", "3.0.0", ">2.0.0", true},
		{"greater than not affected", "1.0.0", ">2.0.0", false},
		{"range affected", "1.5.0", ">=1.0.0,<2.0.0", true},
		{"range not affected upper", "2.0.0", ">=1.0.0,<2.0.0", false},
		{"range not affected lower", "0.5.0", ">=1.0.0,<2.0.0", false},
		{"exact equal", "1.0.0", "1.0.0", true},
		{"exact not equal", "1.0.1", "1.0.0", false},
		{"not equal", "1.0.1", "!=1.0.1", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsVersionAffected(tc.current, tc.vulnExpr)
			if result != tc.expected {
				t.Errorf("IsVersionAffected(%s, %s) = %v, expected %v", tc.current, tc.vulnExpr, result, tc.expected)
			}
		})
	}
}
