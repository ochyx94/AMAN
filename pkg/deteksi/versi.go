package deteksi

import (
	"fmt"
	"regexp"
	"strings"
)

// CompareVersions membandingkan dua versi
// Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	// Normalize versions
	v1 = normalizeVersion(v1)
	v2 = normalizeVersion(v2)

	// Parse versions
	p1 := parseVersion(v1)
	p2 := parseVersion(v2)

	// Compare major
	if p1.major < p2.major {
		return -1
	}
	if p1.major > p2.major {
		return 1
	}

	// Compare minor
	if p1.minor < p2.minor {
		return -1
	}
	if p1.minor > p2.minor {
		return 1
	}

	// Compare patch
	if p1.patch < p2.patch {
		return -1
	}
	if p1.patch > p2.patch {
		return 1
	}

	return 0
}

// IsVersionAffected mengecek apakah versi terpengaruh
// vulnerableVersions adalah ekspresi seperti "<1.0.0", ">=1.0.0,<2.0.0", dll
func IsVersionAffected(currentVersion, vulnerableVersions string) bool {
	// Parse vulnerable version expressions
	// Format bisa: "<2.0.0" atau ">=1.0.0,<2.0.0"
	
	// Pertama coba parse sebagai range dengan koma
	expressions := strings.Split(vulnerableVersions, ",")
	
	// Jika ada koma, AND semua kondisi
	if len(expressions) > 1 {
		for _, expr := range expressions {
			expr = strings.TrimSpace(expr)
			if !matchesVersion(currentVersion, expr) {
				return false
			}
		}
		return true
	}
	
	// Single expression
	return matchesVersion(currentVersion, vulnerableVersions)
}

type parsedVersion struct {
	major int
	minor int
	patch int
	suffix string
}

func parseVersion(v string) parsedVersion {
	var pv parsedVersion

	// Remove leading 'v' or 'V'
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	// Extract suffix (like -beta, -alpha, +build, etc.)
	if idx := strings.Index(v, "-"); idx != -1 {
		pv.suffix = v[idx:]
		v = v[:idx]
	}
	if idx := strings.Index(v, "+"); idx != -1 {
		pv.suffix = v[idx:]
		v = v[:idx]
	}

	// Parse version numbers
	re := regexp.MustCompile(`(\d+)(?:\.(\d+))?(?:\.(\d+))?`)
	matches := re.FindStringSubmatch(v)

	if len(matches) >= 2 {
		pv.major = atoi(matches[1])
	}
	if len(matches) >= 3 && matches[2] != "" {
		pv.minor = atoi(matches[2])
	}
	if len(matches) >= 4 && matches[3] != "" {
		pv.patch = atoi(matches[3])
	}

	return pv
}

func normalizeVersion(v string) string {
	// Remove common prefixes
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	// Remove build metadata
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}

	return v
}

func matchesVersion(current, expr string) bool {
	expr = strings.TrimSpace(expr)

	// Handle different operators
	if strings.HasPrefix(expr, "<=") {
		// Less than or equal
		v := strings.TrimPrefix(expr, "<=")
		return CompareVersions(current, v) <= 0
	}

	if strings.HasPrefix(expr, ">=") {
		// Greater than or equal
		v := strings.TrimPrefix(expr, ">=")
		return CompareVersions(current, v) >= 0
	}

	if strings.HasPrefix(expr, "!=") {
		// Not equal
		v := strings.TrimPrefix(expr, "!=")
		return CompareVersions(current, v) != 0
	}

	if strings.HasPrefix(expr, "=") {
		// Exact version
		v := strings.TrimPrefix(expr, "=")
		return CompareVersions(current, v) == 0
	}

	if strings.HasPrefix(expr, "<") {
		// Less than
		v := strings.TrimPrefix(expr, "<")
		return CompareVersions(current, v) < 0
	}

	if strings.HasPrefix(expr, ">") {
		// Greater than
		v := strings.TrimPrefix(expr, ">")
		return CompareVersions(current, v) > 0
	}

	if strings.HasPrefix(expr, "~") {
		// Tilde range (like ~1.2.3 means >=1.2.3 <1.3.0)
		v := strings.TrimPrefix(expr, "~")
		pv := parseVersion(v)

		// Check >= v
		if CompareVersions(current, v) < 0 {
			return false
		}

		// Check < major.(minor+1).0
		upper := fmt.Sprintf("%d.%d.0", pv.major, pv.minor+1)
		return CompareVersions(current, upper) < 0
	}

	if strings.HasPrefix(expr, "^") {
		// Caret range (like ^1.2.3 means >=1.2.3 <2.0.0)
		v := strings.TrimPrefix(expr, "^")
		pv := parseVersion(v)

		// Check >= v
		if CompareVersions(current, v) < 0 {
			return false
		}

		// Check < (major+1).0.0
		upper := fmt.Sprintf("%d.0.0", pv.major+1)
		return CompareVersions(current, upper) < 0
	}

	// Exact match
	return CompareVersions(current, expr) == 0
}

func atoi(s string) int {
	if s == "" {
		return 0
	}
	result := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}
