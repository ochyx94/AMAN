package pemindai

import (
	"os"
	"path/filepath"
	"strings"
)

// IgnoreChecker untuk cek file yang harus diabaikan
type IgnoreChecker struct {
	patterns []string
}

// NewIgnoreChecker buat checker baru
func NewIgnoreChecker() *IgnoreChecker {
	return &IgnoreChecker{
		patterns: []string{
			".git",
			"node_modules",
			"vendor",
			".cache",
			"__pycache__",
			".venv",
			"venv",
			".idea",
			".vscode",
			"dist",
			"build",
			"target",
		},
	}
}

// LoadFromFile load ignore patterns dari file
func (c *IgnoreChecker) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c.patterns = append(c.patterns, line)
	}

	return nil
}

// ShouldIgnore cek apakah path harus diabaikan
func (c *IgnoreChecker) ShouldIgnore(path string) bool {
	path = filepath.Base(path)

	for _, pattern := range c.patterns {
		if pattern == path {
			return true
		}
		// Wildcard support
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			mid := strings.Trim(pattern, "*")
			if strings.Contains(path, mid) {
				return true
			}
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(path, strings.Trim(pattern, "*")) {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(path, strings.Trim(pattern, "*")) {
			return true
		}
	}

	return false
}

// GetPatterns get all patterns
func (c *IgnoreChecker) GetPatterns() []string {
	return c.patterns
}
