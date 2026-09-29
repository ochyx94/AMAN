package pemindai

import (
	"os"
	"testing"
)

func TestNewIgnoreChecker(t *testing.T) {
	checker := NewIgnoreChecker()
	if checker == nil {
		t.Fatal("NewIgnoreChecker returned nil")
	}

	if len(checker.patterns) == 0 {
		t.Error("Expected default patterns, got empty")
	}
}

func TestShouldIgnore_DefaultPatterns(t *testing.T) {
	checker := NewIgnoreChecker()

	tests := []struct {
		path     string
		expected bool
	}{
		{".git", true},
		{"node_modules", true},
		{"vendor", true},
		{"__pycache__", true},
		{".venv", true},
		{"dist", true},
		{"build", true},
		{"target", true},
		{"README.md", false},
		{"main.go", false},
		{"app.py", false},
	}

	for _, tt := range tests {
		result := checker.ShouldIgnore(tt.path)
		if result != tt.expected {
			t.Errorf("ShouldIgnore(%s) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestShouldIgnore_WildcardPatterns(t *testing.T) {
	checker := NewIgnoreChecker()

	tests := []struct {
		path     string
		pattern  string
		expected bool
	}{
		{"test.log", "*log*", true},
		{"my_test.txt", "*test*", true},
		{"backup.tar.gz", "*tar*", true},
		{"source.go", "*log*", false},
	}

	// Add wildcard patterns
	for _, tt := range tests {
		checker.patterns = append(checker.patterns, tt.pattern)
	}

	for _, tt := range tests {
		result := checker.ShouldIgnore(tt.path)
		if result != tt.expected {
			t.Errorf("ShouldIgnore(%s) with pattern %s = %v, want %v", tt.path, tt.pattern, result, tt.expected)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temp file
	content := `# Comment line
.git
node_modules
*.log
*.tmp

# Another comment
vendor
`
	tmpfile, err := os.CreateTemp("", "amanignore-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Load from file
	checker := NewIgnoreChecker()
	err = checker.LoadFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify patterns loaded
	expectedPatterns := []string{".git", "node_modules", "*.log", "*.tmp", "vendor"}
	for _, pattern := range expectedPatterns {
		found := false
		for _, p := range checker.patterns {
			if p == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected pattern %s not found in loaded patterns", pattern)
		}
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	checker := NewIgnoreChecker()
	err := checker.LoadFromFile("/nonexistent/path/.amanignore")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestGetPatterns(t *testing.T) {
	checker := NewIgnoreChecker()
	patterns := checker.GetPatterns()

	if len(patterns) == 0 {
		t.Error("GetPatterns returned empty slice")
	}

	// Verify it's the same slice
	if len(patterns) != len(checker.patterns) {
		t.Errorf("GetPatterns length mismatch: got %d, want %d", len(patterns), len(checker.patterns))
	}
}
