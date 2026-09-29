package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents AMAN configuration
type Config struct {
	// Database settings
	DatabasePath string `yaml:"database_path"`

	// Scan settings
	ScanTimeout   int  `yaml:"scan_timeout_seconds"`
	OnlineCheck   bool `yaml:"online_check"`
	IgnorePatterns []string `yaml:"ignore_patterns"`

	// Security scan settings
	CheckSecurityHeaders bool `yaml:"check_security_headers"`
	CheckCookieSecurity  bool `yaml:"check_cookie_security"`
	CheckExposedFiles    bool `yaml:"check_exposed_files"`

	// Output settings
	Verbose bool `yaml:"verbose"`
	Format  string `yaml:"output_format"` // text, json

	// Update settings
	AutoUpdate bool `yaml:"auto_update"`
	UpdateURL  string `yaml:"update_url"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		DatabasePath:        filepath.Join(home, ".aman", "aman.db"),
		ScanTimeout:         30,
		OnlineCheck:         false,
		IgnorePatterns:      []string{".amanignore", ".git", "node_modules"},
		CheckSecurityHeaders: true,
		CheckCookieSecurity:  true,
		CheckExposedFiles:    true,
		Verbose:              false,
		Format:              "text",
		AutoUpdate:          true,
		UpdateURL:           "https://api.github.com/advisories",
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Return default config if file doesn't exist
		return DefaultConfig(), nil
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("gagal parse config: %w", err)
	}

	return &cfg, nil
}

// SaveConfig saves configuration to file
func (c *Config) SaveConfig(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("gagal encode config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("gagal buat folder config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("gagal simpan config: %w", err)
	}

	return nil
}

// GetConfigPath returns the default config path
func GetConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aman", "config.yaml")
}
