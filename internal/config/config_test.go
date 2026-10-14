// ©AngelaMos | 2026
// config_test.go

package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/config"
)

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	t.Setenv("ERINYES_CONFIG_DIR", t.TempDir())
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Format != "" {
		t.Errorf("Format = %q, want empty so the CLI default wins", cfg.Format)
	}
}

func TestLoadReadsConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ERINYES_CONFIG_DIR", dir)
	body := "format: markdown\ncache_dir: /var/tmp/erinyes\nno_color: true\nrate_limit_rps: 0.5\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Format != "markdown" {
		t.Errorf("Format = %q", cfg.Format)
	}
	if cfg.ResolvedCacheDir() != "/var/tmp/erinyes" {
		t.Errorf("ResolvedCacheDir() = %q", cfg.ResolvedCacheDir())
	}
	if !cfg.NoColor {
		t.Error("NoColor was not read")
	}
	if cfg.RateLimitRPS != 0.5 {
		t.Errorf("RateLimitRPS = %v", cfg.RateLimitRPS)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ERINYES_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("fromat: json\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() silently ignored a typo'd key")
	}
	if !strings.Contains(err.Error(), "fromat") {
		t.Errorf("error = %v, want it to name the offending key", err)
	}
}

func TestTildeIsExpanded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ERINYES_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("cache_dir: ~/erinyes-cache\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.ResolvedCacheDir()
	if strings.HasPrefix(got, "~") {
		t.Errorf("ResolvedCacheDir() = %q, want the tilde expanded", got)
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, "erinyes-cache"); got != want {
		t.Errorf("ResolvedCacheDir() = %q, want %q", got, want)
	}
}

func TestXDGDirectoriesAreRespected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG paths are a unix convention")
	}
	t.Setenv("ERINYES_CONFIG_DIR", "")
	t.Setenv("ERINYES_CACHE_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	t.Setenv("XDG_CACHE_HOME", "/xdg/cache")

	if got := config.ConfigDir(); got != "/xdg/config/erinyes" {
		t.Errorf("ConfigDir() = %q", got)
	}
	if got := config.CacheDir(); got != "/xdg/cache/erinyes" {
		t.Errorf("CacheDir() = %q", got)
	}
	if got := config.SignaturesDir(); got != "/xdg/config/erinyes/signatures" {
		t.Errorf("SignaturesDir() = %q", got)
	}
}

func TestEnvironmentOverridesXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	t.Setenv("ERINYES_CONFIG_DIR", "/explicit")
	if got := config.ConfigDir(); got != "/explicit" {
		t.Errorf("ConfigDir() = %q, want the explicit override to win", got)
	}
}
