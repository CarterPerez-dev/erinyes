// ©AngelaMos | 2026
// config.go

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

const AppName = "erinyes"

type Config struct {
	Format        string  `yaml:"format"`
	SignaturesDir string  `yaml:"signatures_dir"`
	CacheDir      string  `yaml:"cache_dir"`
	TokenCommand  string  `yaml:"token_command"`
	RateLimitRPS  float64 `yaml:"rate_limit_rps"`
	NoColor       bool    `yaml:"no_color"`

	path string
}

func (c *Config) Path() string { return c.path }

func ConfigDir() string {
	if v := os.Getenv("ERINYES_CONFIG_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, AppName)
		}
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, AppName)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "."+AppName)
	}
	return filepath.Join(home, ".config", AppName)
}

func CacheDir() string {
	if v := os.Getenv("ERINYES_CACHE_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, AppName, "cache")
		}
	}
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, AppName)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "."+AppName, "cache")
	}
	return filepath.Join(home, ".cache", AppName)
}

func SignaturesDir() string {
	return filepath.Join(ConfigDir(), "signatures")
}

func Load() (*Config, error) {
	cfg := &Config{
		path: filepath.Join(ConfigDir(), "config.yaml"),
	}
	data, err := os.ReadFile(cfg.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", cfg.path, err)
	}
	return cfg, nil
}

func (c *Config) ResolvedCacheDir() string {
	if c.CacheDir != "" {
		return expand(c.CacheDir)
	}
	return CacheDir()
}

func (c *Config) ResolvedSignaturesDir() string {
	if c.SignaturesDir != "" {
		return expand(c.SignaturesDir)
	}
	return SignaturesDir()
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}
