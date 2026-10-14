// ©AngelaMos | 2026
// cache.go

package gh

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Cache struct {
	dir     string
	enabled bool
}

func NewCache(dir string) (*Cache, error) {
	if dir == "" {
		return &Cache{}, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "search"), 0o700); err != nil {
		return nil, err
	}
	return &Cache{dir: dir, enabled: true}, nil
}

func (c *Cache) Enabled() bool { return c != nil && c.enabled }

func (c *Cache) Dir() string {
	if c == nil {
		return ""
	}
	return c.dir
}

func (c *Cache) rawPath(key string) string {
	return filepath.Join(c.dir, "raw", key[:2], key)
}

func (c *Cache) GetRaw(key string) ([]byte, bool) {
	if !c.Enabled() || len(key) < 3 {
		return nil, false
	}
	data, err := os.ReadFile(c.rawPath(key))
	if err != nil {
		return nil, false
	}
	return data, true
}

func (c *Cache) PutRaw(key string, data []byte) error {
	if !c.Enabled() || len(key) < 3 {
		return nil
	}
	p := c.rawPath(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeAtomic(p, data, 0o600)
}

type cachedSearch struct {
	Query     string       `json:"query"`
	FetchedAt time.Time    `json:"fetched_at"`
	Total     int          `json:"total_count"`
	Items     []SearchItem `json:"items"`
}

func (c *Cache) searchPath(query string) string {
	sum := sha256.Sum256([]byte(query))
	return filepath.Join(c.dir, "search", hex.EncodeToString(sum[:])+".json")
}

func (c *Cache) GetSearch(query string, ttl time.Duration) ([]SearchItem, int, bool) {
	if !c.Enabled() || ttl <= 0 {
		return nil, 0, false
	}
	data, err := os.ReadFile(c.searchPath(query))
	if err != nil {
		return nil, 0, false
	}
	var cs cachedSearch
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, 0, false
	}
	if time.Since(cs.FetchedAt) > ttl {
		return nil, 0, false
	}
	return cs.Items, cs.Total, true
}

func (c *Cache) PutSearch(query string, items []SearchItem, total int) error {
	if !c.Enabled() {
		return nil
	}
	data, err := json.MarshalIndent(cachedSearch{
		Query:     query,
		FetchedAt: time.Now().UTC(),
		Total:     total,
		Items:     items,
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(c.searchPath(query), data, 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func BlobSHA(data []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %s\x00", strconv.Itoa(len(data)))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

var errBlobMismatch = errors.New("fetched content does not match the blob sha reported by code search")
