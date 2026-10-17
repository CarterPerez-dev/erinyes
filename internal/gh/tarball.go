// ©AngelaMos | 2026
// tarball.go

package gh

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxTarballBytes = 512 << 20

type TarballFile struct {
	Path string
	Data []byte
	SHA  string
}

func (c *Client) Tarball(ctx context.Context, repo Repository, keep func(path string, size int64) bool, maxFileSize int64) ([]TarballFile, error) {
	u := fmt.Sprintf("%s/repos/%s/tarball/%s", c.base, repo.FullName, repo.Ref())

	req, err := c.newRequest(ctx, http.MethodGet, u, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	if err := c.fetchLim.Wait(ctx); err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	c.mu.Lock()
	c.apiCalls++
	c.mu.Unlock()

	if rl := parseRateLimit(resp.Header); rl.Known() {
		c.mu.Lock()
		c.lastRate = rl
		c.mu.Unlock()
	}

	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w (tarball for %s returned %d)", ErrRateLimited, repo.FullName, resp.StatusCode)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("tarball for %s returned %d", repo.FullName, resp.StatusCode)
	}

	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxTarballBytes))
	if err != nil {
		return nil, fmt.Errorf("tarball for %s is not gzip: %w", repo.FullName, err)
	}
	defer func() { _ = gz.Close() }()

	var out []TarballFile
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("reading tarball for %s: %w", repo.FullName, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		path := stripArchiveRoot(hdr.Name)
		if path == "" {
			continue
		}
		if maxFileSize > 0 && hdr.Size > maxFileSize {
			continue
		}
		if keep != nil && !keep(path, hdr.Size) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, maxFileSize+1))
		if err != nil {
			return out, err
		}
		if maxFileSize > 0 && int64(len(data)) > maxFileSize {
			continue
		}

		sha := BlobSHA(data)
		if err := c.cache.PutRaw(sha, data); err != nil {
			c.notify("could not cache blob from tarball: %v", err)
		}
		out = append(out, TarballFile{Path: path, Data: data, SHA: sha})
	}

	return out, nil
}

func stripArchiveRoot(name string) string {
	name = strings.TrimPrefix(name, "./")
	i := strings.Index(name, "/")
	if i < 0 {
		return ""
	}
	return name[i+1:]
}
