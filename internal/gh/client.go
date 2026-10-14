// ©AngelaMos | 2026
// client.go

package gh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	apiBase             = "https://api.github.com"
	rawBase             = "https://raw.githubusercontent.com"
	apiVersion          = "2022-11-28"
	searchPageSize      = 100
	searchMaxPages      = 10
	defaultRetries      = 5
	defaultTimeout      = 30 * time.Second
	tokenCommandTimeout = 5 * time.Second
	maxBodyBytes        = 32 << 20
)

type SearchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	SHA        string `json:"sha"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		HTMLURL       string `json:"html_url"`
		Fork          bool   `json:"fork"`
	} `json:"repository"`
}

type SearchResult struct {
	TotalCount        int          `json:"total_count"`
	IncompleteResults bool         `json:"incomplete_results"`
	Items             []SearchItem `json:"items"`
}

type Notifier func(format string, args ...any)

type Client struct {
	http      *http.Client
	token     string
	ua        string
	retries   int
	notify    Notifier
	cache     *Cache
	searchLim *Limiter
	fetchLim  *Limiter
	base      string
	raw       string

	mu       sync.Mutex
	branches map[string]string
	lastRate RateLimit
	apiCalls int
	rawCalls int
	cacheHit int
}

type Options struct {
	Token          string
	UserAgent      string
	Cache          *Cache
	RPS            float64
	Retries        int
	Notify         Notifier
	HTTPClient     *http.Client
	BaseURL        string
	RawURL         string
	SearchInterval time.Duration
}

func New(opts Options) (*Client, error) {
	token := opts.Token
	if token == "" {
		var err error
		token, err = Token()
		if err != nil {
			return nil, err
		}
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	retries := opts.Retries
	if retries <= 0 {
		retries = defaultRetries
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "erinyes"
	}
	notify := opts.Notify
	if notify == nil {
		notify = func(string, ...any) {}
	}

	searchInterval := opts.SearchInterval
	if searchInterval == 0 {
		searchInterval = minSearchInterval
	}
	searchLim := NewLimiter(opts.RPS)
	searchLim.SetMinInterval(searchInterval)

	base := opts.BaseURL
	if base == "" {
		base = apiBase
	}
	raw := opts.RawURL
	if raw == "" {
		raw = rawBase
	}

	return &Client{
		http:      hc,
		token:     token,
		ua:        ua,
		retries:   retries,
		notify:    notify,
		cache:     opts.Cache,
		searchLim: searchLim,
		fetchLim:  NewLimiter(opts.RPS),
		base:      strings.TrimRight(base, "/"),
		raw:       strings.TrimRight(raw, "/"),
		branches:  make(map[string]string),
	}, nil
}

func Token() (string, error) {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), tokenCommandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v, nil
		}
	}
	return "", errors.New("no GitHub token: set $GITHUB_TOKEN or authenticate with `gh auth login`")
}

func (c *Client) Stats() (apiCalls, rawCalls, cacheHits int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.apiCalls, c.rawCalls, c.cacheHit
}

func (c *Client) RateLimit() RateLimit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRate
}

func (c *Client) do(ctx context.Context, req *http.Request, lim *Limiter) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		if lim != nil {
			if err := lim.Wait(ctx); err != nil {
				return nil, err
			}
		}

		clone := req.Clone(ctx)
		resp, err := c.http.Do(clone)
		if err != nil {
			if attempt >= c.retries {
				return nil, err
			}
			wait := transientBackoff(attempt)
			c.notify("network error (%v), retrying in %s", err, wait.Round(time.Second))
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}

		rl := parseRateLimit(resp.Header)
		if rl.Known() {
			c.mu.Lock()
			c.lastRate = rl
			c.mu.Unlock()
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		switch {
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			if attempt >= c.retries {
				return body, fmt.Errorf("%w (last status %d)", ErrRateLimited, resp.StatusCode)
			}
			wait, ok := retryAfter(resp.Header)
			switch {
			case ok:
				c.notify("secondary rate limit, Retry-After %s", wait.Round(time.Second))
			case rl.Exhausted():
				wait = rl.Until()
				c.notify("primary rate limit for %s exhausted, sleeping %s until reset", rl.Resource, wait.Round(time.Second))
			default:
				wait = backoffFor(attempt)
				c.notify("403 from GitHub, backing off %s", wait.Round(time.Second))
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue

		case resp.StatusCode >= 500:
			if attempt >= c.retries {
				return body, fmt.Errorf("github returned %d: %s", resp.StatusCode, snippet(body))
			}
			wait := transientBackoff(attempt)
			c.notify("github %d, retrying in %s", resp.StatusCode, wait.Round(time.Second))
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue

		case resp.StatusCode == http.StatusUnauthorized:
			return body, errors.New("github rejected the token (401): check $GITHUB_TOKEN or run `gh auth login`")

		case resp.StatusCode >= 400:
			return body, fmt.Errorf("github returned %d: %s", resp.StatusCode, snippet(body))
		}

		if rl.Exhausted() && rl.Until() > 0 {
			c.notify("%s quota down to %d, pausing %s until reset", rl.Resource, rl.Remaining, rl.Until().Round(time.Second))
			if err := sleep(ctx, rl.Until()); err != nil {
				return body, err
			}
		}

		return body, nil
	}
}

func (c *Client) newRequest(ctx context.Context, method, rawurl string, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", c.ua)
	return req, nil
}

func (c *Client) SearchCode(ctx context.Context, query string, limit int, cacheTTL time.Duration) ([]SearchItem, int, error) {
	if items, total, ok := c.cache.GetSearch(query, cacheTTL); ok {
		c.notify("search cache hit: %s", query)
		if limit > 0 && len(items) > limit {
			items = items[:limit]
		}
		return items, total, nil
	}

	var (
		all   []SearchItem
		total int
	)

	for page := 1; page <= searchMaxPages; page++ {
		perPage := searchPageSize
		if limit > 0 && limit-len(all) < perPage {
			perPage = limit - len(all)
		}
		if perPage <= 0 {
			break
		}

		q := url.Values{}
		q.Set("q", query)
		q.Set("per_page", fmt.Sprint(perPage))
		q.Set("page", fmt.Sprint(page))

		req, err := c.newRequest(ctx, http.MethodGet, c.base+"/search/code?"+q.Encode(), "application/vnd.github+json")
		if err != nil {
			return nil, 0, err
		}

		body, err := c.do(ctx, req, c.searchLim)
		c.mu.Lock()
		c.apiCalls++
		c.mu.Unlock()
		if err != nil {
			return all, total, err
		}

		var sr SearchResult
		if err := json.Unmarshal(body, &sr); err != nil {
			return all, total, fmt.Errorf("decode search response: %w", err)
		}
		total = sr.TotalCount
		all = append(all, sr.Items...)

		if len(sr.Items) < perPage {
			break
		}
		if limit > 0 && len(all) >= limit {
			break
		}
	}

	if err := c.cache.PutSearch(query, all, total); err != nil {
		c.notify("could not cache search results: %v", err)
	}
	return all, total, nil
}

func (c *Client) DefaultBranch(ctx context.Context, repo string) (string, error) {
	c.mu.Lock()
	if b, ok := c.branches[repo]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()

	req, err := c.newRequest(ctx, http.MethodGet, c.base+"/repos/"+repo, "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	body, err := c.do(ctx, req, c.fetchLim)
	c.mu.Lock()
	c.apiCalls++
	c.mu.Unlock()
	if err != nil {
		return "", err
	}

	var meta struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", err
	}
	if meta.DefaultBranch == "" {
		meta.DefaultBranch = "main"
	}

	c.mu.Lock()
	c.branches[repo] = meta.DefaultBranch
	c.mu.Unlock()
	return meta.DefaultBranch, nil
}

func (c *Client) FetchItem(ctx context.Context, item SearchItem) ([]byte, string, error) {
	repo := item.Repository.FullName

	if item.SHA != "" {
		if data, ok := c.cache.GetRaw(item.SHA); ok {
			c.mu.Lock()
			c.cacheHit++
			c.mu.Unlock()
			return data, "cache", nil
		}
	}

	var refs []string
	if b := item.Repository.DefaultBranch; b != "" {
		refs = append(refs, b)
	}
	for _, b := range []string{"main", "master"} {
		if !contains(refs, b) {
			refs = append(refs, b)
		}
	}
	if b, err := c.DefaultBranch(ctx, repo); err == nil && !contains(refs, b) {
		refs = append(refs, b)
	}

	var lastErr error
	for _, ref := range refs {
		data, err := c.fetchRaw(ctx, repo, ref, item.Path)
		if err != nil {
			lastErr = err
			continue
		}
		if item.SHA != "" && BlobSHA(data) != item.SHA {
			lastErr = errBlobMismatch
			continue
		}
		c.store(item.SHA, data)
		return data, "raw:" + ref, nil
	}

	if item.SHA != "" {
		data, err := c.fetchBlob(ctx, repo, item.SHA)
		if err == nil {
			c.store(item.SHA, data)
			return data, "blob", nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("no reachable ref")
	}
	return nil, "", lastErr
}

func (c *Client) store(sha string, data []byte) {
	if sha == "" {
		return
	}
	if err := c.cache.PutRaw(sha, data); err != nil {
		c.notify("could not cache blob %s: %v", sha[:min(8, len(sha))], err)
	}
}

func (c *Client) fetchRaw(ctx context.Context, repo, ref, path string) ([]byte, error) {
	u := fmt.Sprintf("%s/%s/%s/%s", c.raw, repo, url.PathEscape(ref), escapePath(path))
	req, err := c.newRequest(ctx, http.MethodGet, u, "application/vnd.github.raw")
	if err != nil {
		return nil, err
	}
	body, err := c.do(ctx, req, c.fetchLim)
	c.mu.Lock()
	c.rawCalls++
	c.mu.Unlock()
	return body, err
}

func (c *Client) fetchBlob(ctx context.Context, repo, sha string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, c.base+"/repos/"+repo+"/git/blobs/"+sha, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	body, err := c.do(ctx, req, c.fetchLim)
	c.mu.Lock()
	c.apiCalls++
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	var blob struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &blob); err != nil {
		return nil, err
	}
	if blob.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected blob encoding %q", blob.Encoding)
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.Content, "\n", ""))
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
