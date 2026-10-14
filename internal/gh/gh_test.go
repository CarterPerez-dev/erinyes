// ©AngelaMos | 2026
// gh_test.go

package gh_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
)

const payload = "_rd9r1n=lambda a,k:bytes(v^k for v in a)\n"

func newItem(repo, path, sha string) gh.SearchItem {
	item := gh.SearchItem{Name: filepath.Base(path), Path: path, SHA: sha}
	item.Repository.FullName = repo
	item.Repository.DefaultBranch = "main"
	item.HTMLURL = "https://github.com/" + repo + "/blob/main/" + path
	return item
}

type stubServer struct {
	*httptest.Server
	searchCalls atomic.Int64
	rawCalls    atomic.Int64
	blobCalls   atomic.Int64
	repoCalls   atomic.Int64
}

func newStub(t *testing.T, total int) *stubServer {
	t.Helper()
	s := &stubServer{}
	sha := gh.BlobSHA([]byte(payload))

	mux := http.NewServeMux()
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, r *http.Request) {
		s.searchCalls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page == 0 {
			page = 1
		}

		start := (page - 1) * perPage
		var items []gh.SearchItem
		for i := start; i < start+perPage && i < total; i++ {
			items = append(items, newItem(fmt.Sprintf("owner/repo%d", i), "pkg/mod.py", sha))
		}
		w.Header().Set("X-RateLimit-Limit", "10")
		w.Header().Set("X-RateLimit-Remaining", "9")
		w.Header().Set("X-RateLimit-Resource", "code_search")
		writeJSON(w, map[string]any{"total_count": total, "items": items})
	})
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			s.blobCalls.Add(1)
			writeJSON(w, map[string]any{
				"content":  base64.StdEncoding.EncodeToString([]byte(payload)),
				"encoding": "base64",
			})
		default:
			s.repoCalls.Add(1)
			writeJSON(w, map[string]any{"default_branch": "trunk"})
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.rawCalls.Add(1)
		if strings.Contains(r.URL.Path, "/main/") || strings.Contains(r.URL.Path, "/trunk/") {
			fmt.Fprint(w, payload)
			return
		}
		http.NotFound(w, r)
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newClient(t *testing.T, srv *stubServer, cacheDir string) *gh.Client {
	t.Helper()
	cache, err := gh.NewCache(cacheDir)
	if err != nil {
		t.Fatalf("NewCache() = %v", err)
	}
	c, err := gh.New(gh.Options{
		Token:          "test-token",
		Cache:          cache,
		RPS:            1000,
		BaseURL:        srv.URL,
		RawURL:         srv.URL,
		Retries:        2,
		SearchInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	return c
}

func TestSearchCodePaginates(t *testing.T) {
	srv := newStub(t, 250)
	c := newClient(t, srv, t.TempDir())

	items, total, err := c.SearchCode(context.Background(), "q", 0, 0)
	if err != nil {
		t.Fatalf("SearchCode() = %v", err)
	}
	if total != 250 {
		t.Errorf("total = %d, want 250", total)
	}
	if len(items) != 250 {
		t.Errorf("got %d items, want 250", len(items))
	}
	if got := srv.searchCalls.Load(); got != 3 {
		t.Errorf("made %d search calls, want 3 pages of 100", got)
	}
}

func TestSearchCodeRespectsLimit(t *testing.T) {
	srv := newStub(t, 250)
	c := newClient(t, srv, t.TempDir())

	items, _, err := c.SearchCode(context.Background(), "q", 30, 0)
	if err != nil {
		t.Fatalf("SearchCode() = %v", err)
	}
	if len(items) != 30 {
		t.Errorf("got %d items, want 30", len(items))
	}
	if got := srv.searchCalls.Load(); got != 1 {
		t.Errorf("made %d search calls, want 1", got)
	}
}

func TestSearchResponsesAreCachedWithinTTL(t *testing.T) {
	srv := newStub(t, 5)
	dir := t.TempDir()

	c1 := newClient(t, srv, dir)
	if _, _, err := c1.SearchCode(context.Background(), "q", 0, time.Hour); err != nil {
		t.Fatalf("first SearchCode() = %v", err)
	}
	first := srv.searchCalls.Load()

	c2 := newClient(t, srv, dir)
	items, _, err := c2.SearchCode(context.Background(), "q", 0, time.Hour)
	if err != nil {
		t.Fatalf("second SearchCode() = %v", err)
	}
	if len(items) != 5 {
		t.Errorf("cached search returned %d items, want 5", len(items))
	}
	if srv.searchCalls.Load() != first {
		t.Errorf("second search hit the network: %d calls, want it served from cache", srv.searchCalls.Load())
	}
}

func TestSearchCacheIsBypassedWithZeroTTL(t *testing.T) {
	srv := newStub(t, 5)
	dir := t.TempDir()

	c := newClient(t, srv, dir)
	if _, _, err := c.SearchCode(context.Background(), "q", 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.SearchCode(context.Background(), "q", 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := srv.searchCalls.Load(); got != 2 {
		t.Errorf("made %d search calls, want 2 with caching disabled", got)
	}
}

func TestFetchItemCachesByBlobSHA(t *testing.T) {
	srv := newStub(t, 1)
	dir := t.TempDir()
	item := newItem("owner/repo", "pkg/mod.py", gh.BlobSHA([]byte(payload)))

	c1 := newClient(t, srv, dir)
	data, origin, err := c1.FetchItem(context.Background(), item)
	if err != nil {
		t.Fatalf("FetchItem() = %v", err)
	}
	if string(data) != payload {
		t.Errorf("content = %q", data)
	}
	if !strings.HasPrefix(origin, "raw:") {
		t.Errorf("origin = %q, want a raw fetch", origin)
	}
	rawAfterFirst := srv.rawCalls.Load()

	c2 := newClient(t, srv, dir)
	data, origin, err = c2.FetchItem(context.Background(), item)
	if err != nil {
		t.Fatalf("second FetchItem() = %v", err)
	}
	if origin != "cache" {
		t.Errorf("origin = %q, want cache", origin)
	}
	if string(data) != payload {
		t.Errorf("cached content = %q", data)
	}
	if srv.rawCalls.Load() != rawAfterFirst {
		t.Error("a cached blob was downloaded again")
	}

	_, _, cacheHits := c2.Stats()
	if cacheHits != 1 {
		t.Errorf("cacheHits = %d, want 1", cacheHits)
	}
}

func TestFetchItemFallsBackToBlobAPIOnSHAMismatch(t *testing.T) {
	srv := newStub(t, 1)
	c := newClient(t, srv, t.TempDir())

	item := newItem("owner/repo", "pkg/mod.py", gh.BlobSHA([]byte("different content entirely")))
	_, origin, err := c.FetchItem(context.Background(), item)
	if err != nil {
		t.Fatalf("FetchItem() = %v", err)
	}
	if origin != "blob" {
		t.Errorf("origin = %q, want the git blobs API fallback when raw content does not match the search sha", origin)
	}
	if srv.blobCalls.Load() == 0 {
		t.Error("the blobs API was never called")
	}
}

func TestFetchItemTriesTheDefaultBranch(t *testing.T) {
	srv := newStub(t, 1)
	c := newClient(t, srv, t.TempDir())

	item := newItem("owner/repo", "pkg/mod.py", gh.BlobSHA([]byte(payload)))
	item.Repository.DefaultBranch = ""

	data, origin, err := c.FetchItem(context.Background(), item)
	if err != nil {
		t.Fatalf("FetchItem() = %v", err)
	}
	if string(data) != payload {
		t.Errorf("content = %q", data)
	}
	if !strings.HasPrefix(origin, "raw:") {
		t.Errorf("origin = %q", origin)
	}
}

func TestSecondaryRateLimitIsRetriedThenGivesUp(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"You have exceeded a secondary rate limit"}`)
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, err := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: 2, SearchInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = c.SearchCode(context.Background(), "q", 0, 0)
	if !errors.Is(err, gh.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("made %d attempts, want the initial try plus 2 retries", got)
	}
}

func TestPrimaryRateLimitSleepsUntilReset(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("X-RateLimit-Limit", "10")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Resource", "code_search")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"total_count": 0, "items": []gh.SearchItem{}})
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, err := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: 3, SearchInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, _, err := c.SearchCode(context.Background(), "q", 0, 0); err != nil {
		t.Fatalf("SearchCode() = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("waited %s for a reset that was already in the past", elapsed)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d calls, want a retry after the reset", calls.Load())
	}
}

func TestUnauthorizedIsNotRetried(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, _ := gh.New(gh.Options{Token: "bad", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: 3, SearchInterval: time.Millisecond})

	_, _, err := c.SearchCode(context.Background(), "q", 0, 0)
	if err == nil {
		t.Fatal("SearchCode() accepted a 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want it to mention the 401", err)
	}
	if calls.Load() != 1 {
		t.Errorf("made %d calls, a 401 must not be retried", calls.Load())
	}
}

func TestServerErrorsAreRetried(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"total_count": 0, "items": []gh.SearchItem{}})
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, _ := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: 3, SearchInterval: time.Millisecond})

	start := time.Now()
	if _, _, err := c.SearchCode(context.Background(), "q", 0, 0); err != nil {
		t.Fatalf("SearchCode() = %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d calls, want one retry after the 502", calls.Load())
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("backoff of %s is too long for a single 502", elapsed)
	}
}

func TestAuthHeadersAreSet(t *testing.T) {
	var auth, accept, apiVer, ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		accept = r.Header.Get("Accept")
		apiVer = r.Header.Get("X-GitHub-Api-Version")
		ua = r.Header.Get("User-Agent")
		writeJSON(w, map[string]any{"total_count": 0, "items": []gh.SearchItem{}})
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, _ := gh.New(gh.Options{Token: "secret", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, UserAgent: "erinyes/test", SearchInterval: time.Millisecond})
	if _, _, err := c.SearchCode(context.Background(), "q", 0, 0); err != nil {
		t.Fatal(err)
	}

	if auth != "Bearer secret" {
		t.Errorf("Authorization = %q", auth)
	}
	if accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", accept)
	}
	if apiVer == "" {
		t.Error("X-GitHub-Api-Version was not sent")
	}
	if ua != "erinyes/test" {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestBlobSHAMatchesGit(t *testing.T) {
	if got := gh.BlobSHA([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Errorf("BlobSHA() = %q, want git's hash-object output for \"hello\\n\"", got)
	}
	if got := gh.BlobSHA(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Errorf("BlobSHA(empty) = %q, want git's empty blob hash", got)
	}
}

func TestCacheIsOptional(t *testing.T) {
	c, err := gh.NewCache("")
	if err != nil {
		t.Fatalf("NewCache(\"\") = %v", err)
	}
	if c.Enabled() {
		t.Error("an empty cache dir must disable caching")
	}
	if err := c.PutRaw("abcdef", []byte("x")); err != nil {
		t.Errorf("PutRaw() on a disabled cache = %v", err)
	}
	if _, ok := c.GetRaw("abcdef"); ok {
		t.Error("GetRaw() returned a hit from a disabled cache")
	}
}

func TestCacheSurvivesACorruptEntry(t *testing.T) {
	dir := t.TempDir()
	c, err := gh.NewCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "search", "not-json.json")
	if err := os.WriteFile(bad, []byte("{{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.GetSearch("anything", time.Hour); ok {
		t.Error("GetSearch() reported a hit for a query it never stored")
	}
}

func TestTokenPrefersEnvironment(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "from-env")
	tok, err := gh.Token()
	if err != nil {
		t.Fatalf("Token() = %v", err)
	}
	if tok != "from-env" {
		t.Errorf("Token() = %q, want from-env", tok)
	}
}

func TestLimiterPacesRequests(t *testing.T) {
	lim := gh.NewLimiter(20)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := lim.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("4 waits at 20rps took %s, want at least 150ms of pacing", elapsed)
	}
}

func TestLimiterRespectsCancellation(t *testing.T) {
	lim := gh.NewLimiter(0.01)
	ctx, cancel := context.WithCancel(context.Background())
	if err := lim.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := lim.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait() = %v, want context.Canceled", err)
	}
}

func TestSearchIntervalDefaultsToGitHubsCodeSearchCap(t *testing.T) {
	srv := newStub(t, 150)
	cache, _ := gh.NewCache("")
	c, err := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = c.SearchCode(ctx, "q", 0, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the second page to be paced past the 2s deadline by the %d req/min cap",
			err, gh.SearchRequestsPerMinute)
	}
	if got := srv.searchCalls.Load(); got != 1 {
		t.Errorf("made %d search calls inside 2s, want 1", got)
	}
}
