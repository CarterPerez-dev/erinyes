// ©AngelaMos | 2026
// repo_test.go

package gh_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
)

type repoStub struct {
	*httptest.Server
	searchCalls atomic.Int64
	treeCalls   atomic.Int64
	rawCalls    atomic.Int64
	blobCalls   atomic.Int64
	listCalls   atomic.Int64
}

func newRepoStub(t *testing.T, totalRepos int) *repoStub {
	t.Helper()
	s := &repoStub{}
	sha := gh.BlobSHA([]byte(payload))

	mkRepo := func(i int) map[string]any {
		return map[string]any{
			"full_name":      fmt.Sprintf("owner/repo%d", i),
			"default_branch": "main",
			"html_url":       fmt.Sprintf("https://github.com/owner/repo%d", i),
			"fork":           i%7 == 0,
			"archived":       i%11 == 0,
			"created_at":     "2026-01-02T00:00:00Z",
			"pushed_at":      "2026-09-20T00:00:00Z",
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		s.searchCalls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page == 0 {
			page = 1
		}
		items := []map[string]any{}
		for i := (page - 1) * perPage; i < page*perPage && i < totalRepos; i++ {
			items = append(items, mkRepo(i))
		}
		writeJSON(w, map[string]any{"total_count": totalRepos, "items": items})
	})
	mux.HandleFunc("/users/owner/repos", func(w http.ResponseWriter, r *http.Request) {
		s.listCalls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		items := []map[string]any{}
		for i := (page - 1) * 100; i < page*100 && i < totalRepos; i++ {
			items = append(items, mkRepo(i))
		}
		writeJSON(w, items)
	})
	mux.HandleFunc("/orgs/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/trees/"):
			s.treeCalls.Add(1)
			writeJSON(w, map[string]any{
				"sha":       "treesha",
				"truncated": false,
				"tree": []map[string]any{
					{"path": "pkg/mod.py", "type": "blob", "sha": sha, "size": len(payload)},
					{"path": "README.md", "type": "blob", "sha": "readmesha", "size": 10},
					{"path": "pkg", "type": "tree", "sha": "dirsha"},
					{"path": "big.py", "type": "blob", "sha": "bigsha", "size": 999999999},
				},
			})
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			s.blobCalls.Add(1)
			writeJSON(w, map[string]any{
				"content":  base64.StdEncoding.EncodeToString([]byte(payload)),
				"encoding": "base64",
			})
		default:
			writeJSON(w, mkRepo(1))
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.rawCalls.Add(1)
		fmt.Fprint(w, payload)
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func newRepoClient(t *testing.T, srv *repoStub, cacheDir string) *gh.Client {
	t.Helper()
	cache, err := gh.NewCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gh.New(gh.Options{
		Token:              "t",
		Cache:              cache,
		RPS:                1000,
		BaseURL:            srv.URL,
		RawURL:             srv.URL,
		SearchInterval:     time.Millisecond,
		RepoSearchInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSearchRepositoriesPaginates(t *testing.T) {
	srv := newRepoStub(t, 250)
	c := newRepoClient(t, srv, t.TempDir())

	repos, total, err := c.SearchRepositories(context.Background(), "created:2026-01-02", 0)
	if err != nil {
		t.Fatalf("SearchRepositories() = %v", err)
	}
	if total != 250 {
		t.Errorf("total = %d, want 250", total)
	}
	if len(repos) != 250 {
		t.Errorf("got %d repos, want 250", len(repos))
	}
	if srv.searchCalls.Load() != 3 {
		t.Errorf("made %d search calls, want 3", srv.searchCalls.Load())
	}
}

func TestSearchRepositoriesRespectsLimit(t *testing.T) {
	srv := newRepoStub(t, 250)
	c := newRepoClient(t, srv, t.TempDir())

	repos, _, err := c.SearchRepositories(context.Background(), "q", 40)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 40 {
		t.Errorf("got %d repos, want 40", len(repos))
	}
}

func TestListOwnerRepos(t *testing.T) {
	srv := newRepoStub(t, 150)
	c := newRepoClient(t, srv, t.TempDir())

	repos, err := c.ListOwnerRepos(context.Background(), "owner", 0)
	if err != nil {
		t.Fatalf("ListOwnerRepos() = %v", err)
	}
	if len(repos) != 150 {
		t.Errorf("got %d repos, want 150 across two pages", len(repos))
	}
}

func TestListOwnerReposUnknownOwner(t *testing.T) {
	srv := newRepoStub(t, 0)
	c := newRepoClient(t, srv, t.TempDir())

	if _, err := c.ListOwnerRepos(context.Background(), "nobody", 0); err == nil {
		t.Error("ListOwnerRepos() accepted an owner with no repositories")
	}
}

func TestTreeReturnsOnlyBlobs(t *testing.T) {
	srv := newRepoStub(t, 1)
	c := newRepoClient(t, srv, t.TempDir())

	repo := gh.Repository{FullName: "owner/repo0", DefaultBranch: "main"}
	blobs, truncated, err := c.Tree(context.Background(), repo)
	if err != nil {
		t.Fatalf("Tree() = %v", err)
	}
	if truncated {
		t.Error("truncated = true")
	}
	for _, b := range blobs {
		if b.Type != "blob" {
			t.Errorf("Tree() returned a %q entry, want only blobs", b.Type)
		}
	}
	if len(blobs) != 3 {
		t.Errorf("got %d blobs, want 3 (the tree entry must be dropped)", len(blobs))
	}
}

func TestBlobVerifiesAndCaches(t *testing.T) {
	srv := newRepoStub(t, 1)
	dir := t.TempDir()
	repo := gh.Repository{FullName: "owner/repo0", DefaultBranch: "main"}
	entry := gh.TreeEntry{Path: "pkg/mod.py", Type: "blob", SHA: gh.BlobSHA([]byte(payload))}

	c1 := newRepoClient(t, srv, dir)
	data, origin, err := c1.Blob(context.Background(), repo, entry)
	if err != nil {
		t.Fatalf("Blob() = %v", err)
	}
	if string(data) != payload {
		t.Errorf("content = %q", data)
	}
	if origin != "raw" {
		t.Errorf("origin = %q, want raw", origin)
	}

	c2 := newRepoClient(t, srv, dir)
	_, origin, err = c2.Blob(context.Background(), repo, entry)
	if err != nil {
		t.Fatal(err)
	}
	if origin != "cache" {
		t.Errorf("origin = %q, want cache on the second client", origin)
	}
}

func TestBlobFallsBackWhenRawDoesNotMatch(t *testing.T) {
	srv := newRepoStub(t, 1)
	c := newRepoClient(t, srv, t.TempDir())

	repo := gh.Repository{FullName: "owner/repo0", DefaultBranch: "main"}
	entry := gh.TreeEntry{Path: "pkg/mod.py", Type: "blob", SHA: gh.BlobSHA([]byte("something else"))}

	_, origin, err := c.Blob(context.Background(), repo, entry)
	if err != nil {
		t.Fatalf("Blob() = %v", err)
	}
	if origin != "blob" {
		t.Errorf("origin = %q, want the blobs API fallback", origin)
	}
}

func TestParseSweepTarget(t *testing.T) {
	cases := map[string][2]string{
		"owner":                          {"owner", ""},
		"owner/repo":                     {"owner", "repo"},
		"owner/":                         {"owner", ""},
		"https://github.com/owner/repo":  {"owner", "repo"},
		"https://github.com/owner/repo/": {"owner", "repo"},
		"  owner/repo  ":                 {"owner", "repo"},
	}
	for in, want := range cases {
		o, r := gh.ParseSweepTarget(in)
		if o != want[0] || r != want[1] {
			t.Errorf("ParseSweepTarget(%q) = (%q, %q), want (%q, %q)", in, o, r, want[0], want[1])
		}
	}
}

func TestRepoRef(t *testing.T) {
	if got := (gh.Repository{DefaultBranch: "trunk"}).Ref(); got != "trunk" {
		t.Errorf("Ref() = %q", got)
	}
	if got := (gh.Repository{}).Ref(); got != "HEAD" {
		t.Errorf("Ref() with no default branch = %q, want HEAD", got)
	}
}

func TestRepoSearchJSONDecode(t *testing.T) {
	var r gh.Repository
	body := `{"full_name":"a/b","default_branch":"main","stargazers_count":611,"fork":false,"archived":false,"created_at":"2026-01-02T18:51:37Z","pushed_at":"2026-09-20T17:21:32Z"}`
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if r.Stars != 611 || r.FullName != "a/b" || r.PushedAt[:10] != "2026-09-20" {
		t.Errorf("decoded = %+v", r)
	}
}

func TestEmptyRepositoriesAreDistinguishableFromRealErrors(t *testing.T) {
	cases := []struct {
		status        int
		body          string
		nothingToRead bool
	}{
		{http.StatusNotFound, `{"message":"Not Found"}`, true},
		{http.StatusConflict, `{"message":"Git Repository is empty."}`, true},
		{http.StatusInternalServerError, `{"message":"oops"}`, false},
		{http.StatusUnprocessableEntity, `{"message":"bad"}`, false},
	}

	for _, tc := range cases {
		status, body := tc.status, tc.body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}))

		cache, _ := gh.NewCache("")
		c, err := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: -1})
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = c.Tree(context.Background(), gh.Repository{FullName: "owner/repo", DefaultBranch: "main"})
		srv.Close()

		if err == nil {
			if tc.nothingToRead {
				continue
			}
			t.Errorf("status %d: Tree() returned no error", status)
			continue
		}

		var he *gh.HTTPError
		if !errors.As(err, &he) {
			if status >= 500 {
				continue
			}
			t.Errorf("status %d: error is not an *HTTPError: %v", status, err)
			continue
		}
		if he.NothingToRead() != tc.nothingToRead {
			t.Errorf("status %d: NothingToRead() = %v, want %v. An empty repository must not be reported as a scan error",
				status, he.NothingToRead(), tc.nothingToRead)
		}
	}
}

func TestRetriesCanBeDisabled(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, _ := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL, Retries: -1})

	if _, err := c.GetRepo(context.Background(), "owner/repo"); err == nil {
		t.Fatal("GetRepo() returned no error on a persistent 502")
	}
	if calls.Load() != 1 {
		t.Errorf("made %d attempts, want exactly 1 when retries are disabled", calls.Load())
	}
}

func TestRetriesDefaultWhenUnset(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	}))
	defer srv.Close()

	cache, _ := gh.NewCache("")
	c, _ := gh.New(gh.Options{Token: "t", Cache: cache, RPS: 1000, BaseURL: srv.URL, RawURL: srv.URL})

	if _, err := c.GetRepo(context.Background(), "owner/repo"); err != nil {
		t.Fatalf("GetRepo() = %v, want the default retry to recover", err)
	}
	if calls.Load() != 2 {
		t.Errorf("made %d attempts, want 2", calls.Load())
	}
}
