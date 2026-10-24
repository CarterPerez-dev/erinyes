// Copyright AngelaMos | 2026
// watch_test.go

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
)

func TestWatchConcurrentRepositoriesPersistAndAdvance(t *testing.T) {
	var revision atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/git/trees/") {
			_, _ = fmt.Fprintf(w, `{"tree":[{"path":"loader.py","type":"blob","sha":"%040d"},{"path":"ignored.txt","type":"blob","sha":"%040d"}]}`, revision.Load(), revision.Load())
			return
		}
		repo := strings.TrimPrefix(r.URL.Path, "/repos/")
		_, _ = fmt.Fprintf(w, `{"full_name":%q,"default_branch":"main","pushed_at":"2026-10-23T12:%02d:00Z"}`, repo, revision.Load())
	}))
	defer server.Close()

	client, err := gh.New(gh.Options{Token: "test-token", BaseURL: server.URL, HTTPClient: server.Client(), Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	g := &globals{stdout: &output, stderr: io.Discard}
	opts := watchOptions{noNotify: true}
	for i := range 32 {
		opts.targets = append(opts.targets, fmt.Sprintf("example/repo-%02d", i))
	}
	stateFile := filepath.Join(t.TempDir(), "watch-state.json")
	ctx := context.Background()

	if err := watchPass(ctx, g, client, opts, stateFile); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(output.String(), "[BASELINE]"); got != len(opts.targets) {
		t.Fatalf("baseline events = %d, want %d", got, len(opts.targets))
	}
	if got := len(loadWatchState(stateFile).Repos); got != len(opts.targets) {
		t.Fatalf("persisted repositories = %d, want %d", got, len(opts.targets))
	}

	output.Reset()
	if err := watchPass(ctx, g, client, opts, stateFile); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("unchanged repositories emitted events: %s", output.String())
	}

	revision.Store(1)
	if err := watchPass(ctx, g, client, opts, stateFile); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(output.String(), "[PUSH]"); got != len(opts.targets) {
		t.Fatalf("push events = %d, want %d", got, len(opts.targets))
	}
	if strings.Count(output.String(), "[RELEASE-WAVE]") != 1 {
		t.Fatalf("expected one grouped event: %s", output.String())
	}
	for repo, state := range loadWatchState(stateFile).Repos {
		if len(state.Tree) != 1 || state.Tree["loader.py"] != fmt.Sprintf("%040d", 1) {
			t.Errorf("%s has incorrect tracked state: %#v", repo, state.Tree)
		}
	}
}
