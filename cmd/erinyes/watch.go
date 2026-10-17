// ©AngelaMos | 2026
// watch.go

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
)

type watchOptions struct {
	targetsFile string
	targets     []string
	stateFile   string
	intervalMin int
	webhookURL  string
	tgToken     string
	tgChatID    string
	once        bool
	noNotify    bool
	rps         float64
	cacheDir    string
}

type repoState struct {
	Repo       string            `json:"repo"`
	DefBranch  string            `json:"default_branch"`
	LastSHA    string            `json:"last_commit_sha"`
	LastPushed string            `json:"last_pushed_at"`
	Stars      int               `json:"stars"`
	Forks      int               `json:"forks"`
	Tree       map[string]string `json:"tree_blobsha_by_path"`
	Updated    string            `json:"updated_at"`
}

type watchState struct {
	Repos map[string]*repoState `json:"repos"`
}

func newWatchCommand(g *globals) *cobra.Command {
	opts := watchOptions{}

	cmd := &cobra.Command{
		Use:   "watch [owner/repo ...]",
		Short: "Poll a set of GitHub repositories and announce new commits, file changes, and release-wave bursts",
		Long: "Watch tracks the five (or N) active sockpuppet repositories you give it and\n" +
			"announces whenever any one of them gets a new commit, when a tracked file's\n" +
			"blob SHA changes, and when a cluster of repos push within a tight window (a\n" +
			"release wave). State persists across runs in a JSON file so a new push since\n" +
			"last run fires exactly once.\n\n" +
			"Notification channels (set any one — or none for stdout-only):\n" +
			"  --telegram-token / --telegram-chat   Telegram bot API (TELEGRAM_BOT_TOKEN env)\n" +
			"  --webhook URL                        generic POST { 'text': ... } webhook\n" +
			"\n" +
			"Examples:\n" +
			"  erinyes watch --once hkqr/my-free-code letorig/video-generator-client\n" +
			"  erinyes watch --targets-file active.txt --interval 15\n" +
			"  erinyes watch --once hkqr/my-free-code gunkonchi/xscrape --webhook https://hooks.slack.com/...",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}
			opts.targets = args
			if opts.targetsFile != "" {
				extra, err := readTargets(opts.targetsFile)
				if err != nil {
					return fail(exitToolError, "read targets file: %w", err)
				}
				opts.targets = append(opts.targets, extra...)
			}
			if len(opts.targets) == 0 {
				return fail(exitToolError, "give at least one owner/repo on the command line or via --targets-file")
			}
			opts.targets = dedupeStrings(opts.targets)

			if opts.tgToken == "" {
				opts.tgToken = os.Getenv("TELEGRAM_BOT_TOKEN")
			}
			if opts.tgChatID == "" {
				opts.tgChatID = os.Getenv("TELEGRAM_CHAT_ID")
			}

			return runWatch(cmd.Context(), g, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.targetsFile, "targets-file", "f", "", "file with one owner/repo per line (lines starting with # are ignored)")
	cmd.Flags().StringVar(&opts.stateFile, "state", "", "path to the state JSON (default: ~/.cache/erinyes/watch-state.json)")
	cmd.Flags().IntVar(&opts.intervalMin, "interval", 15, "poll interval in minutes (default 15, min 5)")
	cmd.Flags().StringVar(&opts.webhookURL, "webhook", "", "POST a JSON {\"text\": \"...\"} to this URL on each event")
	cmd.Flags().StringVar(&opts.tgToken, "telegram-token", "", "Telegram bot token (or $TELEGRAM_BOT_TOKEN)")
	cmd.Flags().StringVar(&opts.tgChatID, "telegram-chat", "", "Telegram chat id (or $TELEGRAM_CHAT_ID)")
	cmd.Flags().BoolVar(&opts.once, "once", false, "run one poll pass and exit (default: loop until interrupted)")
	cmd.Flags().BoolVar(&opts.noNotify, "no-notify", false, "print to stdout only, do not send any webhook/telegram message")
	cmd.Flags().Float64Var(&opts.rps, "rps", 2, "requests-per-second cap for the GitHub client")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "blob cache dir (default: XDG cache)")

	return cmd
}

func readTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func resolveStateFile(cfgPath string) string {
	if cfgPath != "" {
		return cfgPath
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "erinyes-watch-state.json"
		}
		cache = filepath.Join(home, ".cache")
	}
	return filepath.Join(cache, "erinyes", "watch-state.json")
}

func loadWatchState(path string) *watchState {
	st := &watchState{Repos: map[string]*repoState{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, st)
	if st.Repos == nil {
		st.Repos = map[string]*repoState{}
	}
	return st
}

func saveWatchState(path string, st *watchState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type event struct {
	Repo      string
	Kind      string
	Headline  string
	Detail    string
	Timestamp time.Time
}

func (e event) format() string {
	ts := e.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	out := fmt.Sprintf("[%s] [%s] %s\n%s", ts, e.Kind, e.Headline, e.Repo)
	if e.Detail != "" {
		out += "\n" + e.Detail
	}
	return out
}

func runWatch(ctx context.Context, g *globals, opts watchOptions) error {
	stateFile := resolveStateFile(opts.stateFile)

	cacheDir := opts.cacheDir
	if cacheDir == "" {
		cacheDir = g.cfg.ResolvedCacheDir()
	}
	cache, err := gh.NewCache(cacheDir)
	if err != nil {
		return fail(exitToolError, "cache: %w", err)
	}
	client, err := gh.New(gh.Options{
		Cache:     cache,
		RPS:       opts.rps,
		UserAgent: "erinyes/" + version,
		Notify: func(format string, args ...any) {
			_, _ = fmt.Fprintf(g.errOut(), "  "+format+"\n", args...)
		},
	})
	if err != nil {
		return fail(exitToolError, "%w", err)
	}

	if opts.intervalMin < 5 {
		opts.intervalMin = 5
	}

	_, _ = fmt.Fprintf(g.errOut(), "watching %d repo(s), interval=%dm, state=%s\n", len(opts.targets), opts.intervalMin, stateFile)
	for _, r := range opts.targets {
		_, _ = fmt.Fprintf(g.errOut(), "  - %s\n", r)
	}

	if opts.webhookURL == "" && (opts.tgToken == "" || opts.tgChatID == "") && !opts.noNotify {
		_, _ = fmt.Fprintf(g.errOut(), "no --webhook or --telegram-token/--telegram-chat (and $TELEGRAM_BOT_TOKEN/$TELEGRAM_CHAT_ID empty); events will print to stdout only\n")
	}

	for {
		if err := watchPass(ctx, g, client, opts, stateFile); err != nil {
			_, _ = fmt.Fprintf(g.errOut(), "pass error: %v\n", err)
		}
		if opts.once {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(opts.intervalMin) * time.Minute):
		}
	}
}

func watchPass(ctx context.Context, g *globals, client *gh.Client, opts watchOptions, stateFile string) error {
	st := loadWatchState(stateFile)

	var events []event
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, repo := range opts.targets {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			local, err := checkOne(ctx, client, repo, st)
			if err != nil {
				mu.Lock()
				events = append(events, event{Repo: repo, Kind: "ERROR", Headline: "poll failed", Detail: err.Error(), Timestamp: time.Now()})
				mu.Unlock()
				return
			}
			mu.Lock()
			events = append(events, local...)
			mu.Unlock()
		}(repo)
	}
	wg.Wait()

	burst := detectBurst(events, 15*time.Minute)
	if burst != nil {
		events = append(events, *burst)
	}

	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })

	for _, e := range events {
		msg := e.format()
		_, _ = fmt.Fprintf(g.out(), "%s\n---\n", msg)
		if opts.noNotify {
			continue
		}
		if opts.webhookURL != "" {
			if err := postWebhook(ctx, opts.webhookURL, msg); err != nil {
				_, _ = fmt.Fprintf(g.errOut(), "webhook: %v\n", err)
			}
		}
		if opts.tgToken != "" && opts.tgChatID != "" {
			if err := sendTelegram(ctx, opts.tgToken, opts.tgChatID, msg); err != nil {
				_, _ = fmt.Fprintf(g.errOut(), "telegram: %v\n", err)
			}
		}
	}

	return saveWatchState(stateFile, st)
}

func checkOne(ctx context.Context, client *gh.Client, repo string, st *watchState) ([]event, error) {
	meta, err := client.GetRepo(ctx, repo)
	if err != nil {
		return nil, err
	}

	blobs, _, err := client.Tree(ctx, meta)
	if err != nil {
		return nil, fmt.Errorf("tree: %w", err)
	}

	tree := make(map[string]string, len(blobs))
	for _, b := range blobs {
		if strings.HasSuffix(b.Path, ".py") || strings.HasSuffix(b.Path, ".md") {
			tree[b.Path] = b.SHA
		}
	}

	prev, seen := st.Repos[repo]
	now := time.Now()
	var events []event

	if !seen {
		st.Repos[repo] = &repoState{
			Repo:       repo,
			DefBranch:  meta.DefaultBranch,
			LastPushed: meta.PushedAt,
			Stars:      meta.Stars,
			Forks:      meta.Forks,
			Tree:       tree,
			Updated:    now.UTC().Format(time.RFC3339),
		}
		events = append(events, event{
			Repo: repo, Kind: "BASELINE",
			Headline:  fmt.Sprintf("first observation (%d .py/.md tracked)", len(tree)),
			Detail:    fmt.Sprintf("default_branch=%s  stars=%d  forks=%d  pushed=%s", meta.DefaultBranch, meta.Stars, meta.Forks, meta.PushedAt),
			Timestamp: now,
		})
		return events, nil
	}

	if prev.LastPushed != meta.PushedAt {
		added, changed, removed := diffTrees(prev.Tree, tree)
		detail := fmt.Sprintf("pushed_at: %s -> %s\nstars: %d -> %d  forks: %d -> %d", prev.LastPushed, meta.PushedAt, prev.Stars, meta.Stars, prev.Forks, meta.Forks)
		if len(added)+len(changed)+len(removed) > 0 {
			detail += "\nchanged files:"
			for _, p := range added {
				detail += fmt.Sprintf("\n  + %s", p)
			}
			for _, p := range changed {
				detail += fmt.Sprintf("\n  M %s   %s -> %s", p, prev.Tree[p][:8], tree[p][:8])
			}
			for _, p := range removed {
				detail += fmt.Sprintf("\n  - %s", p)
			}
		}
		pushedTS, _ := time.Parse(time.RFC3339, meta.PushedAt)
		if pushedTS.IsZero() {
			pushedTS = now
		}
		events = append(events, event{
			Repo: repo, Kind: "PUSH",
			Headline:  fmt.Sprintf("%d added, %d changed, %d removed", len(added), len(changed), len(removed)),
			Detail:    detail,
			Timestamp: pushedTS,
		})
	}

	prev.LastPushed = meta.PushedAt
	prev.Stars = meta.Stars
	prev.Forks = meta.Forks
	prev.Tree = tree
	prev.DefBranch = meta.DefaultBranch
	prev.Updated = now.UTC().Format(time.RFC3339)
	return events, nil
}

func diffTrees(oldT, newT map[string]string) (added, changed, removed []string) {
	for p, sha := range newT {
		if prev, ok := oldT[p]; !ok {
			added = append(added, p)
		} else if prev != sha {
			changed = append(changed, p)
		}
	}
	for p := range oldT {
		if _, ok := newT[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)
	return
}

func detectBurst(events []event, window time.Duration) *event {
	var pushes []event
	for _, e := range events {
		if e.Kind == "PUSH" {
			pushes = append(pushes, e)
		}
	}
	if len(pushes) < 2 {
		return nil
	}
	sort.Slice(pushes, func(i, j int) bool { return pushes[i].Timestamp.Before(pushes[j].Timestamp) })
	spread := pushes[len(pushes)-1].Timestamp.Sub(pushes[0].Timestamp)
	if spread > window {
		return nil
	}
	repos := make([]string, 0, len(pushes))
	for _, p := range pushes {
		repos = append(repos, p.Repo)
	}
	return &event{
		Repo:      "<multiple>",
		Kind:      "RELEASE-WAVE",
		Headline:  fmt.Sprintf("%d repos pushed within %s", len(pushes), spread.Round(time.Second)),
		Detail:    "repos: " + strings.Join(repos, ", ") + "\n(this matches the observed pipeline: 5+ repos pushed in the same window = coordinated release)",
		Timestamp: pushes[len(pushes)-1].Timestamp,
	}
}

func postWebhook(ctx context.Context, url, text string) error {
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func sendTelegram(ctx context.Context, token, chatID, text string) error {
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		var body [512]byte
		n, _ := resp.Body.Read(body[:])
		return fmt.Errorf("telegram returned %d: %s", resp.StatusCode, string(body[:n]))
	}
	return nil
}

var _ = errors.New
