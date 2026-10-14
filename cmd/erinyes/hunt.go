// ©AngelaMos | 2026
// hunt.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/scan"
	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

type huntOptions struct {
	limit        int
	cacheDir     string
	noCache      bool
	rps          float64
	searchTTL    time.Duration
	workers      int
	includeForks bool
	dryRun       bool
}

func newHuntCommand(g *globals) *cobra.Command {
	opts := huntOptions{}

	cmd := &cobra.Command{
		Use:   "hunt <signature-id|all>",
		Short: "Retrohunt GitHub for new instances of a signature",
		Long: "Hunt runs every github_queries entry declared by the selected signature(s)\n" +
			"against GitHub code search, fetches each result, and scans it locally.\n\n" +
			"Needs a token: $GITHUB_TOKEN, $GH_TOKEN, or an authenticated `gh` CLI.\n" +
			"Code search is capped at 10 requests per minute by GitHub, so a wide hunt\n" +
			"is paced, not fast. Fetched blobs are cached forever by their git blob sha.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}
			return runHunt(cmd.Context(), g, args[0], opts)
		},
	}

	cmd.Flags().IntVar(&opts.limit, "limit", 0, "stop after this many search results per query (0 = all, GitHub caps at 1000)")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "directory for the blob and search cache (default: XDG cache dir)")
	cmd.Flags().BoolVar(&opts.noCache, "no-cache", false, "do not read or write the on-disk cache")
	cmd.Flags().Float64Var(&opts.rps, "rps", 0, "override the signature's retrohunt.rate_limit_rps")
	cmd.Flags().DurationVar(&opts.searchTTL, "search-ttl", time.Hour, "reuse cached search responses younger than this (0 disables)")
	cmd.Flags().IntVar(&opts.workers, "workers", 4, "concurrent file fetches")
	cmd.Flags().BoolVar(&opts.includeForks, "include-forks", false, "include results from forked repositories")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the queries that would run and exit")

	return cmd
}

type target struct {
	item SearchHit
	sg   *sig.Signature
}

type SearchHit struct {
	gh.SearchItem
	Query string
}

func selectSignatures(g *globals, id string) ([]*sig.Signature, error) {
	if id == "all" {
		sigs := g.catalog.All()
		if len(sigs) == 0 {
			return nil, fail(exitToolError, "no signatures loaded")
		}
		return sigs, nil
	}
	s, ok := g.catalog.Get(id)
	if !ok {
		var ids []string
		for _, c := range g.catalog.All() {
			ids = append(ids, c.ID)
		}
		sort.Strings(ids)
		return nil, fail(exitToolError, "no signature with id %q (loaded: %s)", id, strings.Join(ids, ", "))
	}
	return []*sig.Signature{s}, nil
}

func runHunt(ctx context.Context, g *globals, id string, opts huntOptions) error {
	start := time.Now()

	sigs, err := selectSignatures(g, id)
	if err != nil {
		return err
	}

	var queries []string
	rps := opts.rps
	for _, s := range sigs {
		if len(s.Retrohunt.GitHubQueries) == 0 {
			_, _ = fmt.Fprintf(g.errOut(), "note: signature %s declares no retrohunt queries, skipping\n", s.ID)
			continue
		}
		queries = append(queries, s.Retrohunt.GitHubQueries...)
		if opts.rps == 0 && (rps == 0 || s.RateLimitRPS() < rps) {
			rps = s.RateLimitRPS()
		}
	}
	if len(queries) == 0 {
		return fail(exitToolError, "no retrohunt queries declared by the selected signature(s)")
	}
	queries = dedupeStrings(queries)

	if opts.dryRun {
		_, _ = fmt.Fprintf(g.out(), "%d quer(ies) for %d signature(s):\n", len(queries), len(sigs))
		for _, q := range queries {
			_, _ = fmt.Fprintf(g.out(), "  %s\n", q)
		}
		_, _ = fmt.Fprintf(g.out(), "\nrate: %.3f req/s for fetches, %d req/min cap on code search\n", rps, gh.SearchRequestsPerMinute)
		return nil
	}

	cacheDir := opts.cacheDir
	if cacheDir == "" {
		cacheDir = g.cfg.ResolvedCacheDir()
	}
	if opts.noCache {
		cacheDir = ""
	}
	cache, err := gh.NewCache(cacheDir)
	if err != nil {
		return fail(exitToolError, "cache: %w", err)
	}

	client, err := gh.New(gh.Options{
		Cache:     cache,
		RPS:       rps,
		UserAgent: "erinyes/" + version,
		Notify: func(format string, args ...any) {
			_, _ = fmt.Fprintf(g.errOut(), "  "+format+"\n", args...)
		},
	})
	if err != nil {
		return fail(exitToolError, "%w", err)
	}

	hits, err := searchAll(ctx, g, client, sigs, queries, opts)
	if err != nil {
		return huntError(err)
	}

	entries, summary, err := fetchAndScan(ctx, client, g, hits, opts)
	if err != nil {
		return huntError(err)
	}
	summary.DurationMS = time.Since(start).Milliseconds()

	apiCalls, rawCalls, cacheHits := client.Stats()
	_, _ = fmt.Fprintf(g.errOut(), "\n%d api call(s), %d raw fetch(es), %d cache hit(s)\n", apiCalls, rawCalls, cacheHits)
	if rl := client.RateLimit(); rl.Known() {
		_, _ = fmt.Fprintf(g.errOut(), "rate limit %s: %d/%d remaining, resets %s\n", rl.Resource, rl.Remaining, rl.Limit, rl.Reset.Format(time.Kitchen))
	}

	rules := make([]report.Rule, 0, len(sigs))
	for _, s := range sigs {
		rules = append(rules, report.Rule{
			ID: s.ID, Family: s.Family, Version: s.Version, Severity: string(s.Severity),
			Description: s.Description, References: s.References, Threshold: s.ConfidenceThreshold,
		})
	}

	rep := &report.Report{
		Tool:      "erinyes",
		Version:   version,
		Mode:      "hunt",
		Target:    id,
		ScannedAt: time.Now(),
		Rules:     rules,
		Entries:   entries,
		Summary:   summary,
		Queries:   queries,
	}

	if err := g.emit(rep); err != nil {
		return err
	}
	if summary.Flagged > 0 {
		return &exitError{code: exitFound, err: errFlagged}
	}
	return nil
}

func huntError(err error) error {
	if errors.Is(err, gh.ErrRateLimited) {
		return &exitError{code: exitRateLimit, err: err}
	}
	if errors.Is(err, context.Canceled) {
		return &exitError{code: exitToolError, err: errors.New("cancelled")}
	}
	return fail(exitToolError, "%w", err)
}

func searchAll(ctx context.Context, g *globals, client *gh.Client, sigs []*sig.Signature, queries []string, opts huntOptions) ([]target, error) {
	byQuery := make(map[string]*sig.Signature, len(queries))
	for _, s := range sigs {
		for _, q := range s.Retrohunt.GitHubQueries {
			if _, taken := byQuery[q]; !taken {
				byQuery[q] = s
			}
		}
	}

	seen := make(map[string]struct{})
	var out []target

	for i, q := range queries {
		_, _ = fmt.Fprintf(g.errOut(), "[search %d/%d] %s\n", i+1, len(queries), q)
		items, total, err := client.SearchCode(ctx, q, opts.limit, opts.searchTTL)
		if err != nil {
			return out, err
		}
		_, _ = fmt.Fprintf(g.errOut(), "  total %d, pulled %d\n", total, len(items))

		for _, item := range items {
			if item.Repository.Fork && !opts.includeForks {
				continue
			}
			key := item.Repository.FullName + "\x00" + item.Path
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, target{item: SearchHit{SearchItem: item, Query: q}, sg: byQuery[q]})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].item.Repository.FullName != out[j].item.Repository.FullName {
			return out[i].item.Repository.FullName < out[j].item.Repository.FullName
		}
		return out[i].item.Path < out[j].item.Path
	})
	return out, nil
}

func fetchAndScan(ctx context.Context, client *gh.Client, g *globals, targets []target, opts huntOptions) ([]report.Entry, scan.Summary, error) {
	var summary scan.Summary
	if len(targets) == 0 {
		return nil, summary, nil
	}

	scanner := scan.New(g.catalog)

	bar := progressbar.NewOptions(len(targets),
		progressbar.OptionSetWriter(g.errOut()),
		progressbar.OptionSetDescription("fetching"),
		progressbar.OptionSetVisibility(isTerminal(os.Stderr)),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)

	workers := opts.workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	jobs := make(chan target)
	results := make(chan report.Entry, workers)

	var wg sync.WaitGroup
	var fetchErr error
	var errOnce sync.Once

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				data, origin, err := client.FetchItem(ctx, t.item.SearchItem)
				_ = bar.Add(1)
				if err != nil {
					if errors.Is(err, gh.ErrRateLimited) || errors.Is(err, context.Canceled) {
						errOnce.Do(func() { fetchErr = err })
						return
					}
					e := report.Entry{
						Repository: t.item.Repository.FullName,
						URL:        t.item.HTMLURL,
					}
					e.FilePath = t.item.Path
					e.ErrMessage = err.Error()
					e.Err = err
					results <- e
					continue
				}

				res := scanner.ScanBytes(t.item.Path, data, t.sg)
				results <- report.Entry{
					ScanResult: res,
					Repository: t.item.Repository.FullName,
					URL:        t.item.HTMLURL,
					Origin:     origin,
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case <-ctx.Done():
				errOnce.Do(func() { fetchErr = ctx.Err() })
				return
			case jobs <- t:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var entries []report.Entry
	for e := range results {
		summary.Observe(e.ScanResult)
		entries = append(entries, e)
	}
	_ = bar.Finish()

	if fetchErr != nil {
		return entries, summary, fetchErr
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].TotalScore != entries[j].TotalScore {
			return entries[i].TotalScore > entries[j].TotalScore
		}
		if entries[i].Repository != entries[j].Repository {
			return entries[i].Repository < entries[j].Repository
		}
		return entries[i].FilePath < entries[j].FilePath
	})
	return entries, summary, nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
