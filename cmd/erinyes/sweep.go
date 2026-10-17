// ©AngelaMos | 2026
// sweep.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes/internal/gh"
	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

type sweepOptions struct {
	query        string
	limit        int
	maxFiles     int
	cacheDir     string
	noCache      bool
	rps          float64
	workers      int
	includeForks bool
	includeArch  bool
	maxFileSize  int64
	dryRun       bool
	bulkAfter    int
	forceBlobs   bool
}

func newSweepCommand(g *globals) *cobra.Command {
	opts := sweepOptions{}

	cmd := &cobra.Command{
		Use:   "sweep [owner | owner/repo]",
		Short: "Scan whole GitHub repositories, not just what code search indexed",
		Long: "Sweep enumerates repositories, walks each one's git tree, and scans every\n" +
			"file matching a signature's file_patterns.\n\n" +
			"Where `hunt` asks GitHub's code index what it already knows, sweep reads the\n" +
			"repositories themselves. That reaches files the index never covered, which is\n" +
			"how a low-star repository with a fresh payload stays invisible to hunt.\n\n" +
			"Targets:\n" +
			"  erinyes sweep someowner                 every repository that owner has\n" +
			"  erinyes sweep someowner/somerepo        one repository\n" +
			"  erinyes sweep --query '<search>'        every repository matching a GitHub\n" +
			"                                          repository search\n\n" +
			"Blobs are cached by their git sha, so re-sweeping costs almost nothing.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			if target == "" && opts.query == "" {
				return fail(exitToolError, "give an owner, an owner/repo, or --query")
			}
			if target != "" && opts.query != "" {
				return fail(exitToolError, "pass a target or --query, not both")
			}
			return runSweep(cmd.Context(), g, target, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.query, "query", "q", "", "GitHub repository search instead of an owner (e.g. 'created:2026-01-02 pushed:2026-09-20')")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "stop after this many repositories (0 = all, GitHub caps search at 1000)")
	cmd.Flags().IntVar(&opts.maxFiles, "max-files", 0, "stop after this many candidate files per repository (0 = all)")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "directory for the blob cache (default: XDG cache dir)")
	cmd.Flags().BoolVar(&opts.noCache, "no-cache", false, "do not read or write the on-disk cache")
	cmd.Flags().Float64Var(&opts.rps, "rps", 0, "requests-per-second cap for blob fetches")
	cmd.Flags().IntVar(&opts.workers, "workers", 4, "concurrent blob fetches")
	cmd.Flags().BoolVar(&opts.includeForks, "include-forks", false, "include forked repositories")
	cmd.Flags().BoolVar(&opts.includeArch, "include-archived", false, "include archived repositories")
	cmd.Flags().Int64Var(&opts.maxFileSize, "max-file-size", scan.DefaultMaxFileSize, "skip blobs larger than this many bytes")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "list the repositories that would be swept and exit")
	cmd.Flags().IntVar(&opts.bulkAfter, "bulk-after", 20, "fetch a repository's tarball in one request once it has this many candidate files")
	cmd.Flags().BoolVar(&opts.forceBlobs, "no-bulk", false, "always fetch file by file, never the tarball")

	return cmd
}

func runSweep(ctx context.Context, g *globals, target string, opts sweepOptions) error {
	start := time.Now()

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

	rps := opts.rps
	if rps == 0 {
		rps = 10
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

	repos, err := resolveRepos(ctx, g, client, target, opts)
	if err != nil {
		return huntError(err)
	}
	if len(repos) == 0 {
		return fail(exitToolError, "no repositories matched")
	}

	if opts.dryRun {
		_, _ = fmt.Fprintf(g.out(), "%d repositor(y|ies) would be swept:\n", len(repos))
		for _, r := range repos {
			_, _ = fmt.Fprintf(g.out(), "  %-50s stars=%-6d created=%s pushed=%s\n",
				r.FullName, r.Stars, short(r.CreatedAt), short(r.PushedAt))
		}
		return nil
	}

	entries, summary, err := sweepRepos(ctx, g, client, repos, opts)
	if err != nil {
		return huntError(err)
	}
	summary.DurationMS = time.Since(start).Milliseconds()

	apiCalls, rawCalls, cacheHits := client.Stats()
	_, _ = fmt.Fprintf(g.errOut(), "\n%d repositor(y|ies), %d api call(s), %d raw fetch(es), %d cache hit(s)\n",
		len(repos), apiCalls, rawCalls, cacheHits)

	label := target
	if label == "" {
		label = opts.query
	}

	rep := &report.Report{
		Tool:      "erinyes",
		Version:   version,
		Mode:      "sweep",
		Target:    label,
		ScannedAt: time.Now(),
		Rules:     g.rules(),
		Entries:   entries,
		Summary:   summary,
	}
	if opts.query != "" {
		rep.Queries = []string{opts.query}
	}

	if err := g.emit(rep); err != nil {
		return err
	}
	if summary.Flagged > 0 {
		return &exitError{code: exitFound, err: errFlagged}
	}
	return nil
}

func resolveRepos(ctx context.Context, g *globals, client *gh.Client, target string, opts sweepOptions) ([]gh.Repository, error) {
	var repos []gh.Repository

	switch {
	case opts.query != "":
		_, _ = fmt.Fprintf(g.errOut(), "[search] %s\n", opts.query)
		found, total, err := client.SearchRepositories(ctx, opts.query, opts.limit)
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintf(g.errOut(), "  total %d, pulled %d\n", total, len(found))
		repos = found

	default:
		owner, name := gh.ParseSweepTarget(target)
		if name != "" {
			r, err := client.GetRepo(ctx, owner+"/"+name)
			if err != nil {
				return nil, err
			}
			repos = []gh.Repository{r}
		} else {
			_, _ = fmt.Fprintf(g.errOut(), "[repos] enumerating %s\n", owner)
			found, err := client.ListOwnerRepos(ctx, owner, opts.limit)
			if err != nil {
				return nil, err
			}
			_, _ = fmt.Fprintf(g.errOut(), "  %d repositor(y|ies)\n", len(found))
			repos = found
		}
	}

	kept := repos[:0]
	skippedForks, skippedArchived := 0, 0
	for _, r := range repos {
		if r.Fork && !opts.includeForks {
			skippedForks++
			continue
		}
		if r.Archived && !opts.includeArch {
			skippedArchived++
			continue
		}
		kept = append(kept, r)
	}
	if skippedForks > 0 {
		_, _ = fmt.Fprintf(g.errOut(), "  skipped %d fork(s), pass --include-forks to scan them\n", skippedForks)
	}
	if skippedArchived > 0 {
		_, _ = fmt.Fprintf(g.errOut(), "  skipped %d archived repositor(y|ies)\n", skippedArchived)
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].FullName < kept[j].FullName })
	return kept, nil
}

func sweepRepos(ctx context.Context, g *globals, client *gh.Client, repos []gh.Repository, opts sweepOptions) ([]report.Entry, scan.Summary, error) {
	var summary scan.Summary
	scanner := scan.New(g.catalog, scan.WithMaxFileSize(opts.maxFileSize))

	bar := progressbar.NewOptions(len(repos),
		progressbar.OptionSetWriter(g.errOut()),
		progressbar.OptionSetDescription("sweeping"),
		progressbar.OptionSetVisibility(isTerminal(os.Stderr)),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)

	workers := opts.workers
	if workers < 1 {
		workers = 1
	}

	var entries []report.Entry
	var fatal error
	empty := 0

	for _, repo := range repos {
		if ctx.Err() != nil {
			fatal = ctx.Err()
			break
		}

		blobs, truncated, err := client.Tree(ctx, repo)
		if err != nil {
			_ = bar.Add(1)
			if errors.Is(err, gh.ErrRateLimited) {
				fatal = err
				break
			}
			var he *gh.HTTPError
			if errors.As(err, &he) && he.NothingToRead() {
				summary.Skipped++
				empty++
				continue
			}
			summary.Errors++
			_, _ = fmt.Fprintf(g.errOut(), "  %s: %v\n", repo.FullName, err)
			continue
		}
		if truncated {
			_, _ = fmt.Fprintf(g.errOut(), "  %s: git tree was truncated by GitHub, some files were not seen\n", repo.FullName)
		}

		candidates := make([]gh.TreeEntry, 0, len(blobs))
		for _, b := range blobs {
			if len(g.catalog.For(b.Path)) == 0 {
				summary.Skipped++
				continue
			}
			if opts.maxFileSize > 0 && b.Size > opts.maxFileSize {
				summary.Skipped++
				continue
			}
			candidates = append(candidates, b)
			if opts.maxFiles > 0 && len(candidates) >= opts.maxFiles {
				break
			}
		}

		var got []report.Entry
		if !opts.forceBlobs && opts.bulkAfter > 0 && len(candidates) >= opts.bulkAfter {
			got, err = scanRepoTarball(ctx, client, scanner, repo, candidates, opts.maxFileSize)
		} else {
			got, err = scanRepoBlobs(ctx, client, scanner, repo, candidates, workers)
		}
		_ = bar.Add(1)
		if err != nil {
			fatal = err
			break
		}
		for _, e := range got {
			summary.Observe(e.ScanResult)
			entries = append(entries, e)
		}
	}
	_ = bar.Finish()

	if empty > 0 {
		_, _ = fmt.Fprintf(g.errOut(), "  %d repositor(y|ies) had no commits on the default branch\n", empty)
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

	if fatal != nil {
		return entries, summary, fatal
	}
	return entries, summary, nil
}

func scanRepoBlobs(ctx context.Context, client *gh.Client, scanner *scan.Scanner, repo gh.Repository, blobs []gh.TreeEntry, workers int) ([]report.Entry, error) {
	if len(blobs) == 0 {
		return nil, nil
	}
	if workers > len(blobs) {
		workers = len(blobs)
	}

	jobs := make(chan gh.TreeEntry)
	out := make(chan report.Entry, workers)

	var wg sync.WaitGroup
	var fatal error
	var once sync.Once

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				data, origin, err := client.Blob(ctx, repo, b)
				if err != nil {
					if errors.Is(err, gh.ErrRateLimited) || errors.Is(err, context.Canceled) {
						once.Do(func() { fatal = err })
						return
					}
					e := report.Entry{Repository: repo.FullName, URL: blobURL(repo, b)}
					e.FilePath = b.Path
					e.Err = err
					e.ErrMessage = err.Error()
					out <- e
					continue
				}

				best := report.Entry{}
				found := false
				for _, sg := range scanner.Catalog().For(b.Path) {
					res := scanner.ScanBytes(b.Path, data, sg)
					if !found || res.TotalScore > best.TotalScore {
						best = report.Entry{ScanResult: res, Repository: repo.FullName, URL: blobURL(repo, b), Origin: origin}
						found = true
					}
				}
				if found {
					out <- best
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, b := range blobs {
			select {
			case <-ctx.Done():
				once.Do(func() { fatal = ctx.Err() })
				return
			case jobs <- b:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var entries []report.Entry
	for e := range out {
		entries = append(entries, e)
	}
	return entries, fatal
}

func scanRepoTarball(ctx context.Context, client *gh.Client, scanner *scan.Scanner, repo gh.Repository, candidates []gh.TreeEntry, maxFileSize int64) ([]report.Entry, error) {
	wanted := make(map[string]gh.TreeEntry, len(candidates))
	for _, c := range candidates {
		wanted[c.Path] = c
	}

	files, err := client.Tarball(ctx, repo, func(path string, _ int64) bool {
		_, ok := wanted[path]
		return ok
	}, maxFileSize)
	if err != nil {
		if errors.Is(err, gh.ErrRateLimited) || errors.Is(err, context.Canceled) {
			return nil, err
		}
		return scanRepoBlobs(ctx, client, scanner, repo, candidates, 4)
	}

	entries := make([]report.Entry, 0, len(files))
	for _, f := range files {
		entry := wanted[f.Path]
		if entry.Path == "" {
			entry = gh.TreeEntry{Path: f.Path, SHA: f.SHA}
		}

		best := report.Entry{}
		found := false
		for _, sg := range scanner.Catalog().For(f.Path) {
			res := scanner.ScanBytes(f.Path, f.Data, sg)
			if !found || res.TotalScore > best.TotalScore {
				best = report.Entry{ScanResult: res, Repository: repo.FullName, URL: blobURL(repo, entry), Origin: "tarball"}
				found = true
			}
		}
		if found {
			entries = append(entries, best)
		}
	}
	return entries, nil
}

func blobURL(repo gh.Repository, b gh.TreeEntry) string {
	return fmt.Sprintf("https://github.com/%s/blob/%s/%s", repo.FullName, repo.Ref(), b.Path)
}

func short(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}
