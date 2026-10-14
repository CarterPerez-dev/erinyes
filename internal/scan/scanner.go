// ©AngelaMos | 2026
// scanner.go

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

const (
	DefaultMaxFileSize       = 16 << 20
	concurrentIndicatorFloor = 50 << 10
)

var skipDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {},
}

type Scanner struct {
	catalog     *sig.Catalog
	workers     int
	maxFileSize int64
}

type Option func(*Scanner)

func WithWorkers(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.workers = n
		}
	}
}

func WithMaxFileSize(n int64) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.maxFileSize = n
		}
	}
}

func New(catalog *sig.Catalog, opts ...Option) *Scanner {
	s := &Scanner{
		catalog:     catalog,
		workers:     runtime.NumCPU(),
		maxFileSize: DefaultMaxFileSize,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Catalog() *sig.Catalog { return s.catalog }

func (s *Scanner) ScanBytes(name string, data []byte, sg *sig.Signature) ScanResult {
	start := time.Now()

	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])

	res := ScanResult{
		FilePath:   name,
		FileSHA256: hashHex,
		FileSize:   int64(len(data)),
		Threshold:  sg.ConfidenceThreshold,
		Signature:  sg.ID,
		Family:     sg.Family,
		Severity:   sg.Severity,
	}

	res.Hits = runIndicators(data, sg.Indicators)
	res.TotalScore = Score(res.Hits)
	res.Verdict = Classify(res.TotalScore, sg)

	if kh, ok := sg.MatchesKnownHash(hashHex); ok {
		res.KnownHash = kh.Label
		res.Verdict = VerdictMalicious
	}

	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func (s *Scanner) ScanFile(path string, sg *sig.Signature) ScanResult {
	data, err := s.read(path)
	if err != nil {
		res := ScanResult{FilePath: path, Signature: sg.ID}
		res.setErr(err)
		return res
	}
	return s.ScanBytes(path, data, sg)
}

func (s *Scanner) ScanFileAll(path string, sigs []*sig.Signature) []ScanResult {
	data, err := s.read(path)
	if err != nil {
		res := ScanResult{FilePath: path}
		res.setErr(err)
		return []ScanResult{res}
	}
	out := make([]ScanResult, 0, len(sigs))
	for _, sg := range sigs {
		out = append(out, s.ScanBytes(path, data, sg))
	}
	return out
}

func (s *Scanner) read(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > s.maxFileSize {
		return nil, &SkipError{Path: path, Size: info.Size(), Limit: s.maxFileSize}
	}
	return os.ReadFile(path)
}

type SkipError struct {
	Path  string
	Size  int64
	Limit int64
}

func (e *SkipError) Error() string {
	return "skipped: file is larger than the configured limit"
}

func (s *Scanner) ScanPath(ctx context.Context, root string) ([]ScanResult, Summary, error) {
	start := time.Now()
	info, err := os.Stat(root)
	if err != nil {
		return nil, Summary{}, err
	}

	var summary Summary

	if !info.IsDir() {
		sigs := s.catalog.All()
		results := s.best(s.ScanFileAll(root, sigs))
		for _, r := range results {
			summary.observe(r)
		}
		summary.DurationMS = time.Since(start).Milliseconds()
		return results, summary, nil
	}

	paths, skipped, err := s.walk(root)
	if err != nil {
		return nil, Summary{}, err
	}
	summary.Skipped = skipped

	results, err := s.scanAll(ctx, paths)
	if err != nil {
		return nil, Summary{}, err
	}
	results = s.best(results)
	for _, r := range results {
		summary.observe(r)
	}
	summary.DurationMS = time.Since(start).Milliseconds()
	return results, summary, nil
}

func (s *Scanner) walk(root string) ([]string, int, error) {
	var paths []string
	skipped := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				skipped++
				return nil
			}
			return err
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(s.catalog.For(p)) == 0 {
			skipped++
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	sort.Strings(paths)
	return paths, skipped, err
}

func (s *Scanner) scanAll(ctx context.Context, paths []string) ([]ScanResult, error) {
	workers := s.workers
	if workers > len(paths) {
		workers = len(paths)
	}
	if workers < 1 {
		return nil, nil
	}

	jobs := make(chan string)
	out := make(chan []ScanResult, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				out <- s.ScanFileAll(p, s.catalog.For(p))
			}
		}()
	}

	var feedErr error
	go func() {
		defer close(jobs)
		for _, p := range paths {
			select {
			case <-ctx.Done():
				feedErr = ctx.Err()
				return
			case jobs <- p:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []ScanResult
	for batch := range out {
		results = append(results, batch...)
	}
	if feedErr != nil {
		return nil, feedErr
	}
	return results, nil
}

func (s *Scanner) best(in []ScanResult) []ScanResult {
	index := make(map[string]int, len(in))
	var out []ScanResult
	for _, r := range in {
		i, seen := index[r.FilePath]
		if !seen {
			index[r.FilePath] = len(out)
			out = append(out, r)
			continue
		}
		if better(r, out[i]) {
			out[i] = r
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TotalScore != out[j].TotalScore {
			return out[i].TotalScore > out[j].TotalScore
		}
		return out[i].FilePath < out[j].FilePath
	})
	return out
}

func runIndicators(data []byte, indicators []sig.Indicator) []IndicatorHit {
	if len(indicators) == 0 {
		return nil
	}
	if len(data) < concurrentIndicatorFloor || len(indicators) == 1 {
		var hits []IndicatorHit
		for i := range indicators {
			if n := indicators[i].Count(data); n > 0 {
				hits = append(hits, IndicatorHit{Indicator: indicators[i].Name, MatchCount: n, Weight: indicators[i].Weight})
			}
		}
		return hits
	}

	counts := make([]int, len(indicators))
	var wg sync.WaitGroup
	for i := range indicators {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counts[i] = indicators[i].Count(data)
		}(i)
	}
	wg.Wait()

	var hits []IndicatorHit
	for i := range indicators {
		if counts[i] > 0 {
			hits = append(hits, IndicatorHit{Indicator: indicators[i].Name, MatchCount: counts[i], Weight: indicators[i].Weight})
		}
	}
	return hits
}
