// ©AngelaMos | 2026
// loader.go

package sig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/erinyes"
)

const SchemaVersion = 1

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

type Catalog struct {
	sigs []*Signature
	byID map[string]*Signature
}

func NewCatalog() *Catalog {
	return &Catalog{byID: make(map[string]*Signature)}
}

func (c *Catalog) Add(s *Signature) error {
	if prev, dup := c.byID[s.ID]; dup {
		return fmt.Errorf("duplicate signature id %q (already loaded from %s, redefined in %s)", s.ID, prev.source, s.source)
	}
	c.byID[s.ID] = s
	c.sigs = append(c.sigs, s)
	return nil
}

func (c *Catalog) Replace(s *Signature) {
	if prev, dup := c.byID[s.ID]; dup {
		for i := range c.sigs {
			if c.sigs[i] == prev {
				c.sigs[i] = s
				c.byID[s.ID] = s
				return
			}
		}
	}
	c.byID[s.ID] = s
	c.sigs = append(c.sigs, s)
}

func (c *Catalog) Get(id string) (*Signature, bool) {
	s, ok := c.byID[id]
	return s, ok
}

func (c *Catalog) All() []*Signature {
	out := make([]*Signature, len(c.sigs))
	copy(out, c.sigs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *Catalog) Len() int { return len(c.sigs) }

func (c *Catalog) For(path string) []*Signature {
	var out []*Signature
	for _, s := range c.All() {
		if s.MatchesPath(path) {
			out = append(out, s)
		}
	}
	return out
}

func (c *Catalog) Patterns() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range c.sigs {
		for _, p := range s.FilePatterns {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Catalog) Labels() []string {
	out := make([]string, 0, len(c.sigs))
	for _, s := range c.All() {
		out = append(out, s.Label())
	}
	return out
}

func Parse(data []byte, source string) (*Signature, error) {
	var s Signature
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	s.source = source
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	s.indexHashes()
	return &s, nil
}

func (s *Signature) Validate() error {
	var errs []error

	if !idPattern.MatchString(s.ID) {
		errs = append(errs, fmt.Errorf("id %q must match %s", s.ID, idPattern.String()))
	}
	if s.Version != SchemaVersion {
		errs = append(errs, fmt.Errorf("version must be %d, got %d", SchemaVersion, s.Version))
	}
	if s.Family == "" {
		errs = append(errs, errors.New("family is required"))
	}
	if !s.Severity.Valid() {
		errs = append(errs, fmt.Errorf("severity %q must be one of critical, high, medium, low", s.Severity))
	}
	if s.ConfidenceThreshold < 0 || s.ConfidenceThreshold > 100 {
		errs = append(errs, fmt.Errorf("confidence_threshold %d must be in [0, 100]", s.ConfidenceThreshold))
	}
	if len(s.FilePatterns) == 0 {
		errs = append(errs, errors.New("at least one file_patterns entry is required"))
	}
	for _, p := range s.FilePatterns {
		if _, err := filepath.Match(p, "probe"); err != nil {
			errs = append(errs, fmt.Errorf("file_patterns entry %q is not a valid glob: %w", p, err))
		}
	}
	if len(s.Indicators) == 0 {
		errs = append(errs, errors.New("at least one indicator is required"))
	}

	seen := make(map[string]struct{}, len(s.Indicators))
	for i := range s.Indicators {
		ind := &s.Indicators[i]
		if ind.Name == "" {
			errs = append(errs, fmt.Errorf("indicator %d has no name", i))
			continue
		}
		if _, dup := seen[ind.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate indicator name %q", ind.Name))
		}
		seen[ind.Name] = struct{}{}
		if ind.Weight < 0 || ind.Weight > 100 {
			errs = append(errs, fmt.Errorf("indicator %q: weight %d must be in [0, 100]", ind.Name, ind.Weight))
		}
		if err := ind.compile(); err != nil {
			errs = append(errs, err)
		}
	}

	if max := s.MaxScore(); max < s.ConfidenceThreshold {
		errs = append(errs, fmt.Errorf("sum of indicator weights (%d) is below confidence_threshold (%d): signature can never fire", max, s.ConfidenceThreshold))
	}

	for i, kh := range s.KnownHashes {
		if !sha256Pattern.MatchString(kh.SHA256) {
			errs = append(errs, fmt.Errorf("known_hashes[%d]: %q is not a 64-character hex sha256", i, kh.SHA256))
		}
	}

	if s.Retrohunt.RateLimitRPS < 0 {
		errs = append(errs, fmt.Errorf("retrohunt.rate_limit_rps %v must not be negative", s.Retrohunt.RateLimitRPS))
	}

	return errors.Join(errs...)
}

func LoadFS(fsys fs.FS, root, sourcePrefix string, into *Catalog, replace bool) error {
	entries, err := fs.Glob(fsys, path(root, "*.yaml"))
	if err != nil {
		return err
	}
	more, err := fs.Glob(fsys, path(root, "*.yml"))
	if err != nil {
		return err
	}
	entries = append(entries, more...)
	sort.Strings(entries)

	for _, name := range entries {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		s, err := Parse(data, joinSource(sourcePrefix, name))
		if err != nil {
			return err
		}
		if replace {
			into.Replace(s)
			continue
		}
		if err := into.Add(s); err != nil {
			return err
		}
	}
	return nil
}

func LoadDir(dir string, into *Catalog, replace bool) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(dir)
		if err != nil {
			return err
		}
		s, err := Parse(data, dir)
		if err != nil {
			return err
		}
		if replace {
			into.Replace(s)
			return nil
		}
		return into.Add(s)
	}
	return LoadFS(os.DirFS(dir), ".", dir, into, replace)
}

func joinSource(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return filepath.Join(prefix, filepath.FromSlash(name))
}

func path(root, pattern string) string {
	if root == "" || root == "." {
		return pattern
	}
	return root + "/" + pattern
}

func LoadBuiltin(into *Catalog) error {
	return LoadFS(erinyes.Signatures, "signatures", "builtin", into, false)
}

type LoadOptions struct {
	Override string
	UserDir  string
}

func Load(opts LoadOptions) (*Catalog, error) {
	cat := NewCatalog()

	if opts.Override != "" {
		if err := LoadDir(opts.Override, cat, false); err != nil {
			return nil, err
		}
		if cat.Len() == 0 {
			return nil, fmt.Errorf("no signatures found in %s", opts.Override)
		}
		return cat, nil
	}

	if err := LoadBuiltin(cat); err != nil {
		return nil, err
	}

	if opts.UserDir != "" {
		if _, err := os.Stat(opts.UserDir); err == nil {
			if err := LoadDir(opts.UserDir, cat, true); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	return cat, nil
}
