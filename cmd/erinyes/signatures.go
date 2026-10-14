// ©AngelaMos | 2026
// signatures.go

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

func newSignaturesCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "signatures",
		Aliases: []string{"sig", "sigs"},
		Short:   "Inspect, lint and print the signature catalog",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newSignaturesListCommand(g), newSignaturesValidateCommand(g), newSignaturesShowCommand(g))
	return cmd
}

func newSignaturesListCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every loaded signature",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tFAMILY\tSEVERITY\tTHRESHOLD\tMAX\tINDICATORS\tHASHES\tPATTERNS\tSOURCE")
			for _, s := range g.catalog.All() {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
					s.ID, s.Family, s.Severity, s.ConfidenceThreshold, s.MaxScore(),
					len(s.Indicators), len(s.KnownHashes), strings.Join(s.FilePatterns, ","), s.Source())
			}
			if err := tw.Flush(); err != nil {
				return fail(exitToolError, "%w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n%d signature(s) loaded\n", g.catalog.Len())
			return nil
		},
	}
}

func newSignaturesValidateCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <path>",
		Short: "Lint a signature YAML file or directory before shipping it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			files, err := yamlFiles(target)
			if err != nil {
				return fail(exitToolError, "%w", err)
			}
			if len(files) == 0 {
				return fail(exitToolError, "no .yaml or .yml files found at %s", target)
			}

			out := cmd.OutOrStdout()
			cat := sig.NewCatalog()
			bad := 0

			for _, f := range files {
				data, err := os.ReadFile(f)
				if err != nil {
					bad++
					_, _ = fmt.Fprintf(out, "FAIL  %s\n      %v\n", f, err)
					continue
				}
				s, err := sig.Parse(data, f)
				if err != nil {
					bad++
					_, _ = fmt.Fprintf(out, "FAIL  %s\n", f)
					for _, line := range strings.Split(err.Error(), "\n") {
						_, _ = fmt.Fprintf(out, "      %s\n", line)
					}
					continue
				}
				if err := cat.Add(s); err != nil {
					bad++
					_, _ = fmt.Fprintf(out, "FAIL  %s\n      %v\n", f, err)
					continue
				}
				_, _ = fmt.Fprintf(out, "OK    %s  (%s, %d indicators, max score %d, threshold %d)\n",
					f, s.ID, len(s.Indicators), s.MaxScore(), s.ConfidenceThreshold)
				for _, warning := range warnings(s) {
					_, _ = fmt.Fprintf(out, "WARN  %s\n", warning)
				}
			}

			_, _ = fmt.Fprintf(out, "\n%d file(s) checked, %d failed\n", len(files), bad)
			if bad > 0 {
				return &exitError{code: exitToolError, err: fmt.Errorf("%d signature file(s) failed validation", bad)}
			}
			return nil
		},
	}
}

func warnings(s *sig.Signature) []string {
	var out []string
	if s.ConfidenceThreshold == 0 {
		out = append(out, "confidence_threshold is 0: every scanned file will be reported malicious")
	}
	if s.MaxScore() == s.ConfidenceThreshold {
		out = append(out, "threshold equals the sum of all weights: every indicator must fire for a hit")
	}
	if len(s.Retrohunt.GitHubQueries) == 0 {
		out = append(out, "no retrohunt.github_queries: this signature cannot be hunted on GitHub")
	}
	if s.Description == "" {
		out = append(out, "no description: contributors and reports will have no context")
	}
	for i := range s.Indicators {
		if s.Indicators[i].Weight == 0 {
			out = append(out, fmt.Sprintf("indicator %q has weight 0 and cannot affect the score", s.Indicators[i].Name))
		}
	}
	return out
}

func newSignaturesShowCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Print the full definition of one signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}
			s, ok := g.catalog.Get(args[0])
			if !ok {
				ids := make([]string, 0, g.catalog.Len())
				for _, c := range g.catalog.All() {
					ids = append(ids, c.ID)
				}
				sort.Strings(ids)
				return fail(exitToolError, "no signature with id %q (loaded: %s)", args[0], strings.Join(ids, ", "))
			}
			enc := yaml.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent(2)
			if err := enc.Encode(s); err != nil {
				return fail(exitToolError, "%w", err)
			}
			return enc.Close()
		},
	}
}

func yamlFiles(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{target}, nil
	}
	var out []string
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		matches, err := filepath.Glob(filepath.Join(target, pattern))
		if err != nil {
			return nil, err
		}
		out = append(out, matches...)
	}
	sort.Strings(out)
	return out, nil
}
