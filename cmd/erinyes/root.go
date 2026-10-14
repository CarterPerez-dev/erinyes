// ©AngelaMos | 2026
// root.go

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes/internal/config"
	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

type globals struct {
	signaturesPath string
	format         string
	outputPath     string
	verbose        bool
	noColor        bool

	cfg     *config.Config
	catalog *sig.Catalog
	fmtKind report.Format
	stdout  io.Writer
	stderr  io.Writer
}

func (g *globals) out() io.Writer {
	if g.stdout != nil {
		return g.stdout
	}
	return os.Stdout
}

func (g *globals) errOut() io.Writer {
	if g.stderr != nil {
		return g.stderr
	}
	return os.Stderr
}

func (g *globals) load() error {
	cfg, err := config.Load()
	if err != nil {
		return fail(exitToolError, "config: %w", err)
	}
	g.cfg = cfg

	if g.format == "" {
		g.format = cfg.Format
	}
	if g.format == "" {
		g.format = string(report.FormatCLI)
	}
	kind, err := report.ParseFormat(g.format)
	if err != nil {
		return fail(exitToolError, "%w", err)
	}
	g.fmtKind = kind

	if cfg.NoColor {
		g.noColor = true
	}
	if os.Getenv("NO_COLOR") != "" {
		g.noColor = true
	}
	if g.fmtKind != report.FormatCLI || g.outputPath != "" {
		g.noColor = true
	}

	catalog, err := sig.Load(sig.LoadOptions{
		Override: g.signaturesPath,
		UserDir:  cfg.ResolvedSignaturesDir(),
	})
	if err != nil {
		return fail(exitToolError, "signatures: %w", err)
	}
	g.catalog = catalog
	return nil
}

func (g *globals) rules() []report.Rule {
	out := make([]report.Rule, 0, g.catalog.Len())
	for _, s := range g.catalog.All() {
		out = append(out, report.Rule{
			ID:          s.ID,
			Family:      s.Family,
			Version:     s.Version,
			Severity:    string(s.Severity),
			Description: s.Description,
			References:  s.References,
			Threshold:   s.ConfidenceThreshold,
		})
	}
	return out
}

func (g *globals) emit(rep *report.Report) error {
	opts := report.Options{Verbose: g.verbose, NoColor: g.noColor}

	if g.outputPath == "" {
		if err := report.Write(g.out(), g.fmtKind, rep, opts); err != nil {
			return fail(exitToolError, "write report: %w", err)
		}
		return nil
	}

	if dir := filepath.Dir(g.outputPath); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fail(exitToolError, "create output directory: %w", err)
		}
	}

	f, err := os.Create(g.outputPath)
	if err != nil {
		return fail(exitToolError, "open output file: %w", err)
	}

	writeErr := report.Write(f, g.fmtKind, rep, opts)
	closeErr := f.Close()

	if writeErr != nil {
		return fail(exitToolError, "write report: %w", writeErr)
	}
	if closeErr != nil {
		return fail(exitToolError, "close report file: %w", closeErr)
	}

	_, _ = fmt.Fprintf(g.errOut(), "wrote %s report to %s\n", g.fmtKind, g.outputPath)
	return nil
}

func newRootCommand() *cobra.Command {
	g := &globals{}

	cmd := &cobra.Command{
		Use:   "erinyes",
		Short: "Hunt obfuscated malware hiding in open source",
		Long: "Erinyes applies a catalog of YAML signatures against source files to find\n" +
			"trojanized packages hiding in the open, locally or across GitHub.\n\n" +
			"Scan mode never touches the network.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			g.stdout = cmd.OutOrStdout()
			g.stderr = cmd.ErrOrStderr()
		},
	}

	cmd.PersistentFlags().StringVar(&g.signaturesPath, "signatures", "", "load signatures from this file or directory instead of the builtin catalog")
	cmd.PersistentFlags().StringVar(&g.format, "format", "", "output format: cli, json, markdown, sarif (default cli)")
	cmd.PersistentFlags().StringVarP(&g.outputPath, "output", "o", "", "write the report to this file instead of stdout")
	cmd.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "show clean and errored files too")
	cmd.PersistentFlags().BoolVar(&g.noColor, "no-color", false, "disable ANSI colors")

	cmd.AddCommand(
		newScanCommand(g),
		newHuntCommand(g),
		newVerifyCommand(g),
		newSignaturesCommand(g),
		newVersionCommand(g),
	)
	return cmd
}
