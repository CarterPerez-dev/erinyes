// ©AngelaMos | 2026
// scan.go

package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes/internal/report"
	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

func baseDir(target string) string {
	info, err := os.Stat(target)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return target
	}
	return filepath.Dir(target)
}

func newScanCommand(g *globals) *cobra.Command {
	var (
		workers     int
		maxFileSize int64
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a local file or directory against the signature catalog",
		Long: "Scan walks a path and applies every signature whose file_patterns match.\n" +
			"A single explicitly named file is scanned against every loaded signature.\n" +
			"This command makes no network calls.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}

			scanner := scan.New(g.catalog, scan.WithWorkers(workers), scan.WithMaxFileSize(maxFileSize))
			results, summary, err := scanner.ScanPath(cmd.Context(), args[0])
			if err != nil {
				return fail(exitToolError, "scan %s: %w", args[0], err)
			}

			entries := make([]report.Entry, 0, len(results))
			for _, r := range results {
				entries = append(entries, report.Entry{ScanResult: r})
			}

			rep := &report.Report{
				Tool:      "erinyes",
				Version:   version,
				Mode:      "scan",
				Target:    args[0],
				BaseDir:   baseDir(args[0]),
				ScannedAt: time.Now(),
				Rules:     g.rules(),
				Entries:   entries,
				Summary:   summary,
			}

			if err := g.emit(rep); err != nil {
				return err
			}
			if summary.Flagged > 0 {
				return &exitError{code: exitFound, err: errFlagged}
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&workers, "workers", 0, "number of concurrent file workers (default: one per CPU)")
	cmd.Flags().Int64Var(&maxFileSize, "max-file-size", scan.DefaultMaxFileSize, "skip files larger than this many bytes")
	return cmd
}
