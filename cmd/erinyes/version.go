// ©AngelaMos | 2026
// version.go

package main

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/erinyes"
)

var (
	version = "dev"
	commit  = ""
	date    = ""
)

var errFlagged = errors.New("one or more files matched a signature at or above its confidence threshold")

func init() {
	if version == "dev" {
		version = moduleVersion()
	}
}

func moduleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func buildInfo() (string, string) {
	c, d := commit, date
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return c, d
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "" {
				c = s.Value
			}
		case "vcs.time":
			if d == "" {
				d = s.Value
			}
		}
	}
	return c, d
}

func newVersionCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tool version, catalog version and Go runtime",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, d := buildInfo()
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "erinyes    %s\n", version)
			if c != "" {
				_, _ = fmt.Fprintf(out, "commit     %s\n", c)
			}
			if d != "" {
				_, _ = fmt.Fprintf(out, "built      %s\n", d)
			}
			_, _ = fmt.Fprintf(out, "catalog    schema v%s\n", erinyes.CatalogVersion)
			_, _ = fmt.Fprintf(out, "go         %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)

			if err := g.load(); err == nil {
				_, _ = fmt.Fprintf(out, "signatures %d loaded\n", g.catalog.Len())
				for _, s := range g.catalog.All() {
					_, _ = fmt.Fprintf(out, "           %s  (%s, %s)\n", s.Label(), s.Family, s.Source())
				}
			}
			return nil
		},
	}
}
