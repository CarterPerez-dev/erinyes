// ©AngelaMos | 2026
// verify.go

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var hexSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func newVerifyCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <sha256|path>",
		Short: "Check a hash or a file against the catalog of known-malicious hashes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.load(); err != nil {
				return err
			}

			arg := args[0]
			digest := strings.ToLower(arg)
			origin := "argument"

			if !hexSHA256.MatchString(arg) {
				data, err := os.ReadFile(arg)
				if err != nil {
					return fail(exitToolError, "%q is neither a sha256 digest nor a readable file: %w", arg, err)
				}
				sum := sha256.Sum256(data)
				digest = hex.EncodeToString(sum[:])
				origin = fmt.Sprintf("%s (%d bytes)", arg, len(data))
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "sha256  %s\n", digest)
			_, _ = fmt.Fprintf(out, "source  %s\n", origin)

			found := false
			for _, s := range g.catalog.All() {
				kh, ok := s.MatchesKnownHash(digest)
				if !ok {
					continue
				}
				found = true
				_, _ = fmt.Fprintf(out, "\nKNOWN MALICIOUS\n")
				_, _ = fmt.Fprintf(out, "  signature  %s\n", s.Label())
				_, _ = fmt.Fprintf(out, "  family     %s\n", s.Family)
				_, _ = fmt.Fprintf(out, "  severity   %s\n", s.Severity)
				_, _ = fmt.Fprintf(out, "  label      %s\n", kh.Label)
				if kh.FirstSeen != "" {
					_, _ = fmt.Fprintf(out, "  first seen %s\n", kh.FirstSeen)
				}
			}

			if !found {
				_, _ = fmt.Fprintf(out, "\nNOT IN CATALOG\n")
				_, _ = fmt.Fprintf(out, "  checked against %d signature(s). This is not proof the file is clean.\n", g.catalog.Len())
				_, _ = fmt.Fprintf(out, "  run `erinyes scan <path>` for indicator-based detection.\n")
				return nil
			}
			return &exitError{code: exitFound, err: errFlagged}
		},
	}
}
