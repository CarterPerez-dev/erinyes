// ©AngelaMos | 2026
// bench_test.go

package scan_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/scan"
)

func BenchmarkScanBytesMaliciousFixture(b *testing.B) {
	data, err := os.ReadFile(filepath.Join(maliciousDir, "pymapper_template_rd9r1n.py"))
	if err != nil {
		b.Fatal(err)
	}
	cat := builtinCatalogB(b)
	s, _ := cat.Get("pymapper-fs-loader")
	scanner := scan.New(cat)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res := scanner.ScanBytes("x.py", data, s); res.TotalScore != 140 {
			b.Fatalf("score = %d", res.TotalScore)
		}
	}
}

func BenchmarkScanTreeOfOneThousandFiles(b *testing.B) {
	dir := b.TempDir()
	sample, err := os.ReadFile(filepath.Join(benignDir, "crc_table.py"))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("pkg%02d", i%20))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("mod%04d.py", i)), sample, 0o644); err != nil {
			b.Fatal(err)
		}
	}

	scanner := scan.New(builtinCatalogB(b))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, summary, err := scanner.ScanPath(ctx, dir)
		if err != nil {
			b.Fatal(err)
		}
		if summary.Scanned != 1000 {
			b.Fatalf("scanned %d", summary.Scanned)
		}
	}
}
