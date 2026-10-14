// ©AngelaMos | 2026
// indicator_test.go

package sig_test

import (
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

func builtinPyMapper(t *testing.T) *sig.Signature {
	t.Helper()
	cat := sig.NewCatalog()
	if err := sig.LoadBuiltin(cat); err != nil {
		t.Fatalf("LoadBuiltin() = %v", err)
	}
	s, ok := cat.Get("pymapper-fs-loader")
	if !ok {
		t.Fatal("builtin catalog has no pymapper-fs-loader")
	}
	return s
}

func indicatorByName(t *testing.T, s *sig.Signature, name string) *sig.Indicator {
	t.Helper()
	for i := range s.Indicators {
		if s.Indicators[i].Name == name {
			return &s.Indicators[i]
		}
	}
	t.Fatalf("signature %s has no indicator %q", s.ID, name)
	return nil
}

func TestPyMapperIndicators(t *testing.T) {
	s := builtinPyMapper(t)

	cases := []struct {
		indicator string
		positive  []string
		negative  []string
	}{
		{
			indicator: "xor_decoder_lambda",
			positive: []string{
				`_rd9r1n=lambda a,k:bytes(v^k for v in a)`,
				`_spd980k = lambda a , k : bytes( v ^ k for v in a )`,
				`decrypt = lambda data, key: bytes(b ^ key for b in data)`,
			},
			negative: []string{
				`def xor(a, k): return bytes(v ^ k for v in a)`,
				`f = lambda a, k: bytes(v + k for v in a)`,
				`g = lambda a: bytes(a)`,
			},
		},
		{
			indicator: "import_via_xor_decoder",
			positive: []string{
				`_x=__import__(_rd9r1n([30,23,5],118).decode())`,
				`__import__( _f( [ 109,123 ],23).decode())`,
			},
			negative: []string{
				`__import__("marshal")`,
				`__import__(name)`,
				`importlib.import_module(mod)`,
			},
		},
		{
			indicator: "rolling_xor_checksum",
			positive: []string{
				` return sum((w[i]+p)^i for i in range(len(w)))&255`,
				`return sum( ( w[i] + p ) ^ i for i in range(len(w)) ) & 255`,
			},
			negative: []string{
				`return sum(w[i] for i in range(len(w))) & 255`,
				`return sum((w[i]+p)^i for i in range(len(w)))`,
			},
		},
		{
			indicator: "hmac_keystream_block",
			positive: []string{
				`t=min(32,len(d)-p)`,
				`take = min( 32 , len(data) - offset )`,
			},
			negative: []string{
				`t = min(16, len(d) - p)`,
				`t = min(32, length - offset)`,
				`t = max(32, len(d) - p)`,
			},
		},
		{
			indicator: "embedded_encrypted_blob",
			positive: []string{
				"[" + repeatInts(81) + "0]",
			},
			negative: []string{
				"[" + repeatInts(40) + "0]",
				`[1, 2, 3]`,
				`[]`,
			},
		},
		{
			indicator: "getattr_name_hiding",
			positive: []string{
				`getattr(m,_f([1,2,3],4).decode())`,
				`getattr( module , decode( [ 9 ] ) )`,
			},
			negative: []string{
				`getattr(module, "attribute")`,
				`getattr(m, name)`,
				`getattr(m, decode(s, k).decode())`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.indicator, func(t *testing.T) {
			ind := indicatorByName(t, s, tc.indicator)
			for _, p := range tc.positive {
				if n := ind.Count([]byte(p)); n == 0 {
					t.Errorf("indicator %s did not match positive sample:\n  %s", tc.indicator, p)
				}
			}
			for _, n := range tc.negative {
				if c := ind.Count([]byte(n)); c != 0 {
					t.Errorf("indicator %s matched negative sample %d time(s):\n  %s", tc.indicator, c, n)
				}
			}
		})
	}
}

func TestEveryBuiltinIndicatorHasATest(t *testing.T) {
	s := builtinPyMapper(t)
	covered := map[string]bool{
		"xor_decoder_lambda":      true,
		"import_via_xor_decoder":  true,
		"rolling_xor_checksum":    true,
		"hmac_keystream_block":    true,
		"embedded_encrypted_blob": true,
		"getattr_name_hiding":     true,
	}
	for i := range s.Indicators {
		if !covered[s.Indicators[i].Name] {
			t.Errorf("indicator %q has no positive/negative fixtures in TestPyMapperIndicators", s.Indicators[i].Name)
		}
	}
}

func TestLiteralIndicatorCountsOccurrences(t *testing.T) {
	s := mustParse(t, minimal)
	ind := indicatorByName(t, s, "beta")
	if n := ind.Count([]byte("beta-literal and beta-literal again")); n != 2 {
		t.Errorf("Count() = %d, want 2", n)
	}
	if n := ind.Count([]byte("nothing here")); n != 0 {
		t.Errorf("Count() = %d, want 0", n)
	}
}

func TestCountIsPureOnBytes(t *testing.T) {
	s := builtinPyMapper(t)
	ind := indicatorByName(t, s, "xor_decoder_lambda")
	data := []byte(`x=lambda a,k:bytes(v^k for v in a)`)
	before := string(data)
	ind.Count(data)
	if string(data) != before {
		t.Error("Count() mutated the input buffer")
	}
}

func repeatInts(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += "7,"
	}
	return out
}
