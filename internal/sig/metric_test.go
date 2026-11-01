// ©AngelaMos | 2026
// metric_test.go

package sig_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/erinyes/internal/sig"
)

func cp(points ...rune) string {
	return string(points)
}

func TestMetricMeasure(t *testing.T) {
	random := make([]byte, 3000)
	for i := range random {
		random[i] = byte((i*7919 + i*i*104729) % 251)
	}
	blob := base64.StdEncoding.EncodeToString(random)
	prose := strings.Repeat("the quick brown fox jumps over the lazy dog ", 20)

	bidi := "if x " + cp(0x202E) + "{ " + cp(0x2066) + "y" + cp(0x2069)
	hidden := "a" + cp(0x200B) + "b" + cp(0xE0041, 0xE0101, 0x3164)
	bom := cp(0xFEFF) + "print(1)"
	emoji := cp(0x2764, 0xFE0F) + " " + cp(0x1F468, 0x200D, 0x1F4BB) + " " + cp(0x200C)

	cases := []struct {
		name   string
		metric sig.Metric
		data   string
		check  func(float64) bool
	}{
		{"file size counts bytes", sig.MetricFileSize, "abcdef", func(v float64) bool { return v == 6 }},
		{"longest line wins", sig.MetricMaxLineLength, "ab\n" + strings.Repeat("x", 900) + "\ncd", func(v float64) bool { return v == 900 }},
		{"trailing line without newline", sig.MetricMaxLineLength, "a\nbbbb", func(v float64) bool { return v == 4 }},
		{"empty file has no lines", sig.MetricMaxLineLength, "", func(v float64) bool { return v == 0 }},
		{"base64 blob is high entropy", sig.MetricMaxLineEntropy, "x = 1\nblob = \"" + blob + "\"\n", func(v float64) bool { return v >= 5.8 }},
		{"english prose is low entropy", sig.MetricMaxLineEntropy, prose, func(v float64) bool { return v > 3 && v < 4.5 }},
		{"short lines are ignored for entropy", sig.MetricMaxLineEntropy, blob[:200], func(v float64) bool { return v == 0 }},
		{"bidi overrides are counted", sig.MetricBidiControls, bidi, func(v float64) bool { return v == 3 }},
		{"zero width and tag runes are counted", sig.MetricInvisibleRunes, hidden, func(v float64) bool { return v == 4 }},
		{"leading BOM is not invisible", sig.MetricInvisibleRunes, bom, func(v float64) bool { return v == 0 }},
		{"emoji joiners and selectors are not invisible", sig.MetricInvisibleRunes, emoji, func(v float64) bool { return v == 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v := tc.metric.Measure([]byte(tc.data)); !tc.check(v) {
				t.Errorf("%s.Measure() = %v", tc.metric, v)
			}
		})
	}
}

func TestMetricIndicatorFiresAtMin(t *testing.T) {
	data := []byte(strings.Repeat("y", 2000))
	for _, tc := range []struct {
		min      string
		wantHit  bool
		wantSeen float64
	}{
		{"2000", true, 2000},
		{"2001", false, 2000},
	} {
		s, err := sig.Parse([]byte(`
id: metric-probe
version: 1
family: Test
severity: low
confidence_threshold: 10
file_patterns: ["*"]
indicators:
  - name: long
    weight: 10
    type: metric
    metric: max_line_length
    min: `+tc.min+`
`), "probe.yaml")
		if err != nil {
			t.Fatalf("Parse() = %v", err)
		}
		n, v := s.Indicators[0].Eval(data)
		if (n > 0) != tc.wantHit || v != tc.wantSeen {
			t.Errorf("min %s: Eval() = (%d, %v), want hit=%v value=%v", tc.min, n, v, tc.wantHit, tc.wantSeen)
		}
	}
}

func TestMetricIndicatorValidation(t *testing.T) {
	base := `
id: metric-probe
version: 1
family: Test
severity: low
confidence_threshold: 10
file_patterns: ["*"]
indicators:
  - name: probe
    weight: 10
`
	cases := map[string]string{
		"unknown metric":         "    type: metric\n    metric: vibes\n    min: 1\n",
		"missing min":            "    type: metric\n    metric: file_size\n",
		"pattern on metric":      "    type: metric\n    metric: file_size\n    min: 1\n    pattern: x\n",
		"metric fields on regex": "    type: regex\n    pattern: x\n    metric: file_size\n    min: 1\n",
		"min on literal":         "    type: literal\n    pattern: x\n    min: 3\n",
	}
	for name, tail := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := sig.Parse([]byte(base+tail), "probe.yaml"); err == nil {
				t.Error("Parse() accepted an invalid metric indicator")
			}
		})
	}
}
