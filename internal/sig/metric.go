// ©AngelaMos | 2026
// metric.go

package sig

import (
	"bytes"
	"math"
	"unicode/utf8"
)

type Metric string

const (
	MetricFileSize       Metric = "file_size"
	MetricMaxLineLength  Metric = "max_line_length"
	MetricMaxLineEntropy Metric = "max_line_entropy"
	MetricBidiControls   Metric = "bidi_controls"
	MetricInvisibleRunes Metric = "invisible_runes"
)

const entropyMinLineLength = 256

func (m Metric) Valid() bool {
	switch m {
	case MetricFileSize, MetricMaxLineLength, MetricMaxLineEntropy, MetricBidiControls, MetricInvisibleRunes:
		return true
	}
	return false
}

func (m Metric) Measure(data []byte) float64 {
	switch m {
	case MetricFileSize:
		return float64(len(data))
	case MetricMaxLineLength:
		return float64(maxLineLength(data))
	case MetricMaxLineEntropy:
		return maxLineEntropy(data)
	case MetricBidiControls:
		return float64(countRunes(data, isBidiControl))
	case MetricInvisibleRunes:
		return float64(countRunes(data, isInvisible))
	}
	return 0
}

func maxLineLength(data []byte) int {
	longest := 0
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n')
		if n < 0 {
			n = len(data)
		}
		if n > longest {
			longest = n
		}
		if n == len(data) {
			break
		}
		data = data[n+1:]
	}
	return longest
}

func maxLineEntropy(data []byte) float64 {
	best := 0.0
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n')
		if n < 0 {
			n = len(data)
		}
		if n >= entropyMinLineLength {
			if e := shannon(bytes.TrimSpace(data[:n])); e > best {
				best = e
			}
		}
		if n == len(data) {
			break
		}
		data = data[n+1:]
	}
	return math.Round(best*100) / 100
}

func shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	total := float64(len(data))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		e -= p * math.Log2(p)
	}
	return e
}

func countRunes(data []byte, match func(rune, int) bool) int {
	n := 0
	for i := 0; i < len(data); {
		if data[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRune(data[i:])
		if match(r, i) {
			n++
		}
		i += size
	}
	return n
}

func isBidiControl(r rune, _ int) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isInvisible(r rune, offset int) bool {
	switch {
	case r == 0xFEFF:
		return offset != 0
	case r == 0x200B, r == 0x3164, r == 0xFFA0, r == 0x115F, r == 0x1160:
		return true
	case r >= 0x2060 && r <= 0x2064:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	case r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}
