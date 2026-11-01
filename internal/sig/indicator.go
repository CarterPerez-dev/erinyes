// ©AngelaMos | 2026
// indicator.go

package sig

import (
	"bytes"
	"fmt"
	"regexp"
)

type IndicatorType string

const (
	TypeRegex   IndicatorType = "regex"
	TypeLiteral IndicatorType = "literal"
	TypeMetric  IndicatorType = "metric"
	TypeAST     IndicatorType = "ast"
)

const maxMatchCount = 4096

type Indicator struct {
	Name    string        `yaml:"name"`
	Weight  int           `yaml:"weight"`
	Type    IndicatorType `yaml:"type"`
	Pattern string        `yaml:"pattern,omitempty"`
	Metric  Metric        `yaml:"metric,omitempty"`
	Min     float64       `yaml:"min,omitempty"`

	re       *regexp.Regexp
	lit      []byte
	compiled bool
}

func (i *Indicator) compile() error {
	switch i.Type {
	case "", TypeRegex:
		i.Type = TypeRegex
		if err := i.rejectMetricFields(); err != nil {
			return err
		}
		re, err := regexp.Compile(i.Pattern)
		if err != nil {
			return fmt.Errorf("indicator %q: pattern does not compile as RE2: %w", i.Name, err)
		}
		i.re = re
	case TypeLiteral:
		if err := i.rejectMetricFields(); err != nil {
			return err
		}
		if i.Pattern == "" {
			return fmt.Errorf("indicator %q: literal pattern is empty", i.Name)
		}
		i.lit = []byte(i.Pattern)
	case TypeMetric:
		if i.Pattern != "" {
			return fmt.Errorf("indicator %q: metric indicators take metric and min, not pattern", i.Name)
		}
		if !i.Metric.Valid() {
			return fmt.Errorf("indicator %q: unknown metric %q (want file_size, max_line_length, max_line_entropy, bidi_controls or invisible_runes)", i.Name, i.Metric)
		}
		if i.Min <= 0 {
			return fmt.Errorf("indicator %q: metric min must be greater than 0", i.Name)
		}
	case TypeAST:
		return fmt.Errorf("indicator %q: type %q is reserved and not implemented in schema version 1", i.Name, TypeAST)
	default:
		return fmt.Errorf("indicator %q: unknown type %q (want regex, literal, metric or ast)", i.Name, i.Type)
	}
	i.compiled = true
	return nil
}

func (i *Indicator) rejectMetricFields() error {
	if i.Metric != "" || i.Min != 0 {
		return fmt.Errorf("indicator %q: metric and min are only valid with type metric", i.Name)
	}
	return nil
}

func (i *Indicator) Eval(data []byte) (int, float64) {
	switch i.Type {
	case TypeLiteral:
		return bytes.Count(data, i.lit), 0
	case TypeRegex:
		if i.re == nil {
			return 0, 0
		}
		return len(i.re.FindAllIndex(data, maxMatchCount)), 0
	case TypeMetric:
		v := i.Metric.Measure(data)
		if v >= i.Min {
			return 1, v
		}
		return 0, v
	default:
		return 0, 0
	}
}

func (i *Indicator) Count(data []byte) int {
	n, _ := i.Eval(data)
	return n
}

func (i *Indicator) Compiled() bool {
	return i.compiled
}
