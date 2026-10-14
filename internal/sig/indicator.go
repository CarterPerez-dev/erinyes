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
	TypeAST     IndicatorType = "ast"
)

const maxMatchCount = 4096

type Indicator struct {
	Name    string        `yaml:"name"`
	Weight  int           `yaml:"weight"`
	Type    IndicatorType `yaml:"type"`
	Pattern string        `yaml:"pattern"`

	re  *regexp.Regexp
	lit []byte
}

func (i *Indicator) compile() error {
	switch i.Type {
	case "", TypeRegex:
		i.Type = TypeRegex
		re, err := regexp.Compile(i.Pattern)
		if err != nil {
			return fmt.Errorf("indicator %q: pattern does not compile as RE2: %w", i.Name, err)
		}
		i.re = re
	case TypeLiteral:
		if i.Pattern == "" {
			return fmt.Errorf("indicator %q: literal pattern is empty", i.Name)
		}
		i.lit = []byte(i.Pattern)
	case TypeAST:
		return fmt.Errorf("indicator %q: type %q is reserved and not implemented in schema version 1", i.Name, TypeAST)
	default:
		return fmt.Errorf("indicator %q: unknown type %q (want regex, literal or ast)", i.Name, i.Type)
	}
	return nil
}

func (i *Indicator) Count(data []byte) int {
	switch i.Type {
	case TypeLiteral:
		return bytes.Count(data, i.lit)
	case TypeRegex:
		if i.re == nil {
			return 0
		}
		return len(i.re.FindAllIndex(data, maxMatchCount))
	default:
		return 0
	}
}

func (i *Indicator) Compiled() bool {
	return i.re != nil || i.lit != nil
}
