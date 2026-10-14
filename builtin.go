// ©AngelaMos | 2026
// builtin.go

package erinyes

import "embed"

//go:embed signatures/*.yaml
var Signatures embed.FS

const CatalogVersion = "1"
