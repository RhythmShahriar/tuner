// Package checks embeds the built-in YAML checks and their fixtures.
// See docs/checks.md for the format.
package checks

import "embed"

//go:embed */*.yaml
var FS embed.FS
