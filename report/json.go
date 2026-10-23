// Package report renders scan results for people and machines.
package report

import (
	"encoding/json"
	"io"

	"github.com/RhythmShahriar/tuner/engine"
)

// Schema identifies the JSON report layout. It is unstable until v1.0.
const Schema = "rhythm-tuner/v0"

// Report is one target's results in the documented JSON schema.
type Report struct {
	Schema     string                  `json:"schema"`
	Tool       string                  `json:"tool"`
	Version    string                  `json:"version"`
	DurationMS int64                   `json:"duration_ms"`
	Summary    map[engine.Severity]int `json:"summary"`
	CheckSet   string                  `json:"check_set,omitempty"`  // built-in, pack or directory
	CheckPack  string                  `json:"check_pack,omitempty"` // the pack's version, when check_set is pack
	*engine.Result
}

// New wraps a scan result for output.
func New(res *engine.Result, version string) Report {
	if res.Findings == nil {
		res.Findings = []engine.Finding{}
	}
	return Report{
		Schema:     Schema,
		Tool:       "rhythm-tuner",
		Version:    version,
		DurationMS: res.Duration.Milliseconds(),
		Summary:    res.Counts(),
		Result:     res,
	}
}

func encoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc
}

// JSON writes one report as an object, or several as an array.
func JSON(w io.Writer, reports []Report) error {
	enc := encoder(w)
	enc.SetIndent("", "  ")
	if len(reports) == 1 {
		return enc.Encode(reports[0])
	}
	if reports == nil {
		reports = []Report{}
	}
	return enc.Encode(reports)
}

// JSONLine writes one finding as a single line, for streaming into jq or
// a log pipeline while the scan runs.
func JSONLine(w io.Writer, f engine.Finding) error { return encoder(w).Encode(f) }
