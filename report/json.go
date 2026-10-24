// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

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
	Baselined  int                     `json:"baselined"`            // findings a baseline file hid
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

// JSON writes one target's report as an object, or several targets' as an array.
//
// many says whether several targets were scanned. The shape follows the
// request, not how many scans succeeded, so a script reading a batch
// always gets an array even when only one site could be reached.
func JSON(w io.Writer, reports []Report, many bool) error {
	return Write("json", w, reports, WriteOptions{Many: many})
}

// writeJSON is the json writer. Failed targets join the array as
// {"target", "error"} entries after the reports.
func writeJSON(w io.Writer, reports []Report, o WriteOptions) error {
	enc := encoder(w)
	enc.SetIndent("", "  ")
	if len(reports) == 1 && !o.Many && !o.Array && len(o.Failed) == 0 {
		return enc.Encode(reports[0])
	}
	all := make([]any, 0, len(reports)+len(o.Failed))
	for _, r := range reports {
		all = append(all, r)
	}
	for _, f := range o.Failed {
		all = append(all, f)
	}
	return enc.Encode(all)
}

// JSONLine writes one finding as a single line, for streaming into jq or
// a log pipeline while the scan runs.
func JSONLine(w io.Writer, f engine.Finding) error { return encoder(w).Encode(f) }
