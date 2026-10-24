// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package report renders scan results for people and machines.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

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

	// How complete the scan is (see Status). These sit on Report rather
	// than in an embedded struct so they win over the same names on
	// engine.Result once it has them (contract D1).
	Complete  bool   `json:"complete"`
	StoppedBy string `json:"stopped_by,omitempty"`
	BlockedBy string `json:"blocked_by,omitempty"`
	VulnData  string `json:"vuln_data,omitempty"`

	*engine.Result

	root string // the local scan root, for fingerprints; see WriteOptions.Root
}

// stampedFinding is a finding as the JSON report writes it, with its
// fingerprint. Once engine.Finding has its own Fingerprint field (contract
// D1) this field shadows it with the same value.
type stampedFinding struct {
	engine.Finding
	Fingerprint string `json:"fingerprint"`
}

// MarshalJSON writes the report with a fingerprint on every finding, so a
// saved report works as a baseline and diffs line up across runs.
func (r Report) MarshalJSON() ([]byte, error) {
	type plain Report // no methods, so encoding it doesn't come back here
	if r.Result == nil {
		return marshal(plain(r))
	}
	// Findings and Warnings are listed again so they shadow the embedded
	// ones and keep their place at the end of the object.
	out := struct {
		plain
		Findings []stampedFinding `json:"findings"`
		Warnings []string         `json:"warnings,omitempty"`
	}{plain: plain(r), Findings: make([]stampedFinding, 0, len(r.Findings)), Warnings: r.Warnings}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, stampedFinding{f, Fingerprint(f, r.root)})
	}
	return marshal(out)
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	err := encoder(&b).Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), err
}

// New wraps a scan result for output. The report holds a copy of res with
// every string passed through SafeText, so no writer can print a control
// byte a site or a scanned file put there; res itself is left as it is.
func New(res *engine.Result, version string) Report {
	if res.Findings == nil {
		res.Findings = []engine.Finding{}
	}
	clean := sanitized(*res)
	return Report{
		Schema:     Schema,
		Tool:       "rhythm-tuner",
		Version:    SafeText(version),
		DurationMS: res.Duration.Milliseconds(),
		Summary:    summary(&clean),
		Complete:   true, // until engine.Result says otherwise (contract D1)
		Result:     &clean,
	}
}

// summary counts findings per severity with every severity present, so
// a script reads .summary.critical as 0 rather than null on a clean run.
func summary(res *engine.Result) map[engine.Severity]int {
	c := res.Counts()
	for _, s := range engine.Severities {
		if _, ok := c[s]; !ok {
			c[s] = 0
		}
	}
	return c
}

// Status says whether a scan saw everything it set out to. A report that
// looks finished but isn't (a Ctrl+C, --max-time, a firewall challenge,
// a vulnerability API that never answered) would pass a CI gate it
// should fail, so every format says so plainly.
type Status struct {
	Complete  bool
	StoppedBy string // interrupted, max-time, waf, home-status or budget
	BlockedBy string // the firewall that challenged the scan: cloudflare, sucuri, ...
	VulnData  string // ok, partial, missing or off (--no-vulns)
}

// Status returns the report's completeness.
func (r Report) Status() Status {
	return Status{Complete: r.Complete, StoppedBy: r.StoppedBy, BlockedBy: r.BlockedBy, VulnData: r.VulnData}
}

// SetStatus records the scan's completeness on the report.
func (r *Report) SetStatus(s Status) {
	r.Complete, r.StoppedBy, r.BlockedBy, r.VulnData = s.Complete, SafeText(s.StoppedBy), SafeText(s.BlockedBy), SafeText(s.VulnData)
}

// Partial reports whether the scan stopped early or was blocked.
func (s Status) Partial() bool { return !s.Complete || s.StoppedBy != "" || s.BlockedBy != "" }

// Notes returns the warnings a reader must see before the score, e.g.
// "Incomplete: stopped by --max-time". It is empty for a whole scan.
func (s Status) Notes() []string {
	var notes []string
	if s.Partial() {
		notes = append(notes, "Incomplete: "+s.reason())
	}
	switch s.VulnData {
	case "missing":
		notes = append(notes, "Score excludes known vulnerabilities (vulnerability data missing)")
	case "partial":
		notes = append(notes, "Score may miss known vulnerabilities (vulnerability data partial)")
	}
	return notes
}

func (s Status) reason() string {
	blocked := "blocked by a firewall challenge"
	if s.BlockedBy != "" {
		blocked = "blocked by " + firewallName(s.BlockedBy) + " challenge"
	}
	switch s.StoppedBy {
	case "interrupted":
		return "interrupted"
	case "max-time":
		return "stopped by --max-time"
	case "waf":
		return blocked
	case "home-status":
		return "the home page did not load"
	case "budget":
		return "stopped at the request budget"
	case "":
		if s.BlockedBy != "" {
			return blocked
		}
		return "the scan did not finish"
	}
	return "stopped by " + SafeText(s.StoppedBy)
}

var firewallNames = map[string]string{
	"cloudflare": "Cloudflare", "sucuri": "Sucuri", "imperva": "Imperva", "wordfence": "Wordfence",
	"akamai": "Akamai", "aws": "AWS WAF", "modsecurity": "ModSecurity",
}

func firewallName(id string) string {
	if n, ok := firewallNames[strings.ToLower(id)]; ok {
		return n
	}
	return SafeText(id)
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
		r := reports[0]
		if o.Root != "" {
			r.root = o.Root
		}
		return enc.Encode(r)
	}
	all := make([]any, 0, len(reports)+len(o.Failed))
	for _, r := range reports {
		if o.Root != "" {
			r.root = o.Root
		}
		all = append(all, r)
	}
	for _, f := range o.Failed {
		all = append(all, f)
	}
	return enc.Encode(all)
}

// JSONLine writes one finding as a single line, for streaming into jq or
// a log pipeline while the scan runs.
// The finding is cleaned with SafeText like every report.
func JSONLine(w io.Writer, f engine.Finding) error {
	f = sanitized(f)
	return encoder(w).Encode(stampedFinding{f, Fingerprint(f, "")})
}

// ReadJSON reads what the json writer wrote: one report, or an array of
// reports and failed targets. It is how a saved report comes back for a
// diff or a later rendering.
func ReadJSON(r io.Reader) ([]Report, []TargetError, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		items = []json.RawMessage{data}
	}
	var (
		reports []Report
		failed  []TargetError
	)
	for _, item := range items {
		var probe struct {
			Schema   string  `json:"schema"`
			Error    *string `json:"error"`
			Complete *bool   `json:"complete"`
		}
		if err := json.Unmarshal(item, &probe); err != nil {
			return nil, nil, fmt.Errorf("not a Tuner JSON report: %w", err)
		}
		if probe.Schema == "" && probe.Error != nil {
			var t TargetError
			if err := json.Unmarshal(item, &t); err != nil {
				return nil, nil, fmt.Errorf("not a Tuner JSON report: %w", err)
			}
			failed = append(failed, sanitized(t))
			continue
		}
		if !strings.HasPrefix(probe.Schema, "rhythm-tuner/") {
			return nil, nil, errors.New("not a Tuner JSON report: no rhythm-tuner schema")
		}
		var rep Report
		if err := json.Unmarshal(item, &rep); err != nil {
			return nil, nil, fmt.Errorf("not a Tuner JSON report: %w", err)
		}
		if rep.Result == nil {
			rep.Result = &engine.Result{}
		}
		// Reports saved before the complete field were never marked
		// partial, so reading one as incomplete would put a false
		// warning in front of a client.
		if probe.Complete == nil {
			rep.Complete = true
		}
		rep.Duration = time.Duration(rep.DurationMS) * time.Millisecond
		// A report from disk is untrusted like a site: clean it as New does.
		clean := sanitized(*rep.Result)
		rep.Result = &clean
		rep.Version, rep.CheckSet, rep.CheckPack = SafeText(rep.Version), SafeText(rep.CheckSet), SafeText(rep.CheckPack)
		rep.SetStatus(rep.Status())
		reports = append(reports, rep)
	}
	if len(reports) == 0 && len(failed) == 0 {
		// null, [] or {}: comparing with nothing would list every finding as new.
		return nil, nil, errors.New("not a Tuner JSON report: no report in it")
	}
	return reports, failed, nil
}
