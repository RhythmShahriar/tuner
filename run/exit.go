// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"fmt"
	"slices"

	"github.com/RhythmShahriar/tuner/engine"
)

// Exit codes, the same as rhythm tuner scan's.
const (
	ExitOK       = 0
	ExitFindings = 1 // a finding at or above Plan.FailOn
	ExitError    = 3 // a target couldn't be scanned, or FailOn can't trust the result
	ExitCanceled = 130
)

// Exit picks the exit code for a finished run and says why, one message
// per reason, when it is not ExitOK or ExitFindings. A canceled run is
// ExitCanceled. With FailOn, a finding at or above it is ExitFindings.
// A run with none is still ExitError when a target's vulnerability
// data was missing or its scan was cut short, unless the plan allows
// that. Otherwise a target that failed makes it ExitError.
func (o *Outcome) Exit(p *Plan) (code int, why []string) {
	if o.Canceled {
		return ExitCanceled, []string{"scan canceled; results are partial"}
	}
	if p.FailOn != "" {
		for _, r := range o.Reports {
			if w := GateWorst(r.Findings, p.ConfirmedOnly); w != "" && w.Rank() <= p.FailOn.Rank() {
				return ExitFindings, nil
			}
		}
		// No findings only means a clean site when the scan saw it all.
		if why := o.untrusted(p); len(why) > 0 {
			return ExitError, why
		}
	}
	if slices.ContainsFunc(o.Targets, func(t Target) bool { return t.Failed() }) {
		return ExitError, nil
	}
	return ExitOK, nil
}

// untrusted lists why FailOn can't call the reports clean: the
// vulnerability data was missing, or the scan was blocked or cut short.
// AllowMissingVulns and AllowPartial accept each case.
func (o *Outcome) untrusted(p *Plan) []string {
	var why []string
	for i, r := range o.Reports {
		why = append(why, Untrusted(r.Target, o.Status[i], "--fail-on "+string(p.FailOn), p.AllowMissingVulns, p.AllowPartial)...)
	}
	return why
}

// Untrusted lists why a gate such as "--fail-on high" can't call one
// target's report clean: its vulnerability data was missing (unless
// allowMissingVulns), or its scan was blocked or cut short (unless
// allowPartial). Each reason is a message with its hint on a second line.
func Untrusted(target string, s Status, gate string, allowMissingVulns, allowPartial bool) []string {
	var why []string
	if s.VulnData == VulnMissing && !allowMissingVulns {
		why = append(why, fmt.Sprintf("%s: no vulnerability data, so %s can't pass it\n"+
			"  rerun when the data source is back, or add --allow-missing-vulns", target, gate))
	}
	if (!s.Complete || s.BlockedBy != "") && !allowPartial {
		why = append(why, fmt.Sprintf("%s: the scan is incomplete (%s), so %s can't pass it\n"+
			"  add --allow-partial to accept a partial scan", target, s.Reason(), gate))
	}
	return why
}

// Confirmed reports whether a finding counts as confirmed. A finding is
// likely when its check or the advisor marked it low confidence, such as
// a CVE matched on a distro PHP build that may carry the fix already.
func Confirmed(f engine.Finding) bool { return f.Confidence.Confirmed() }

// GateWorst is the worst severity a fail-on gate looks at: among every
// finding, or only the confirmed ones.
func GateWorst(findings []engine.Finding, confirmedOnly bool) engine.Severity {
	var w engine.Severity
	for _, f := range findings {
		if confirmedOnly && !Confirmed(f) {
			continue
		}
		if w == "" || f.Severity.Rank() < w.Rank() {
			w = f.Severity
		}
	}
	return w
}
