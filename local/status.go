// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"net/url"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// status says how complete a local scan was, in the terms remote scans
// use: whether it ran to the end and whether vulnerability data was
// there to match versions against.
type status struct {
	complete  bool
	stoppedBy string // "budget" when a walk stopped at MaxEntries
	// vulnData is "ok" when every lookup succeeded, "partial" when some
	// failed, "missing" when none did and "off" when matching was off.
	vulnData string
}

// The vulnData values.
const (
	vulnOK      = "ok"
	vulnPartial = "partial"
	vulnMissing = "missing"
	vulnOff     = "off"
)

// statusAdvisor is an Advisor that also reports its vulnData status, as
// engine.StatusAdvisor will. It is declared here so local uses the
// status as soon as the vulnerability advisor provides it.
type statusAdvisor interface {
	AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string, string)
}

// advise runs the advisor and adds its findings and warnings. It returns
// its vulnData status ("" when there is no advisor). An advisor that
// can't report one is judged by its warnings: any warning means some
// data was missing.
func (s *scan) advise(ctx context.Context, fp fingerprint.Result, findings *[]engine.Finding) string {
	a := s.opts.Advisor
	switch {
	case a == nil:
		return ""
	case ctx.Err() != nil:
		return vulnMissing
	}
	if sa, ok := a.(statusAdvisor); ok {
		more, warnings, st := sa.AdviseStatus(ctx, s.base, fp)
		*findings = append(*findings, more...)
		s.warnings = append(s.warnings, warnings...)
		return st
	}
	more, warnings := a.Advise(ctx, s.base, fp)
	*findings = append(*findings, more...)
	s.warnings = append(s.warnings, warnings...)
	if len(warnings) > 0 {
		return vulnPartial
	}
	return vulnOK
}

// vulnStep runs a vulnerability lookup that reports trouble only through
// warnings (the Composer OSV match) and returns its vulnData status, or
// "" when it had nothing to look up.
func (s *scan) vulnStep(run func()) string {
	if s.opts.OSV == nil || len(s.pkgs) == 0 {
		return ""
	}
	before := len(s.warnings)
	run()
	if len(s.warnings) > before {
		return vulnPartial
	}
	return vulnOK
}

// combineVulnData merges the statuses of the lookups that ran ("" for one
// that didn't): "off" when none ran, the shared value when they agree,
// otherwise "partial".
func combineVulnData(statuses ...string) string {
	out := ""
	for _, st := range statuses {
		switch {
		case st == "" || st == vulnOff:
		case out == "":
			out = st
		case out != st:
			out = vulnPartial
		}
	}
	if out == "" {
		return vulnOff
	}
	return out
}
