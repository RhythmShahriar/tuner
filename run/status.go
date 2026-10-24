// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/report"
)

// Status says how much of a target one run saw. Run works it out from the
// run context, the scan's own result (a firewall, a home page error or a
// request budget) and the vulnerability advisor, then records it on each
// report with report.SetStatus.
type Status struct {
	Complete  bool   `json:"complete"`
	StoppedBy string `json:"stopped_by,omitempty"` // interrupted, max-time, waf, home-status, budget or integrity
	BlockedBy string `json:"blocked_by,omitempty"` // the firewall that challenged the scan
	VulnData  string `json:"vuln_data,omitempty"`  // one of the Vuln* values below
}

// How much vulnerability data a scan got, as vulns.Advisor.AdviseStatus
// names it.
const (
	VulnOK      = "ok"      // every lookup worked
	VulnPartial = "partial" // some lookups failed or used stale data
	VulnMissing = "missing" // no usable data
	VulnOff     = "off"     // matching was not part of the scan
)

// Reason says in a few plain words why a scan is incomplete, in the
// words the report notes use, such as "stopped at the request budget".
func (s Status) Reason() string {
	return report.Status{Complete: s.Complete, StoppedBy: s.StoppedBy, BlockedBy: s.BlockedBy, VulnData: s.VulnData}.Reason()
}

// status works out a finished target's Status. err is what the scan
// returned: a target that finished before Ctrl-C is still complete. ctx
// is the run's context, which tells a MaxTime stop apart from one slow
// request: both wrap DeadlineExceeded. res, when not nil, adds what the
// scan itself saw: a firewall (BlockedBy) or an early stop of its own.
func (p *Plan) status(ctx context.Context, err error, slot *vulnSlot, res *engine.Result) Status {
	s := Status{Complete: true, VulnData: VulnOff}
	switch {
	case isCanceled(err):
		s.Complete, s.StoppedBy = false, "interrupted"
	case errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.Complete, s.StoppedBy = false, "max-time"
	}
	if res != nil {
		s.BlockedBy = res.BlockedBy
		if res.StoppedBy != "" && s.StoppedBy == "" {
			s.Complete, s.StoppedBy = false, res.StoppedBy
		}
	}
	if p.Engine.Advisor != nil {
		s.VulnData = slot.get()
	}
	// A local scan also matches Composer packages on its own and says how
	// that went; the worse of the two wins.
	if res != nil && res.VulnData != "" && (vulnRank[res.VulnData] > vulnRank[s.VulnData] || s.VulnData == VulnOff) {
		s.VulnData = res.VulnData
	}
	return s
}

// vulnRank orders vulnerability data statuses from best to worst.
var vulnRank = map[string]int{VulnOK: 1, VulnPartial: 2, VulnMissing: 3}

func isCanceled(err error) bool { return errors.Is(err, context.Canceled) }

// TrackVulns wraps a vulnerability advisor so Run can tell how much data
// each target's lookups got. Put it inside engine.Filtered, so it sees
// every lookup, including ones whose findings the selection drops.
func TrackVulns(a engine.Advisor) engine.Advisor { return vulnTracker{a} }

// vulnTracker records each lookup's data status in the vulnSlot its scan
// context carries.
type vulnTracker struct{ engine.Advisor }

// PluginSlugs passes engine.PluginLister through the tracker, so deep
// plugin discovery still sees the advisor's slugs.
func (v vulnTracker) PluginSlugs(ctx context.Context) []string {
	if l, ok := v.Advisor.(engine.PluginLister); ok {
		return l.PluginSlugs(ctx)
	}
	return nil
}

// statusAdvisor is the optional advisor method that reports the data
// status itself, rather than leaving it to be read from warnings.
type statusAdvisor interface {
	AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string, string)
}

func (v vulnTracker) Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string) {
	findings, warnings, _ := v.AdviseStatus(ctx, base, fp)
	return findings, warnings
}

// AdviseStatus implements engine.StatusAdvisor, so a local scan, which
// asks its advisor for the status itself, gets the same one Run records.
func (v vulnTracker) AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string, string) {
	var findings []engine.Finding
	var warnings []string
	var status string
	if sa, ok := v.Advisor.(statusAdvisor); ok {
		findings, warnings, status = sa.AdviseStatus(ctx, base, fp)
	} else {
		findings, warnings = v.Advisor.Advise(ctx, base, fp)
		status = vulnStatusFromWarnings(advisorLookups(fp), warnings)
	}
	if slot, ok := ctx.Value(vulnSlotKey{}).(*vulnSlot); ok {
		slot.set(status)
	}
	return findings, warnings, status
}

// vulnStatusFromWarnings reads the status from vulns.Advisor's warnings,
// for advisors without AdviseStatus. The warning counts the failed
// lookups; lookups is how many the advisor made for fp.
func vulnStatusFromWarnings(lookups int, warnings []string) string {
	failed, stale := 0, false
	for _, w := range warnings {
		for _, prefix := range []string{"couldn't fetch vulnerability data for ", "vulnerability data not cached for "} {
			if rest, ok := strings.CutPrefix(w, prefix); ok {
				var n int
				if _, err := fmt.Sscanf(rest, "%d", &n); err != nil {
					n = lookups // unreadable: assume the worst
				}
				failed += n
			}
		}
		stale = stale || strings.HasPrefix(w, "used cached vulnerability data older")
	}
	switch {
	case failed > 0 && failed >= lookups:
		return VulnMissing
	case failed > 0 || stale:
		return VulnPartial
	}
	return VulnOK
}

// serverVersion matches a Server header vulns.Advisor looks up.
var serverVersion = regexp.MustCompile(`(?i)^(nginx|apache)/[0-9]+(\.[0-9]+)+`)

// advisorLookups counts the lookups vulns.Advisor makes for fp: one per
// component, plus one for recent PHP flaws when PHP runs but hides its
// version. It goes with vulnStatusFromWarnings once AdviseStatus lands.
func advisorLookups(fp fingerprint.Result) int {
	n := len(fp.Components)
	if fp.Has("wordpress") && fp.WordPress != "" {
		n++
	}
	if fp.PHP != "" || fp.Has("php") {
		n++
	}
	if serverVersion.MatchString(fp.Server) {
		n++
	}
	return n
}

// vulnSlotKey is the context key for a target's vulnSlot.
type vulnSlotKey struct{}

// vulnSlot holds one target's vulnerability data status. A scan that never
// reached the advisor got no data.
type vulnSlot struct {
	mu     sync.Mutex
	status string
}

// set records a lookup's status; with several lookups the worst one wins.
func (s *vulnSlot) set(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vulnRank[status] > vulnRank[s.status] {
		s.status = status
	}
}

func (s *vulnSlot) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == "" {
		return VulnMissing
	}
	return s.status
}
