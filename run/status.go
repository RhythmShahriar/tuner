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
)

// Status says how much of a target one run saw. It mirrors report.Status
// from the report writer work: until engine.Result and report.Report carry
// these fields, Run fills them in from the run context and the
// vulnerability advisor. The CLI adds them to JSON.
type Status struct {
	Complete  bool   `json:"complete"`
	StoppedBy string `json:"stopped_by,omitempty"` // interrupted or max-time
	BlockedBy string `json:"blocked_by,omitempty"` // a firewall, once the engine detects them
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

// Reason says in a few words why a scan is incomplete.
func (s Status) Reason() string {
	switch {
	case s.BlockedBy != "":
		return "blocked by " + s.BlockedBy
	case s.StoppedBy == "max-time":
		return "stopped by --max-time"
	case s.StoppedBy != "":
		return s.StoppedBy
	}
	return "the scan did not finish"
}

// status works out a finished target's Status. err is what the scan
// returned: a target that finished before Ctrl-C is still complete. ctx
// is the run's context, which tells a MaxTime stop apart from one slow
// request: both wrap DeadlineExceeded.
func (p *Plan) status(ctx context.Context, err error, slot *vulnSlot) Status {
	s := Status{Complete: true, VulnData: VulnOff}
	switch {
	case isCanceled(err):
		s.Complete, s.StoppedBy = false, "interrupted"
	case errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.Complete, s.StoppedBy = false, "max-time"
	}
	if p.Engine.Advisor != nil {
		s.VulnData = slot.get()
	}
	return s
}

func isCanceled(err error) bool { return errors.Is(err, context.Canceled) }

// TrackVulns wraps a vulnerability advisor so Run can tell how much data
// each target's lookups got. Put it inside engine.Filtered, so it sees
// every lookup, including ones whose findings the selection drops.
func TrackVulns(a engine.Advisor) engine.Advisor { return vulnTracker{a} }

// vulnTracker records each lookup's data status in the vulnSlot its scan
// context carries.
type vulnTracker struct{ engine.Advisor }

// statusAdvisor is the optional advisor method that reports the data
// status itself, rather than leaving it to be read from warnings.
type statusAdvisor interface {
	AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string, string)
}

func (v vulnTracker) Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string) {
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
	return findings, warnings
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
	rank := map[string]int{VulnOK: 1, VulnPartial: 2, VulnMissing: 3}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rank[status] > rank[s.status] {
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
