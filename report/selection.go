// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"slices"

	"github.com/RhythmShahriar/tuner/engine"
)

// Selection is what a narrowed scan left out. A comparison uses it to
// tell a finding that was fixed from one whose check did not run, such
// as a header finding next to a scan with --id 'leak-*'. A scan that ran
// every check has none, as do reports saved before it existed. Then
// every finding counts as looked for.
type Selection struct {
	// Skipped lists the HTTP checks the scan had but did not run, sorted.
	Skipped     []string        `json:"skipped_checks,omitempty"`
	IDs         []string        `json:"ids,omitempty"`
	ExcludeIDs  []string        `json:"exclude_ids,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	ExcludeTags []string        `json:"exclude_tags,omitempty"`
	MinSeverity engine.Severity `json:"min_severity,omitempty"`
}

// NewSelection records what a scan leaves out. It runs the checks in ran
// out of those in all; selection s narrows its other findings. It is nil
// when the scan leaves out nothing.
func NewSelection(all, ran []*engine.Check, s engine.Selector) *Selection {
	running := map[string]bool{}
	for _, c := range ran {
		running[c.ID] = true
	}
	var skipped []string
	for _, c := range all {
		if !running[c.ID] {
			skipped = append(skipped, c.ID)
		}
	}
	slices.Sort(skipped)
	sel := &Selection{
		Skipped: slices.Compact(skipped), IDs: s.IDs, ExcludeIDs: s.ExcludeIDs,
		Tags: s.Tags, ExcludeTags: s.ExcludeTags, MinSeverity: s.MinSeverity,
	}
	if sel.MinSeverity == engine.Info {
		sel.MinSeverity = ""
	}
	if len(sel.Skipped)+len(sel.IDs)+len(sel.ExcludeIDs)+len(sel.Tags)+len(sel.ExcludeTags) == 0 && sel.MinSeverity == "" {
		return nil
	}
	return sel
}

// LookedFor reports whether a scan with this selection could have found
// f: an HTTP check's finding unless that check was skipped, a finding
// from Go code (vulnerability matching or a local scan) when the
// selection keeps it. A nil Selection looked for everything.
func (s *Selection) LookedFor(f engine.Finding) bool {
	if s == nil {
		return true
	}
	if slices.Contains(s.Skipped, f.ID) {
		return false
	}
	if !engine.IsAdvisorID(f.ID) {
		return true
	}
	return engine.Selector{IDs: s.IDs, ExcludeIDs: s.ExcludeIDs, Tags: s.Tags, ExcludeTags: s.ExcludeTags, MinSeverity: s.MinSeverity}.Keeps(f)
}

// Why a later scan lacks an earlier finding without it being fixed.
const (
	UnseenIncomplete = "incomplete"  // the scan stopped early, was blocked or lacked vulnerability data
	UnseenNotChecked = "not_checked" // the finding's check was not part of the scan
)

// Unseen says why r, a later scan of the same site, may lack f, an
// earlier finding: UnseenIncomplete, UnseenNotChecked, or "" when its
// absence means f was fixed.
func (r Report) Unseen(f engine.Finding) string {
	st := r.Status()
	switch {
	case st.Partial():
		return UnseenIncomplete
	case len(f.Advisories) > 0 && (st.VulnData == "missing" || st.VulnData == "partial" || st.VulnData == "off"):
		return UnseenIncomplete
	case !r.Selection.LookedFor(f):
		return UnseenNotChecked
	}
	return ""
}
