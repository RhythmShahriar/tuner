package engine

import (
	"errors"
	"fmt"
	"path"
	"slices"
)

// Profile trades coverage for request count.
type Profile string

const (
	ProfileQuick   Profile = "quick"   // the highest-value checks, about 30 requests
	ProfileDefault Profile = "default" // everything polite and non-intrusive
	ProfileDeep    Profile = "deep"    // adds aggressive enumeration
)

var Profiles = []Profile{ProfileQuick, ProfileDefault, ProfileDeep}

// Rank orders profiles from cheapest; -1 if unknown.
func (p Profile) Rank() int { return slices.Index(Profiles, p) }

// Selector narrows the checks a scan runs. Zero values select everything
// in the default profile.
type Selector struct {
	Profile     Profile
	Tags        []string // run checks with any of these tags
	ExcludeTags []string
	IDs         []string // run only these checks; globs like leak-* allowed
	ExcludeIDs  []string
	MinSeverity Severity // skip checks below this severity
}

// Select applies s to all.
func Select(all []*Check, s Selector) ([]*Check, error) {
	if s.Profile == "" {
		s.Profile = ProfileDefault
	}
	if s.Profile.Rank() < 0 {
		return nil, fmt.Errorf("unknown profile %q: want one of %v", s.Profile, Profiles)
	}
	if s.MinSeverity == "" {
		s.MinSeverity = Info
	}
	if s.MinSeverity.Rank() < 0 {
		return nil, fmt.Errorf("unknown severity %q: want one of %v", s.MinSeverity, Severities)
	}
	for _, id := range append(slices.Clone(s.IDs), s.ExcludeIDs...) {
		if _, err := path.Match(id, ""); err != nil {
			return nil, fmt.Errorf("bad check pattern %q: %w", id, err)
		}
		if !slices.ContainsFunc(all, func(c *Check) bool { return globMatch(id, c.ID) }) {
			return nil, fmt.Errorf("no check matches %q; list them with: rhythm tuner checks", id)
		}
	}

	var out []*Check
	for _, c := range all {
		switch {
		case len(s.IDs) == 0 && c.Profile.Rank() > s.Profile.Rank():
		case c.Severity.Rank() > s.MinSeverity.Rank():
		case len(s.IDs) > 0 && !slices.ContainsFunc(s.IDs, func(id string) bool { return globMatch(id, c.ID) }):
		case slices.ContainsFunc(s.ExcludeIDs, func(id string) bool { return globMatch(id, c.ID) }):
		case len(s.Tags) > 0 && !hasAny(c.Tags, s.Tags):
		case hasAny(c.Tags, s.ExcludeTags):
		default:
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no checks match the selection; list them with: rhythm tuner checks")
	}
	return out, nil
}

func globMatch(pattern, id string) bool {
	ok, _ := path.Match(pattern, id)
	return ok
}

func hasAny(have, want []string) bool {
	return slices.ContainsFunc(want, func(t string) bool { return slices.Contains(have, t) })
}

// Penalty per distinct failing check, by severity. The Tune score is
// 100 minus the penalties, floored at 0. A check that fires on several
// paths counts once, at its worst severity.
var penalty = map[Severity]int{Critical: 30, High: 15, Medium: 6, Low: 2, Info: 0}

// Score computes the Tune score (0–100) for a set of findings.
func Score(findings []Finding) int {
	worst := map[string]Severity{}
	for _, f := range findings {
		if w, ok := worst[f.ID]; !ok || f.Severity.Rank() < w.Rank() {
			worst[f.ID] = f.Severity
		}
	}
	score := 100
	for _, sev := range worst {
		score -= penalty[sev]
	}
	return max(score, 0)
}
