package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/fingerprint"
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

// ErrNoChecks means the selection matched no YAML checks. Advisor
// findings (vuln-*) may still apply.
var ErrNoChecks = errors.New("no checks match the selection; list them with: rhythm tuner checks")

// IsAdvisorID reports whether an ID pattern names advisor findings
// (vulnerability matching) rather than YAML checks.
func IsAdvisorID(pattern string) bool {
	for _, p := range []string{"vuln", "wp-core-", "wp-components-", "wp-plugin-closed", "wp-theme-closed", "php-eol", "nginx-eol", "apache-eol"} {
		if strings.HasPrefix(pattern, p) || strings.HasPrefix(p, strings.TrimSuffix(pattern, "*")) && strings.HasSuffix(pattern, "*") && pattern != "*" {
			return true
		}
	}
	return false
}

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
		if !IsAdvisorID(id) && !slices.ContainsFunc(all, func(c *Check) bool { return globMatch(id, c.ID) }) {
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
		return nil, ErrNoChecks
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

// Filtered applies the parts of a selection that make sense for findings
// (IDs, tags, minimum severity) to an advisor's output.
func Filtered(a Advisor, s Selector) Advisor { return filtered{a, s} }

type filtered struct {
	Advisor
	sel Selector
}

func (f filtered) Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]Finding, []string) {
	findings, warnings := f.Advisor.Advise(ctx, base, fp)
	var kept []Finding
	for _, x := range findings {
		switch {
		case f.sel.MinSeverity != "" && x.Severity.Rank() > f.sel.MinSeverity.Rank():
		case len(f.sel.IDs) > 0 && !slices.ContainsFunc(f.sel.IDs, func(id string) bool { return globMatch(id, x.ID) }):
		case slices.ContainsFunc(f.sel.ExcludeIDs, func(id string) bool { return globMatch(id, x.ID) }):
		case len(f.sel.Tags) > 0 && !hasAny(x.Tags, f.sel.Tags):
		case hasAny(x.Tags, f.sel.ExcludeTags):
		default:
			kept = append(kept, x)
		}
	}
	return kept, warnings
}
