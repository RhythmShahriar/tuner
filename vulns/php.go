package vulns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// When a site hides its PHP version, critical or actively exploited PHP
// advisories published within this window are the ones it can't rule out.
const recentPHPWindow = 180 * 24 * time.Hour

// Branch is one PHP release branch, from php.net's release states.
type Branch struct {
	Version     string `json:"version"`                // e.g. 8.4
	State       string `json:"state,omitempty"`        // stable, security or eol
	SecurityEnd string `json:"security_end,omitempty"` // YYYY-MM-DD; no fixes after it
}

// Supported reports whether the branch still gets security fixes.
func (b Branch) Supported(now time.Time) bool {
	if end, err := time.Parse(time.DateOnly, b.SecurityEnd); err == nil && now.After(end) {
		return false
	}
	return b.State == "stable" || b.State == "security"
}

// PHPBranches returns every PHP release branch php.net knows, oldest first.
func (c *Client) PHPBranches(ctx context.Context) (branches []Branch, stale bool, err error) {
	c.init()
	return load(c, ctx, "php.net/releases", "states", func(ctx context.Context) ([]Branch, error) {
		// {"8": {"8.4": {"state": "stable", "security_support_end": "2028-12-31T00:00:00+00:00"}}};
		// ancient branches have a null state.
		var raw map[string]map[string]struct {
			State       flex `json:"state"`
			SecurityEnd flex `json:"security_support_end"`
		}
		if err := c.getJSON(ctx, c.PHPNetBase+"/releases/states.php", &raw); err != nil {
			return nil, err
		}
		var out []Branch
		for _, major := range raw {
			for v, b := range major {
				end := string(b.SecurityEnd)
				if len(end) > len(time.DateOnly) {
					end = end[:len(time.DateOnly)]
				}
				out = append(out, Branch{Version: v, State: string(b.State), SecurityEnd: end})
			}
		}
		if len(out) == 0 {
			return nil, errors.New("php.net: no release branches")
		}
		slices.SortFunc(out, func(a, b Branch) int { return Compare(a.Version, b.Version) })
		return out, nil
	})
}

// supportedBranches returns the branches that still get fixes, oldest first.
func (c *Client) supportedBranches(ctx context.Context, now time.Time) ([]Branch, bool, error) {
	all, stale, err := c.PHPBranches(ctx)
	if err != nil {
		return nil, false, err
	}
	var out []Branch
	for _, b := range all {
		if b.Supported(now) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, stale, errors.New("php.net: no supported branches")
	}
	return out, stale, nil
}

// branchOf returns the major.minor branch of a version: 8.1.2 → 8.1.
func branchOf(v string) string {
	p := strings.SplitN(v, ".", 3)
	if len(p) < 2 {
		return v
	}
	return p[0] + "." + p[1]
}

func published(v Vuln) (time.Time, bool) {
	if len(v.Published) < len(time.DateOnly) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly, v.Published[:len(time.DateOnly)])
	return t, err == nil
}

// advisoryKey identifies an advisory across branches, whose records each
// carry their own copy.
func advisoryKey(v Vuln) string {
	if len(v.CVEs) > 0 {
		return v.CVEs[0]
	}
	return v.ID
}

// newerPHPFlaws finds advisories disclosed after an end-of-life branch lost
// support. WPVulnerability stops listing new CVEs for such branches, so they
// are inferred: an advisory for the oldest supported branch with no lower
// bound affects every older release too, and will never be fixed on an EOL
// branch. Advisories rec already lists are skipped. It returns nothing when
// version's branch is still supported.
func (a *Advisor) newerPHPFlaws(ctx context.Context, rec *Record, version string, now time.Time) (flaws []Vuln, from string, stale bool, err error) {
	eol, perr := time.Parse(time.DateOnly, rec.EndOfLife)
	if perr != nil || !now.After(eol) {
		return nil, "", false, nil
	}
	supported, stale, err := a.Client.supportedBranches(ctx, now)
	if err != nil {
		return nil, "", false, err
	}
	i := slices.IndexFunc(supported, func(b Branch) bool { return Compare(b.Version, branchOf(version)) > 0 })
	if i < 0 {
		return nil, "", stale, nil
	}
	from = supported[i].Version
	newer, s, err := a.Client.Advisories(ctx, "php", from+".0")
	if err != nil {
		return nil, "", false, err
	}
	known := map[string]bool{}
	for _, v := range rec.Vulns {
		known[v.ID] = true
		for _, c := range v.CVEs {
			known[c] = true
		}
	}
	for _, v := range newer.Vulns {
		pub, ok := published(v)
		if v.Min != "" || !ok || !pub.After(eol) || known[v.ID] || slices.ContainsFunc(v.CVEs, func(c string) bool { return known[c] }) {
			continue
		}
		known[v.ID] = true
		for _, c := range v.CVEs {
			known[c] = true
		}
		v.Max, v.MaxOp, v.Unfixed = "", "", true
		flaws = append(flaws, v)
	}
	return flaws, from, stale || s, nil
}

// recentFlaw is one critical or actively exploited PHP advisory, merged
// across the supported branches that list it.
type recentFlaw struct {
	Vuln
	fixed map[string]string // branch → first fixed release; "" if none yet
}

// recentPHPFlaws gathers the critical or actively exploited advisories
// published in the last recentPHPWindow for every supported PHP branch,
// one per CVE, most pressing first. branches are newest first.
func (a *Advisor) recentPHPFlaws(ctx context.Context, now time.Time) (flaws []*recentFlaw, branches []string, stale bool, err error) {
	supported, stale, err := a.Client.supportedBranches(ctx, now)
	if err != nil {
		return nil, nil, false, err
	}
	recs := make([]*Record, len(supported))
	errs := make([]error, len(supported))
	stales := make([]bool, len(supported))
	var wg sync.WaitGroup
	for i, b := range supported {
		wg.Go(func() { recs[i], stales[i], errs[i] = a.Client.Advisories(ctx, "php", b.Version+".0") })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, nil, false, err
	}

	byKey := map[string]*recentFlaw{}
	for i, rec := range recs {
		stale = stale || stales[i]
		branch := supported[i].Version
		branches = append(branches, branch)
		for _, v := range rec.Vulns {
			pub, ok := published(v)
			if !ok || now.Sub(pub) > recentPHPWindow || (v.Severity != "critical" && !v.KEV) {
				continue
			}
			f := byKey[advisoryKey(v)]
			if f == nil {
				f = &recentFlaw{Vuln: v, fixed: map[string]string{}}
				byKey[advisoryKey(v)] = f
				flaws = append(flaws, f)
			}
			f.KEV = f.KEV || v.KEV
			if fx, ok := f.fixed[branch]; !ok || Compare(v.FixedIn(), fx) > 0 {
				f.fixed[branch] = v.FixedIn()
			}
		}
	}
	slices.Reverse(branches)
	slices.SortStableFunc(flaws, func(x, y *recentFlaw) int {
		return cmp.Or(cmpBool(x.KEV, y.KEV), cmp.Compare(y.Published, x.Published), cmp.Compare(y.CVSS, x.CVSS),
			cmp.Compare(advisoryKey(x.Vuln), advisoryKey(y.Vuln)))
	})
	return flaws, branches, stale, nil
}

// fixedList renders "fixed in 8.4.27, 8.3.36" for the branches that list a
// flaw, newest first, noting those without a fix yet.
func (f *recentFlaw) fixedList(branches []string) string {
	var fixed, open []string
	for _, b := range branches {
		fx, ok := f.fixed[b]
		switch {
		case !ok:
		case fx == "":
			open = append(open, b)
		default:
			fixed = append(fixed, fx)
		}
	}
	var parts []string
	if len(fixed) > 0 {
		parts = append(parts, "fixed in "+strings.Join(fixed, ", "))
	}
	if len(open) > 0 {
		parts = append(parts, "no fix yet for "+strings.Join(open, ", "))
	}
	return strings.Join(parts, "; ")
}

// hiddenPHPFinding warns that a site's PHP version couldn't be read, naming
// the recent critical flaws that can't be ruled out. It returns false when
// there are none.
func hiddenPHPFinding(base *url.URL, flaws []*recentFlaw, branches []string) (engine.Finding, bool) {
	if len(flaws) == 0 {
		return engine.Finding{}, false
	}
	label := func(f *recentFlaw) string {
		s := cmp.Or(f.Severity, "unrated")
		if f.KEV {
			s += ", actively exploited"
		}
		return s
	}
	top := flaws[0]
	title := fmt.Sprintf("PHP version hidden: can't rule out %s (%s)", cmp.Or(advisoryKey(top.Vuln), top.Title), label(top))
	if n := len(flaws) - 1; n > 0 {
		title += fmt.Sprintf(" and %d more", n)
	}

	var ev []string
	var advisories []engine.Advisory
	latest := map[string]string{} // branch → newest fixed release among the flaws
	kev := 0
	for i, f := range flaws {
		fixed := f.fixedList(branches)
		if i < 5 {
			line := f.Title
			if len(f.CVEs) > 0 && f.Title != f.CVEs[0] {
				line = f.CVEs[0] + " " + line
			}
			if fixed != "" {
				line += " — " + fixed
			}
			if f.KEV {
				line += " [actively exploited]"
			}
			ev = append(ev, line)
		}
		if f.KEV {
			kev++
		}
		for b, fx := range f.fixed {
			if fx != "" && Compare(fx, latest[b]) > 0 {
				latest[b] = fx
			}
		}
		sev := engine.Severity(f.Severity)
		if sev.Rank() < 0 {
			sev = ""
		}
		advisories = append(advisories, engine.Advisory{
			ID: f.ID, Title: f.Title, CVEs: f.CVEs, Severity: sev, CVSS: f.CVSS, KEV: f.KEV,
			FixedIn: strings.TrimPrefix(fixed, "fixed in "), References: f.References,
		})
	}
	if n := len(flaws) - 5; n > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", n))
	}

	plural := "flaws were"
	if len(flaws) == 1 {
		plural = "flaw was"
	}
	impact := fmt.Sprintf("The site runs PHP but doesn't reveal its version (hiding it is good practice), so Tuner can't tell whether it's patched. "+
		"%d critical or actively exploited PHP %s disclosed in the last %d days; every release before the fixed ones is affected.",
		len(flaws), plural, int(recentPHPWindow.Hours()/24))
	if kev > 0 {
		impact += fmt.Sprintf(" %d of them are in CISA's Known Exploited Vulnerabilities catalog: attackers use them in the wild.", kev)
	}

	var safe []string
	for _, b := range branches {
		if fx := latest[b]; fx != "" {
			safe = append(safe, fx)
		}
	}
	fix := "Check the PHP version serving the site: php -v on the server (the command line can run a different PHP than the web server, " +
		"so confirm in your hosting panel, or in WordPress under Tools → Site Health → Info → Server)."
	if len(safe) > 0 {
		fix += fmt.Sprintf(" If it's older than %s on its branch, upgrade.", strings.Join(safe, ", "))
	}
	fix += fmt.Sprintf(" Branches older than %s are end of life and need moving to a supported one.", branches[len(branches)-1])

	f := finding(base, "php-version-hidden", engine.Medium, "/", title, ev, impact, fix, "php", "vuln")
	f.Confidence = "low"
	f.Caveat = "the PHP version is hidden, so this can't be confirmed"
	f.Advisories = advisories
	f.References = top.References
	f.Source = Source
	return f, true
}
