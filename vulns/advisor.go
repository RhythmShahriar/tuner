// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns/cache"
)

// A plugin or theme with no release for this long counts as abandoned.
const abandonedAfter = 2 * 365 * 24 * time.Hour

// How many components are looked up at once. The pacer still spaces the
// requests; this bounds the goroutines waiting on a slow data service.
const lookupConcurrency = 4

var errNoRecord = errors.New("no vulnerability record")

// Advisor implements engine.Advisor with Client's data.
type Advisor struct {
	Client *Client
	Now    func() time.Time
}

var (
	serverVersion = regexp.MustCompile(`(?i)^(nginx|apache)/([0-9]+(?:\.[0-9]+)+)`)
	// Distro builds backport security fixes without changing the version.
	backported = regexp.MustCompile(`(?i)ubuntu|debian|deb[0-9]|\bel[0-9]|centos|red ?hat|rhel|fedora|amazon|rocky|alma|suse`)
)

// component is one thing to look up.
type component struct {
	kind    string // core, plugin, theme, php, nginx, apache
	key     string // slug, or version for core and software
	slug    string // display name / slug
	version string
	path    string
	build   string // raw version string, to spot distro builds
	source  string // where the version was read, e.g. "x-powered-by /wp-login.php"
}

type lookup struct {
	component
	rec     *Record
	rel     *Release
	stale   bool
	staleAt time.Time // when the oldest stale copy used was fetched
	err     error

	// PHP on an end-of-life branch: advisories inferred from the oldest
	// supported branch (newerFrom), which will never be fixed on this one.
	newer     []Vuln
	newerFrom string
	newerErr  error
}

// Vulnerability data status for a scan, as engine.Result.VulnData reports
// it: whether the scan could actually check for known vulnerabilities.
const (
	StatusOK      = "ok"      // every lookup succeeded or came from a fresh cache
	StatusPartial = "partial" // some lookups failed, or used a cache past its TTL
	StatusMissing = "missing" // no lookup succeeded
	StatusOff     = "off"     // matching was turned off (--no-vulns)
)

// DataStatus turns lookup counts into a Status value: total lookups,
// how many failed and how many were served from a stale cache.
func DataStatus(total, failed, stale int) string {
	switch {
	case total > 0 && failed >= total:
		return StatusMissing
	case failed > 0 || stale > 0:
		return StatusPartial
	}
	return StatusOK
}

// Advise implements engine.Advisor.
func (a *Advisor) Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string) {
	findings, warnings, _ := a.AdviseStatus(ctx, base, fp)
	return findings, warnings
}

// AdviseStatus is Advise plus the vulnerability data status (StatusOK,
// StatusPartial or StatusMissing), so a scan whose data service was down
// can't pass as clean. It implements engine.StatusAdvisor.
func (a *Advisor) AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]engine.Finding, []string, string) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}

	var comps []component
	if fp.Has("wordpress") && fp.WordPress != "" {
		comps = append(comps, component{kind: "core", key: fp.WordPress, slug: "wordpress", version: fp.WordPress, path: "/"})
	}
	for _, c := range fp.Components {
		comps = append(comps, component{kind: c.Type, key: c.Slug, slug: c.Slug, version: c.Version,
			path: "/wp-content/" + c.Type + "s/" + c.Slug + "/"})
	}
	if fp.PHP != "" {
		comps = append(comps, component{kind: "php", key: fp.PHP, slug: "PHP", version: fp.PHP, path: "/", build: fp.PHPBuild, source: fp.PHPSource})
	}
	if m := serverVersion.FindStringSubmatch(fp.Server); m != nil {
		kind := strings.ToLower(m[1])
		comps = append(comps, component{kind: kind, key: m[2], slug: m[1], version: m[2], path: "/", build: fp.Server})
	}

	lookups := make([]*lookup, len(comps))
	var wg sync.WaitGroup
	var hidden struct {
		flaws    []*recentFlaw
		branches []string
		stale    bool
		err      error
	}
	if fp.Has("php") && fp.PHP == "" {
		wg.Go(func() { hidden.flaws, hidden.branches, hidden.stale, hidden.err = a.recentPHPFlaws(ctx, now()) })
	}
	sem := make(chan struct{}, lookupConcurrency)
	for i, c := range comps {
		l := &lookup{component: c}
		lookups[i] = l
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			var info cache.Info
			l.rec, info, l.err = a.Client.advisories(ctx, c.kind, c.key)
			l.addStale(info)
			if c.kind == "core" || c.kind == "plugin" || c.kind == "theme" {
				key := c.slug
				if c.kind == "core" {
					key = "wordpress"
				}
				// Release data is a nice-to-have; a failed lookup isn't reported.
				rel, info, err := a.Client.latest(ctx, c.kind, key)
				if err == nil {
					l.rel = rel
					l.addStale(info)
				}
			}
			if c.kind == "php" && l.err == nil && l.rec != nil {
				var stale bool
				l.newer, l.newerFrom, stale, l.newerErr = a.newerPHPFlaws(ctx, l.rec, c.version, now())
				l.stale = l.stale || stale
			}
		})
	}
	wg.Wait()

	var findings []engine.Finding
	var outdated, abandoned, unverified []string
	var looked, failed, stale, old int
	var offline bool
	var firstErr string
	fail := func(what string, err error) {
		failed++
		if errors.Is(err, ErrOldCache) {
			old++
		}
		offline = offline || errors.Is(err, ErrOffline) || errors.Is(err, ErrOldCache)
		if firstErr == "" {
			firstErr = fmt.Sprintf("%s: %v", what, err)
		}
	}
	if fp.Has("php") && fp.PHP == "" {
		looked++
	}
	if hidden.err != nil {
		fail("recent PHP advisories", hidden.err)
	} else if f, ok := hiddenPHPFinding(base, hidden.flaws, hidden.branches); ok {
		findings = append(findings, f)
	}
	if hidden.stale {
		stale++
	}
	for _, l := range lookups {
		looked++
		if l.err == nil && l.rec == nil {
			l.err = errNoRecord // never expected; still, a nil record must not crash a scan
		}
		if l.err != nil {
			fail(l.kind+" "+l.slug, l.err)
			continue
		}
		if l.newer != nil || l.newerFrom != "" || l.newerErr != nil {
			looked++
		}
		if l.newerErr != nil {
			fail("newer PHP advisories", l.newerErr)
		}
		if l.stale {
			stale++
		}
		f, hasVulns := a.vulnFinding(base, l)
		if hasVulns {
			findings = append(findings, f)
		}

		switch l.kind {
		case "core":
			if !hasVulns && l.rel != nil && l.rel.Latest != "" && Compare(l.version, l.rel.Latest) < 0 {
				findings = append(findings, finding(base, "wp-core-outdated", engine.Low, "/",
					fmt.Sprintf("WordPress %s is out of date", l.version),
					[]string{fmt.Sprintf("installed %s, latest %s", l.version, l.rel.Latest)},
					"Older releases miss security hardening and fixes.",
					fmt.Sprintf("Update WordPress to %s (Dashboard → Updates, or: wp core update).", l.rel.Latest),
					"wordpress", "outdated"))
			}
		case "plugin", "theme":
			if l.rec.Closed {
				ev := []string{"closed on wordpress.org"}
				if l.rec.ClosedDate != "" {
					ev[0] += " on " + l.rec.ClosedDate
				}
				if l.rec.ClosedReason != "" {
					ev = append(ev, "reason: "+l.rec.ClosedReason)
				}
				f := finding(base, "wp-"+l.kind+"-closed", engine.Medium, l.path,
					fmt.Sprintf("%s %s was closed on wordpress.org", strings.ToUpper(l.kind[:1])+l.kind[1:], l.slug), ev,
					"Closed "+l.kind+"s get no updates, and are often closed because of an unfixed security issue.",
					"Remove it, or replace it with a maintained alternative.", "wordpress", "abandoned")
				f.Source = Source
				findings = append(findings, f)
			}
			switch {
			case l.version == "" && len(l.rec.Vulns) > 0:
				unverified = append(unverified, fmt.Sprintf("%s (%d known in some versions)", l.slug, len(l.rec.Vulns)))
			case l.version != "" && !hasVulns && l.rel != nil && l.rel.Latest != "" && Compare(l.version, l.rel.Latest) < 0:
				outdated = append(outdated, fmt.Sprintf("%s %s → %s", l.slug, l.version, l.rel.Latest))
			}
			if l.rel != nil && !l.rel.LastUpdated.IsZero() && now().Sub(l.rel.LastUpdated) > abandonedAfter {
				abandoned = append(abandoned, fmt.Sprintf("%s (last release %s)", l.slug, l.rel.LastUpdated.Format("2006-01-02")))
			}
		case "php", "nginx", "apache":
			if eol, err := time.Parse("2006-01-02", l.rec.EndOfLife); err == nil && now().After(eol) {
				name := cmp.Or(l.rec.Name, l.slug+" "+l.version)
				sev, impact := engine.Medium, "No more security fixes are released for this branch."
				fix := fmt.Sprintf("Upgrade to a supported %s release.", l.slug)
				if l.kind == "php" {
					// PHP is what every request runs through, and its EOL
					// branches quietly collect new, never-fixed flaws.
					sev = engine.High
					impact = "No more security fixes are released for this branch: newly disclosed PHP flaws are never fixed on it, and vulnerability databases stop listing them for it."
					if n := len(l.newer); n > 0 {
						impact += fmt.Sprintf(" %d flaws disclosed since support ended likely affect it (see vuln-php).", n)
					}
					if l.newerFrom != "" {
						fix = fmt.Sprintf("Upgrade to a supported PHP branch (%s or later).", l.newerFrom)
					}
				}
				f := finding(base, l.kind+"-eol", sev, "/",
					fmt.Sprintf("%s is past end of life", name),
					[]string{fmt.Sprintf("%s %s, support ended %s", l.slug, l.version, l.rec.EndOfLife)},
					impact, fix, l.kind, "outdated")
				if l.source != "" {
					f.Evidence.Matched = append(f.Evidence.Matched, "version from "+l.source)
				}
				a.distroCaveat(&f, l.build)
				findings = append(findings, f)
			}
		}
	}

	if len(outdated) > 0 {
		findings = append(findings, finding(base, "wp-components-outdated", engine.Low, "/wp-content/",
			fmt.Sprintf("%d plugins or themes out of date", len(outdated)), outdated,
			"Outdated plugins and themes are the most common way WordPress sites get compromised.",
			"Update them (Dashboard → Updates, or: wp plugin update --all && wp theme update --all).",
			"wordpress", "outdated"))
	}
	if len(abandoned) > 0 {
		findings = append(findings, finding(base, "wp-components-abandoned", engine.Low, "/wp-content/",
			fmt.Sprintf("%d plugins or themes look abandoned", len(abandoned)), abandoned,
			"No release in over two years. Future security issues are unlikely to be fixed.",
			"Replace them with maintained alternatives.", "wordpress", "abandoned"))
	}
	if len(unverified) > 0 {
		f := finding(base, "wp-components-unverified", engine.Info, "/wp-content/",
			fmt.Sprintf("Versions unknown for %d plugins or themes with known vulnerabilities", len(unverified)), unverified,
			"Tuner couldn't read their versions, so it can't tell whether the site is affected.",
			"Check the installed versions in the dashboard, or rerun with the default profile so readme.txt and style.css are read.",
			"wordpress", "vuln")
		f.Confidence = "low"
		findings = append(findings, f)
	}

	var oldest time.Time
	for _, l := range lookups {
		if !l.staleAt.IsZero() && (oldest.IsZero() || l.staleAt.Before(oldest)) {
			oldest = l.staleAt
		}
	}
	unreachable := !offline && len(a.Client.Unreachable()) > 0 && (failed > 0 || stale > 0)

	var warnings []string
	switch {
	case unreachable:
		// Cache times are wall-clock times, unlike the advisor's clock.
		warnings = append(warnings, UnreachableWarning("", failed, looked, stale, oldest, time.Now()))
	case failed > 0 && offline && old > 0:
		warnings = append(warnings, fmt.Sprintf("vulnerability data not cached for %d components (%d cached by an older Tuner); run once online to cache it", failed, old))
	case failed > 0 && offline:
		warnings = append(warnings, fmt.Sprintf("vulnerability data not cached for %d components; run once online to cache it", failed))
	case failed > 0:
		warnings = append(warnings, fmt.Sprintf("couldn't fetch vulnerability data for %d components (%s)", failed, firstErr))
	}
	if stale > 0 && !unreachable {
		warnings = append(warnings, fmt.Sprintf("used cached vulnerability data older than %s for %d components", a.Client.TTL, stale))
	}
	return findings, warnings, DataStatus(looked, failed, stale)
}

// addStale notes a lookup served from a stale cache.
func (l *lookup) addStale(info cache.Info) {
	if !info.Stale {
		return
	}
	l.stale = true
	if l.staleAt.IsZero() || info.Fetched.Before(l.staleAt) {
		l.staleAt = info.Fetched
	}
}

// UnreachableWarning is the one warning a scan gets when a data service
// can't be reached: what was used instead and what wasn't checked. what
// names the data ("" for vulnerability data in general, or e.g. "Composer
// " with a trailing space); failed of total lookups had no cached copy and
// stale used one, the oldest fetched at oldest.
func UnreachableWarning(what string, failed, total, stale int, oldest, now time.Time) string {
	msg := what + "vulnerability data unreachable"
	switch {
	case stale > 0 && failed > 0:
		msg += fmt.Sprintf(", using %s; no cached data for %d of %d, so their known vulnerabilities were not checked", cacheAge(oldest, now), failed, total)
	case stale > 0:
		msg += ", using " + cacheAge(oldest, now)
	case failed >= total:
		return msg + ", no cached data; known vulnerabilities not checked"
	default:
		return msg + fmt.Sprintf(", no cached data for %d of %d lookups; their known vulnerabilities not checked", failed, total)
	}
	return msg + " (use --offline to skip)"
}

// cacheAge says how old a cached copy is: "cache from 3 days ago".
func cacheAge(fetched, now time.Time) string {
	if fetched.IsZero() {
		return "cached data"
	}
	d := now.Sub(fetched)
	n, unit := int(d/time.Minute), "minute"
	switch {
	case d >= 48*time.Hour:
		n, unit = int(d/(24*time.Hour)), "day"
	case d >= 2*time.Hour:
		n, unit = int(d/time.Hour), "hour"
	}
	n = max(n, 1)
	if n != 1 {
		unit += "s"
	}
	return fmt.Sprintf("cache from %d %s ago", n, unit)
}

// vulnFinding builds the one finding that lists every advisory affecting a
// component. It returns false if none apply.
func (a *Advisor) vulnFinding(base *url.URL, l *lookup) (engine.Finding, bool) {
	if l.version == "" || l.rec == nil {
		return engine.Finding{}, false
	}
	var affected []Vuln
	for _, v := range l.rec.Vulns {
		if v.Affects(l.version) {
			affected = append(affected, v)
		}
	}
	affected = append(affected, l.newer...)
	inferred := map[string]bool{}
	for _, v := range l.newer {
		inferred[v.ID] = true
	}
	if len(affected) == 0 {
		return engine.Finding{}, false
	}

	worst, kev, unfixed := engine.Info, 0, 0
	fixedIn := ""
	var advisories []engine.Advisory
	for _, v := range affected {
		sev := engine.Severity(v.Severity)
		if sev.Rank() < 0 {
			sev = "" // unrated
		}
		if r := cmp.Or(sev, engine.Medium); r.Rank() < worst.Rank() {
			worst = r
		}
		if v.KEV {
			kev++
		}
		if fx := v.FixedIn(); fx != "" && (fixedIn == "" || Compare(fx, fixedIn) > 0) {
			fixedIn = fx
		} else if fx == "" && l.kind != "core" {
			unfixed++
		}
		advisories = append(advisories, engine.Advisory{
			ID: v.ID, Title: v.Title, CVEs: v.CVEs, Severity: sev, CVSS: v.CVSS, KEV: v.KEV,
			FixedIn: v.FixedIn(), References: v.References,
		})
	}
	slices.SortStableFunc(advisories, func(x, y engine.Advisory) int {
		if x.KEV != y.KEV {
			if x.KEV {
				return -1
			}
			return 1
		}
		// Within a severity, flaws that will never be fixed on this branch first.
		return cmp.Or(cmp.Compare(rankOr(x.Severity), rankOr(y.Severity)), cmpBool(inferred[x.ID], inferred[y.ID]), cmp.Compare(y.CVSS, x.CVSS))
	})

	name := l.slug
	switch l.kind {
	case "core":
		name = "WordPress"
	case "theme":
		name = "theme " + l.slug
	}
	plural := "ies"
	if len(affected) == 1 {
		plural = "y"
	}
	title := fmt.Sprintf("%s %s: %d known vulnerabilit%s", name, l.version, len(affected), plural)

	var ev []string
	for _, ad := range advisories[:min(len(advisories), 5)] {
		line := strings.ToUpper(string(cmp.Or(ad.Severity, "unrated")))
		if len(ad.CVEs) > 0 && ad.Title != ad.CVEs[0] {
			line += " " + ad.CVEs[0]
		}
		line += " " + ad.Title
		if ad.FixedIn != "" {
			line += " (fixed in " + ad.FixedIn + ")"
		}
		if inferred[ad.ID] {
			line += " (no fix for this branch)"
		}
		if ad.KEV {
			line += " [actively exploited]"
		}
		ev = append(ev, line)
	}
	if n := len(advisories) - 5; n > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", n))
	}

	impact := fmt.Sprintf("%d published vulnerabilities affect %s %s; the worst is rated %s.", len(affected), name, l.version, worst)
	if kev > 0 {
		impact += fmt.Sprintf(" %d of them are in CISA's Known Exploited Vulnerabilities catalog: attackers use them in the wild.", kev)
	}
	if n := len(l.newer); n > 0 {
		impact += fmt.Sprintf(" %d were disclosed after PHP %s reached end of life: they're listed for PHP %s with no lower version bound, so they reach older branches too, and will never be fixed on this one.",
			n, branchOf(l.version), l.newerFrom)
	}

	latest := ""
	if l.rel != nil {
		latest = l.rel.Latest
	}
	var fix string
	switch {
	case l.kind == "core":
		fix = "Update WordPress to the latest release"
		if latest != "" {
			fix += " (" + latest + ")"
		}
		fix += ": Dashboard → Updates, or: wp core update"
	case l.kind == "php" && len(l.newer) > 0:
		fix = fmt.Sprintf("Upgrade to a supported PHP branch (%s or later). PHP %s is end of life, so %d of these issues will never be fixed on it.",
			l.newerFrom, branchOf(l.version), len(l.newer))
	case fixedIn == "" && unfixed > 0:
		fix = fmt.Sprintf("No fixed version is known. Remove or replace %s.", name)
	case l.kind == "plugin" || l.kind == "theme":
		fix = fmt.Sprintf("Update %s to %s or later", name, fixedIn)
		if latest != "" && latest != fixedIn {
			fix += " (latest is " + latest + ")"
		}
		fix += fmt.Sprintf(": wp %s update %s", l.kind, l.slug)
		if unfixed > 0 {
			fix += fmt.Sprintf(". %d of the issues have no known fixed version; consider replacing it.", unfixed)
		}
	default:
		fix = fmt.Sprintf("Update %s", l.slug)
		if fixedIn != "" {
			fix += " to " + fixedIn + " or later"
		}
		fix += " from your OS or vendor packages."
	}

	tags := []string{"vuln", l.kind}
	if l.kind == "plugin" || l.kind == "theme" || l.kind == "core" {
		tags = append(tags, "wordpress")
	}
	if kev > 0 {
		tags = append(tags, "known-exploited")
	}
	f := finding(base, "vuln-"+l.kind+"-"+strings.ToLower(l.slug), worst, l.path, title, ev, impact, fix, tags...)
	if l.kind == "core" || l.kind == "php" || l.kind == "nginx" || l.kind == "apache" {
		f.ID = "vuln-" + l.kind
	}
	f.Advisories = advisories
	f.Source = Source
	if len(advisories) > 0 {
		f.References = advisories[0].References
	}
	if l.source != "" {
		f.Evidence.Matched = append(f.Evidence.Matched, "version from "+l.source)
	}
	// Only inferred advisories: likely, not confirmed.
	if len(l.newer) == len(affected) {
		f.Confidence = "low"
		f.Caveat = "inferred from a supported branch's advisories"
	}
	if l.kind != "plugin" && l.kind != "theme" && l.kind != "core" {
		a.distroCaveat(&f, l.build)
	}
	return f, true
}

// distroCaveat lowers confidence for versions reported by distro packages,
// which backport fixes without changing the upstream version number.
func (a *Advisor) distroCaveat(f *engine.Finding, build string) {
	if backported.MatchString(build) {
		f.Confidence = "low"
		f.Caveat = "a distro build may already include the fix"
		f.Impact += " The server reports a distribution build (" + build + "), which may include backported fixes; check the package's security status before acting."
	}
}

// cmpBool orders true before false.
func cmpBool(x, y bool) int {
	switch {
	case x == y:
		return 0
	case x:
		return -1
	}
	return 1
}

func rankOr(s engine.Severity) int {
	if r := s.Rank(); r >= 0 {
		return r
	}
	return engine.Medium.Rank()
}

func finding(base *url.URL, id string, sev engine.Severity, path, title string, ev []string, impact, fix string, tags ...string) engine.Finding {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + path
	return engine.Finding{
		ID:         id,
		Title:      title,
		Severity:   sev,
		Confidence: "high",
		URL:        u.String(),
		Path:       path,
		Evidence:   engine.Evidence{Request: "version match", Matched: ev},
		Impact:     impact,
		Fix:        fix,
		Tags:       tags,
	}
}
