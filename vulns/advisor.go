// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns/cache"
)

// How many components are looked up at once. The pacer still spaces the
// requests; this bounds the goroutines waiting on a slow data service.
const lookupConcurrency = 4

// errNoRecord marks a lookup that came back without a usable record.
var errNoRecord = errors.New("no vulnerability record")

// Advisor implements engine.Advisor with Client's data. It is composed of
// one advisor per kind of component (see kinds): each says what to look
// up in a fingerprint, fetches it and turns the answers into findings.
// Advisor runs their lookups together, counts what failed or came from a
// stale cache, then writes the warnings and the data status.
type Advisor struct {
	Client *Client          // the data source; required
	Now    func() time.Time // the clock end-of-life findings are judged by; nil means time.Now
}

// part is the advisor for one kind of component.
type part interface {
	// lookups lists what to look up for fp.
	lookups(fp fingerprint.Result) []*lookup
	// fetch fills l in from the data services, recording each lookup it
	// makes with lookup.did. It runs alongside the other lookups.
	fetch(ctx context.Context, a *Advisor, l *lookup, now time.Time)
	// advise turns the part's finished lookups into findings. Lookups
	// whose main data couldn't be fetched (err set) are skipped.
	advise(base *url.URL, a *Advisor, ls []*lookup, now time.Time) []engine.Finding
	// rules describes every finding ID the part emits.
	rules() []Rule
}

// kinds are the advisors Advisor is made of, in the order their findings
// are listed.
var kinds = []part{phpAdvisor{}, coreAdvisor{}, componentAdvisor{}, serverAdvisor{}}

// Rules describes every finding the vulnerability advisor emits, for
// selection, documentation and SARIF rules.
func Rules() []Rule {
	var out []Rule
	for _, p := range kinds {
		out = append(out, p.rules()...)
	}
	return out
}

var (
	// serverVersion reads a version from a Server header such as nginx/1.24.0.
	serverVersion = regexp.MustCompile(`(?i)^(nginx|apache)/([0-9]+(?:\.[0-9]+)+)`)
	// Distro builds backport security fixes without changing the version.
	backported = regexp.MustCompile(`(?i)ubuntu|debian|deb[0-9]|\bel[0-9]|centos|red ?hat|rhel|fedora|amazon|rocky|alma|suse`)
)

// component is one thing to look up.
type component struct {
	kind    string // core, plugin, theme, php, nginx, apache; php-hidden for a PHP site hiding its version
	key     string // slug, or version for core and software
	slug    string // display name / slug
	version string
	path    string
	build   string // raw version string, to spot distro builds
	source  string // where the version was read, e.g. "x-powered-by /wp-login.php"
}

// lookup is one component's lookup and everything its fetch learned.
type lookup struct {
	component
	rec     *Record
	rel     *Release
	stale   bool
	staleAt time.Time // when the oldest stale copy used was fetched
	err     error     // the main lookup failed: no findings for this component

	looked   int       // data lookups made for this component
	failures []failure // the ones that failed, err's among them

	// PHP on an end-of-life branch: advisories inferred from the oldest
	// supported branch (newerFrom), which will never be fixed on this one.
	newer     []Vuln
	newerFrom string

	// A PHP site hiding its version: recent critical or exploited flaws
	// it can't be ruled out for, per supported branch.
	flaws    []*recentFlaw
	branches []string
}

// failure is one lookup that failed: what was asked and why.
type failure struct {
	what string
	err  error
}

// did records one data lookup for l, naming it what in case it failed.
func (l *lookup) did(what string, err error) {
	l.looked++
	if err != nil {
		l.failures = append(l.failures, failure{what, err})
	}
}

// fetchAdvisories looks up l's advisories as its main lookup. It reports
// whether they arrived.
func (a *Advisor) fetchAdvisories(ctx context.Context, l *lookup) bool {
	var info cache.Info
	l.rec, info, l.err = a.Client.advisories(ctx, l.kind, l.key)
	if l.err == nil && l.rec == nil {
		l.err = errNoRecord // never expected; still, a nil record must not crash a scan
	}
	if l.err == nil {
		l.addStale(info)
	}
	l.did(l.kind+" "+l.slug, l.err)
	return l.err == nil
}

// fetchLatest looks up l's latest release. Release data is a nice-to-have,
// so a failed lookup isn't counted or reported.
func (a *Advisor) fetchLatest(ctx context.Context, l *lookup, slug string) {
	rel, info, err := a.Client.latest(ctx, l.kind, slug)
	if err == nil {
		l.rel = rel
		l.addStale(info)
	}
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

	perPart := make([][]*lookup, len(kinds))
	var wg sync.WaitGroup
	sem := make(chan struct{}, lookupConcurrency)
	for i, p := range kinds {
		perPart[i] = p.lookups(fp)
		for _, l := range perPart[i] {
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				p.fetch(ctx, a, l, now())
			})
		}
	}
	wg.Wait()

	var findings []engine.Finding
	var looked, failed, stale, old int
	var offline, wfAsked bool
	var firstErr string
	var oldest time.Time
	for i, p := range kinds {
		for _, l := range perPart[i] {
			looked += l.looked
			wfAsked = wfAsked || l.kind == "core" || l.kind == "plugin" || l.kind == "theme"
			for _, f := range l.failures {
				failed++
				if errors.Is(f.err, ErrOldCache) {
					old++
				}
				offline = offline || errors.Is(f.err, ErrOffline) || errors.Is(f.err, ErrOldCache)
				if firstErr == "" {
					firstErr = fmt.Sprintf("%s: %v", f.what, f.err)
				}
			}
			if l.stale && l.err == nil {
				stale++
			}
			if !l.staleAt.IsZero() && (oldest.IsZero() || l.staleAt.Before(oldest)) {
				oldest = l.staleAt
			}
		}
		findings = append(findings, p.advise(base, a, perPart[i], now())...)
	}
	unreachable := !offline && len(a.Client.Unreachable()) > 0 && (failed > 0 || stale > 0)

	var warnings []string
	switch {
	case unreachable:
		// Cache times are wall-clock times, unlike the advisor's clock.
		warnings = append(warnings, UnreachableWarning("", failed, looked, stale, oldest, time.Now()))
	case failed > 0 && offline && old > 0:
		warnings = append(warnings, fmt.Sprintf("vulnerability data not cached for %s (%d cached by an older Tuner); run once online to cache it", Count(failed, "component"), old))
	case failed > 0 && offline:
		warnings = append(warnings, fmt.Sprintf("vulnerability data not cached for %s; run once online to cache it", Count(failed, "component")))
	case failed > 0:
		warnings = append(warnings, fmt.Sprintf("couldn't fetch vulnerability data for %s (%s)", Count(failed, "component"), firstErr))
	}
	if stale > 0 && !unreachable {
		warnings = append(warnings, fmt.Sprintf("used cached vulnerability data older than %s for %s", a.Client.TTL, Count(stale, "component")))
	}
	if w := a.Client.Wordfence; w != nil && wfAsked {
		if err := w.Err(); err != nil {
			warnings = append(warnings, wordfenceWarning(err))
		}
	}
	return findings, warnings, DataStatus(looked, failed, stale)
}

// ok lists the lookups whose main data arrived.
func ok(ls []*lookup) []*lookup {
	var out []*lookup
	for _, l := range ls {
		if l.err == nil {
			out = append(out, l)
		}
	}
	return out
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

// Count says how many of noun there are: "1 component", "3 components".
func Count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
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
