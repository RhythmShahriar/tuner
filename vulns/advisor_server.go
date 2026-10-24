// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// serverAdvisor matches the nginx or Apache version from the Server
// header: known vulnerabilities (vuln-nginx, vuln-apache) and an
// end-of-life branch (nginx-eol, apache-eol).
type serverAdvisor struct{}

func (serverAdvisor) lookups(fp fingerprint.Result) []*lookup {
	m := serverVersion.FindStringSubmatch(fp.Server)
	if m == nil {
		return nil
	}
	return []*lookup{{component: component{kind: strings.ToLower(m[1]), key: m[2], slug: m[1], version: m[2], path: "/", build: fp.Server}}}
}

func (serverAdvisor) fetch(ctx context.Context, a *Advisor, l *lookup, _ time.Time) {
	a.fetchAdvisories(ctx, l)
}

func (serverAdvisor) advise(base *url.URL, a *Advisor, ls []*lookup, now time.Time) []engine.Finding {
	var out []engine.Finding
	for _, l := range ok(ls) {
		if f, found := a.vulnFinding(base, l); found {
			out = append(out, f)
		}
		if f, found := a.eolFinding(base, l, now); found {
			out = append(out, f)
		}
	}
	return out
}

func (serverAdvisor) rules() []Rule {
	var out []Rule
	for _, s := range []string{"nginx", "apache"} {
		name := map[string]string{"nginx": "nginx", "apache": "Apache"}[s]
		out = append(out,
			NewRule("vuln-"+s, false, engine.High, name+" version with known vulnerabilities", "vuln", s),
			NewRule(s+"-eol", false, engine.Medium, name+" branch past end of life", s, "outdated"))
	}
	return out
}
