// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/osv"
)

func init() { registerScanExtension(vulnsExtension{}) }

// vulnsExtension wires the vulnerability data sources into a scan: the
// optional Wordfence Intelligence feed, --timeout for the data clients
// and the Composer match on an exposed composer.lock.
type vulnsExtension struct{}

func (vulnsExtension) Help() string {
	return `Vulnerability data:
      TUNER_WORDFENCE_KEY  a free Wordfence Intelligence API key: plugins,
                           themes and core are also matched against its feed
                           (see rhythm tuner update --help)
                           An exposed composer.lock or installed.json is
                           matched against OSV.dev (up to 500 packages).`
}

func (vulnsExtension) Flags(*flag.FlagSet) {}

// Plan gives the data clients the scan's --timeout, adds the Wordfence
// feed when TUNER_WORDFENCE_KEY is set and matches an exposed Composer
// lock file's packages. Nothing changes with --no-vulns.
func (vulnsExtension) Plan(p *scanPlan) error {
	if p.vulns != nil {
		p.vulns.Timeout = p.o.timeout
		p.vulns.Wordfence = wordfenceClient(p.engine.UserAgent, p.engine.Proxy, p.o.offline)
	}
	if p.osv != nil {
		p.osv.Timeout = p.o.timeout
		p.engine.ResponseAdvisors = append(p.engine.ResponseAdvisors,
			selectedResponses{&osv.ComposerAdvisor{Client: p.osv}, p.sel})
	}
	return nil
}

func (vulnsExtension) Finished(*scanPlan, []report.Report, io.Writer) (int, error) {
	return exitOK, nil
}

// selectedResponses drops the findings of a ResponseAdvisor that the
// scan's selection leaves out, as engine.Filtered does for an Advisor.
type selectedResponses struct {
	engine.ResponseAdvisor
	sel engine.Selector
}

func (s selectedResponses) AdviseResponse(ctx context.Context, f engine.Finding, body []byte) ([]engine.Finding, []string) {
	found, warnings := s.ResponseAdvisor.AdviseResponse(ctx, f, body)
	var kept []engine.Finding
	for _, x := range found {
		if s.sel.Keeps(x) {
			kept = append(kept, x)
		}
	}
	return kept, warnings
}

// wordfenceHelp explains the optional second vulnerability source.
const wordfenceHelp = `With TUNER_WORDFENCE_KEY set to a free Wordfence Intelligence API key,
plugins, themes and core are also matched against the Wordfence
Intelligence feed (Copyright Defiant Inc.), merged with WPVulnerability by
CVE. The feed is cached with the other data. rhythm tuner update
refreshes it; a scan downloads it (which can take a few minutes) only
when no copy under a week old is cached. TUNER_WORDFENCE_API points
Tuner at a mirror.
`

// wordfenceClient builds the Wordfence Intelligence client when
// TUNER_WORDFENCE_KEY is set, else nil: the feed is opt-in. It goes
// through the same proxy as the scan and caches next to the other
// vulnerability data, so rhythm tuner update --clear clears it too.
func wordfenceClient(ua string, proxy *url.URL, offline bool) *vulns.Wordfence {
	key := os.Getenv("TUNER_WORDFENCE_KEY")
	if key == "" {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &vulns.Wordfence{
		HTTP:      &http.Client{Transport: tr},
		UserAgent: ua,
		Key:       key,
		Base:      os.Getenv("TUNER_WORDFENCE_API"), // default www.wordfence.com/api/intelligence/v3
		CacheDir:  vulns.DefaultCacheDir(),
		Offline:   offline,
	}
}
