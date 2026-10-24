// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/vulns"
)

func init() { registerScanExtension(&localExtension{}) }

// localExtension adds the local-scan flags --integrity and --discover.
type localExtension struct {
	integrity bool
	discover  bool
	// nested holds, per discovered install, the installs found inside
	// it. Each is scanned on its own, so the parent's walk skips them.
	nested map[string][]string
}

// Help is the section printed under scan help.
func (e *localExtension) Help() string {
	return `Local integrity:
      --integrity          compare WordPress core and wordpress.org plugin files
                           with the checksums WordPress.org publishes (fetched
                           once per release and cached; --offline uses the
                           cache). Checksums that can't be loaded mark the
                           scan partial. TUNER_WPORG_API and TUNER_WPDL_API
                           point it at mirrors.
      --discover           scan every WordPress and Laravel install under each
                           folder target, each with its own report (looks 6
                           folders deep; skips vendor, node_modules and .git)
`
}

// Flags registers the extension's flags.
func (e *localExtension) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&e.integrity, "integrity", false, "")
	fs.BoolVar(&e.discover, "discover", false, "")
}

// Plan expands --discover folders into their installs, then has each
// local target's scan skip the installs nested in it and compare
// checksums under --integrity. What --discover found is shown before the
// scan.
func (e *localExtension) Plan(p *scanPlan) error {
	var found strings.Builder
	targets, err := e.expand(p.targets, &found)
	if err != nil {
		return err
	}
	if e.discover {
		p.targets = targets
		p.write.Many = len(p.targets) > 1
		for line := range strings.Lines(found.String()) {
			p.notes = append(p.notes, strings.TrimSuffix(line, "\n"))
		}
	}
	if e.integrity {
		// --integrity reads files, so a URL target can't use it. Say so
		// rather than drop it, as --discover does.
		urls := 0
		for _, t := range targets {
			if !isLocalPath(t) {
				urls++
			}
		}
		switch {
		case urls == len(targets):
			return usagef("%s", named("--integrity needs a folder target, such as rhythm tuner scan --integrity /var/www/site"))
		case urls == 1:
			p.notes = append(p.notes, "--integrity checks folder targets only; 1 URL target is scanned without it")
		case urls > 1:
			p.notes = append(p.notes, fmt.Sprintf("--integrity checks folder targets only; %d URL targets are scanned without it", urls))
		}
	}
	ua, proxy, offline := p.engine.UserAgent, p.engine.Proxy, p.o.offline
	p.localFor = append(p.localFor, func(target string, o *local.Options) {
		e.configure(o, target, ua, proxy, offline)
	})
	return nil
}

// Finished has nothing to add after the scan.
func (e *localExtension) Finished(*scanPlan, []report.Report, io.Writer) (int, error) {
	return exitOK, nil
}

// expand replaces each folder target with the installs found under it
// when --discover is on, saying how many it found on w. Other targets
// are kept as they are. A folder with no installs is a usage error, so
// a typo in the path doesn't pass as a clean scan.
func (e *localExtension) expand(targets []string, w io.Writer) ([]string, error) {
	if !e.discover {
		return targets, nil
	}
	var out []string
	folders := 0
	e.nested = nil
	for _, t := range targets {
		if !isLocalPath(t) {
			out = append(out, t)
			continue
		}
		folders++
		d, err := local.Discover(t, 0)
		if err != nil {
			return nil, usageError{Msg: err.Error()}
		}
		if len(d.Installs) == 0 {
			return nil, usagef("--discover found no WordPress or Laravel installs under %s (looked %d folders deep)", d.Root, local.DefaultDiscoverDepth)
		}
		noun := "installs"
		if len(d.Installs) == 1 {
			noun = "install"
		}
		_, _ = fmt.Fprintf(w, "found %d %s under %s\n", len(d.Installs), noun, d.Root)
		for _, warn := range d.Warnings() {
			_, _ = fmt.Fprintln(w, warn)
		}
		for _, in := range d.Installs {
			out = append(out, in.Path)
			for _, inner := range d.Installs {
				if strings.HasPrefix(inner.Path, in.Path+string(filepath.Separator)) && !slices.Contains(e.nested[in.Path], inner.Path) {
					if e.nested == nil {
						e.nested = map[string][]string{}
					}
					e.nested[in.Path] = append(e.nested[in.Path], inner.Path)
				}
			}
		}
	}
	if folders == 0 {
		return nil, usagef("%s", named("--discover needs a folder target, such as rhythm tuner scan --discover /var/www"))
	}
	return dedupe(out), nil
}

// configure applies the flags to the options of a local scan of target.
func (e *localExtension) configure(o *local.Options, target, ua string, proxy *url.URL, offline bool) {
	o.SkipDirs = append(o.SkipDirs, e.nested[target]...)
	if !e.integrity {
		return
	}
	o.Integrity = true
	o.Checksums = checksumsClient(ua, proxy, offline)
}

// checksumsClient builds the WordPress.org checksum client. It caches
// next to the other vulnerability data, so rhythm tuner update --clear
// clears it too.
func checksumsClient(ua string, proxy *url.URL, offline bool) *local.Checksums {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	cache := vulns.DefaultCacheDir()
	if cache != "" {
		cache = filepath.Join(cache, "checksums")
	}
	return &local.Checksums{
		HTTP:       &http.Client{Transport: tr, Timeout: 20 * time.Second},
		UserAgent:  ua,
		CoreBase:   os.Getenv("TUNER_WPORG_API"), // a mirror; default api.wordpress.org
		PluginBase: os.Getenv("TUNER_WPDL_API"),  // default downloads.wordpress.org
		CacheDir:   cache,
		Offline:    offline,
	}
}
