// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/RhythmShahriar/tuner/checkpack"
	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
)

// Where a scan's checks came from.
const (
	setBuiltIn   = "built-in"
	setPack      = "pack"
	setDirectory = "directory"
)

// checkSet is the checks a run uses and where they came from.
type checkSet struct {
	source   string
	pack     *checkpack.Pack // when source is setPack
	checks   []*engine.Check
	warnings []string // pack trouble; the run goes on with what's here
	// alerts are the warnings that matter even with -q, such as an
	// unreachable pack host, which would otherwise look like an
	// unexplained delay. Each is also in warnings.
	alerts []string
}

// data returns a fingerprint data file from the pack in use, or false to
// use the built-in copy. Plugin discovery reads its tables through it.
func (s *checkSet) data(name string) ([]byte, bool) {
	if s.source != setPack {
		return nil, false
	}
	return s.pack.Data(name)
}

// localRules returns the pack's local scan rules, or nil for the
// built-in rules; it is what local scans take as Options.Rules.
func (s *checkSet) localRules() fs.FS {
	if s.source != setPack {
		return nil
	}
	return s.pack.LocalRules()
}

// How long a scan waits for the check pack release. There is always a set
// of checks to fall back on, so the wait is short; only a first fetch,
// with no pack cached yet, gets longer, since it downloads the archive.
// Variables so tests can shorten them.
var (
	packWait      = 3 * time.Second
	packFirstWait = 10 * time.Second
)

// describe is one line for people, e.g. "pack 2026.10.23-142501 (36 checks, …)".
func (s *checkSet) describe(dir string) string {
	switch s.source {
	case setPack:
		return fmt.Sprintf("check pack %s (commit %.7s, %s)", s.pack.Version, s.pack.Commit, s.pack.Created.Format("2006-01-02"))
	case setDirectory:
		return "checks from " + dir
	}
	return "built-in checks (rhythm-tuner " + version + ")"
}

// loadCheckSet picks the checks to run: --checks if given, else the newest
// valid check pack if it's newer than the built-in checks, else the
// built-in checks. Only --checks can fail; any pack problem becomes a
// warning and the built-in checks are used.
func loadCheckSet(dir string, updates, offline bool, ua string, proxy *url.URL) (*checkSet, error) {
	if dir != "" {
		all, err := engine.LoadChecks(os.DirFS(dir))
		return &checkSet{source: setDirectory, checks: all}, err
	}
	all, err := engine.LoadChecks(checks.FS)
	if err != nil {
		return nil, err
	}
	set := &checkSet{source: setBuiltIn, checks: all}
	if !updates {
		return set, nil
	}

	// Short: an unreachable release must not hold up every scan and after
	// a failure the client backs off for checkpack.Backoff.
	pc := packClient(ua, proxy, offline, false)
	wait := packFirstWait
	if pc.Cached() {
		wait = packWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if pc.Insecure {
		set.alert(insecureWarning)
	}
	p, err := pc.Get(ctx)
	switch {
	case errors.Is(err, checkpack.ErrNotCached), errors.Is(err, checkpack.ErrNoTrustedKeys):
		// Offline and nothing cached, or a build without a signing key
		// (a fork or a dev build): expected, not worth a warning.
		return set, nil
	case errors.Is(err, checkpack.ErrUnreachable):
		set.alert("check pack host unreachable, using built-in checks")
		return set, nil
	case err != nil:
		set.warnings = append(set.warnings, fmt.Sprintf("check pack: %v; using built-in checks", err))
		return set, nil
	}
	if p.Supersedes(currentBuild()) {
		set.source, set.pack, set.checks = setPack, p, p.Loaded
	}
	switch {
	case errors.Is(p.Warning, checkpack.ErrUnreachable) && set.source == setPack:
		set.alert("check pack host unreachable, using pack from " + p.Created.Format("2006-01-02"))
	case errors.Is(p.Warning, checkpack.ErrUnreachable):
		set.alert("check pack host unreachable, using built-in checks")
	case p.Warning != nil:
		set.warnings = append(set.warnings, fmt.Sprintf("%v; using %s", p.Warning, set.describe("")))
	}
	return set, nil
}

// alert records a warning that is shown even with -q.
func (s *checkSet) alert(msg string) {
	s.warnings = append(s.warnings, msg)
	s.alerts = append(s.alerts, msg)
}

// insecureWarning is shown on every run with TUNER_CHECKS_INSECURE=1, so
// the bypass can't be left on and forgotten.
const insecureWarning = "TUNER_CHECKS_INSECURE=1: check pack signatures are not verified; use it only for a pack you build yourself"

// currentBuild is this binary's build; a variable so tests can play an
// upgraded binary.
var currentBuild = checkpack.CurrentBuild

// packKeys overrides the pack signing keys compiled into checkpack, for
// tests; nil means the embedded keys.
var packKeys []ed25519.PublicKey

// packClient builds the check pack client. Like vulnClient, it goes
// through the scan's proxy. A mirror set with TUNER_CHECKS_URL still has
// to serve packs signed by a trusted key; TUNER_CHECKS_INSECURE=1 is the
// only way around that.
func packClient(ua string, proxy *url.URL, offline, force bool) *checkpack.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &checkpack.Client{
		HTTP:      &http.Client{Transport: tr, Timeout: 30 * time.Second},
		UserAgent: ua,
		BaseURL:   os.Getenv("TUNER_CHECKS_URL"), // a mirror; default this repo's checks-latest release
		CacheDir:  checkpack.DefaultCacheDir(),
		Offline:   offline,
		Force:     force,
		Tuner:     version,
		Keys:      packKeys,
		Insecure:  os.Getenv("TUNER_CHECKS_INSECURE") == "1",
		BuiltIn:   builtInIDs(),
		Build:     currentBuild(),
	}
}

// builtInIDs lists the checks compiled into this binary, which a pack must
// keep or retire. A build with uncommitted changes never uses a pack, so
// a check author's new check doesn't make every pack look short of one.
func builtInIDs() []string {
	if currentBuild().Modified {
		return nil
	}
	all, err := engine.LoadChecks(checks.FS)
	if err != nil {
		return nil
	}
	ids := make([]string, len(all))
	for i, c := range all {
		ids[i] = c.ID
	}
	return ids
}
