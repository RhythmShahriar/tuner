package main

import (
	"context"
	"errors"
	"fmt"
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
	pack     *checkpack.Manifest // when source is setPack
	checks   []*engine.Check
	warnings []string // pack trouble; the run goes on with what's here
}

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

	// Short: an unreachable release must not hold up every scan.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := packClient(ua, proxy, offline, false).Get(ctx)
	switch {
	case errors.Is(err, checkpack.ErrNotCached):
		return set, nil // offline and nothing cached: expected, not worth a warning
	case err != nil:
		set.warnings = append(set.warnings, fmt.Sprintf("check pack: %v; using built-in checks", err))
		return set, nil
	}
	if p.Supersedes(checkpack.CurrentBuild()) {
		set.source, set.pack, set.checks = setPack, &p.Manifest, p.Loaded
	}
	if p.Warning != nil {
		set.warnings = append(set.warnings, fmt.Sprintf("%v; using %s", p.Warning, set.describe("")))
	}
	return set, nil
}

// packClient builds the check pack client. Like vulnClient, it goes
// through the scan's proxy.
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
	}
}
