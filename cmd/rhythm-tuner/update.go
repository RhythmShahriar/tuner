// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/checkpack"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/osv"
)

// updateUsage is update --help, laid out for the name Tuner was started
// as like checksUsage.
func updateUsage() string {
	name := cmdName()
	return "Usage:\n" + formatUsage([]usageLine{
		{cmd: name + " update", summary: "refresh everything cached"},
		{cmd: name + " update --prefetch <target>...", summary: "cache what scans of these sites need"},
		{cmd: name + " update --clear", summary: "delete the cached check pack and data"},
	}) + named(updateHelp)
}

const updateHelp = `
Refreshes the check pack and the cached vulnerability data now. Scans also
refresh both on their own once they are a day old.

Flags:
      --prefetch <dir|url>  fingerprint a site or a site folder (no checks run)
                            and cache its vulnerability data, so a later
                            --offline scan has it; more targets may follow
      --php <binary>        local targets: php to ask for the PHP version
                            (default: php on PATH)
      --clear               delete the cached check pack and vulnerability data

` + wordfenceHelp + `
Examples:
  rhythm tuner update --prefetch ./site
  rhythm tuner update --prefetch example.com staging.example.com
`

// cmdUpdate refreshes the check pack and cached vulnerability data now.
// Scans also refresh both automatically once they are a day old.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	clear := flags.Bool("clear", false, "")
	var prefetch cli.RepeatFlag
	flags.Var(&prefetch, "prefetch", "")
	php := flags.String("php", "", "")
	pos, err := cli.ParseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, updateUsage())
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %s\nrun 'rhythm tuner update --help' for its flags\n", updateFlagError(err, flags))
		return exitUsage
	}
	targets := append([]string(prefetch), pos...)
	switch {
	case len(pos) > 0 && len(prefetch) == 0:
		fmt.Fprintf(stderr, "rhythm tuner: update takes no targets; to cache data for %s, run: rhythm tuner update --prefetch %s\n", pos[0], pos[0])
		return exitUsage
	case *clear && len(targets) > 0:
		fmt.Fprintln(stderr, "rhythm tuner: pick one of --clear and --prefetch")
		return exitUsage
	}
	for _, t := range targets {
		if err := checkPrefetchTarget(t); err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitUsage
		}
	}

	ua := fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	c := vulnClient(ua, nil, false)
	c.Wordfence = wordfenceClient(ua, nil, false)
	pc := packClient(ua, nil, false, true)
	if *clear {
		for _, dir := range []string{pc.CacheDir, c.CacheDir} {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintln(stderr, "rhythm tuner:", err)
				return exitError
			}
			fmt.Fprintln(stdout, "Cleared", dir)
		}
		return exitOK
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	packOK := updatePack(ctx, pc, stdout, stderr)
	if len(targets) > 0 {
		return prefetchTargets(ctx, targets, *php, c, packOK, ua, stdout, stderr)
	}
	ok, failed, err := c.Refresh(ctx)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	// Composer advisories from OSV.dev, cached under the same folder.
	oc := osvClient(ua, nil, false)
	osvOK, osvFailed, err := oc.Refresh(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	if ok+failed+osvOK+osvFailed == 0 {
		fmt.Fprintln(stdout, "Nothing cached yet. Vulnerability data is fetched during scans and refreshed daily.")
		fmt.Fprintln(stdout, named("To cache it ahead of an --offline scan, run: rhythm tuner update --prefetch <dir|url>"))
	} else {
		sources := []string{vulns.Source}
		if c.Wordfence != nil {
			sources = append(sources, c.Wordfence.Source())
		}
		if ok+failed > 0 {
			fmt.Fprintf(stdout, "Refreshed %d vulnerability records%s\n", ok, keptNote(failed))
		}
		if osvOK+osvFailed > 0 {
			fmt.Fprintf(stdout, "Refreshed %d Composer advisory records%s\n", osvOK, keptNote(osvFailed))
			sources = append(sources, osv.Source)
		}
		fmt.Fprintf(stdout, "Data: %s\nCache: %s\n", strings.Join(sources, "; "), c.CacheDir)
	}
	failed += osvFailed
	if failed > 0 || !packOK {
		return exitError
	}
	return exitOK
}

// updateFlagError rewords the flag package's parse errors in the style of
// scan's: the flag with its two dashes plus the closest known flag.
func updateFlagError(err error, fs *flag.FlagSet) string {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		name = strings.TrimLeft(name, "-")
		if name == "prefetch" {
			return "--prefetch needs a site or a folder, e.g. rhythm tuner update --prefetch ./site"
		}
		return fmt.Sprintf("--%s needs a value", name)
	}
	name, ok := strings.CutPrefix(msg, "flag provided but not defined: -")
	if !ok {
		return msg
	}
	name = strings.TrimLeft(name, "-")
	if name == "offline" {
		// The usual slip: scans take --offline; update exists to go online.
		return "unknown flag --offline; update always fetches (scan --offline uses what it cached)"
	}
	var known []string
	fs.VisitAll(func(f *flag.Flag) { known = append(known, f.Name) })
	if s := closestFlag(name, known); s != "" {
		return fmt.Sprintf("unknown flag --%s; did you mean --%s?", name, s)
	}
	return "unknown flag --" + name
}

// closestFlag returns the known flag nearest to name, or "" when none is
// close enough to be what the user meant.
func closestFlag(name string, known []string) string {
	best, bestD := "", 3 // more than two edits away is a different word
	for _, k := range known {
		d := editDistance(name, k)
		if strings.HasPrefix(k, name) && len(name) >= 3 {
			d = min(d, 1)
		}
		if d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

// checkPrefetchTarget validates a --prefetch target the way scan does.
// It runs before anything is fetched, so a typo costs no requests. A
// target starting with "-" is a mistyped flag (--prefetch=-x, or a flag
// after --prefetch): no hostname starts with a hyphen.
func checkPrefetchTarget(t string) error {
	if strings.HasPrefix(t, "-") {
		return fmt.Errorf("%q is not a valid URL or hostname; --prefetch needs a site or a folder, e.g. rhythm tuner update --prefetch ./site", t)
	}
	if isLocalPath(t) {
		_, err := local.Root(t)
		return err
	}
	_, _, err := engine.ParseTarget(t)
	return err
}

// prefetchTargets fingerprints each target without running checks and
// caches the vulnerability data a scan of it needs: WPVulnerability,
// wordpress.org and php.net through c, plus OSV.dev for a local
// composer.lock. Lookups still fresh in the cache are not repeated.
func prefetchTargets(ctx context.Context, targets []string, php string, c *vulns.Client, packOK bool, ua string, stdout, stderr io.Writer) int {
	oc := osvClient(ua, nil, false)
	sources := []string{vulns.Source}
	if c.Wordfence != nil {
		sources = append(sources, c.Wordfence.Source())
	}
	ok := packOK
	for _, t := range targets {
		var res *engine.Result
		var err error
		localTarget := isLocalPath(t)
		if localTarget {
			// No checks are wanted, only the fingerprint: selecting advisor
			// IDs drops the local checks' findings. composer.lock is
			// matched below, so the status can be told apart.
			res, err = local.Scan(ctx, t, local.Options{PHP: php, Select: engine.Selector{IDs: []string{"vuln-*"}}}, engine.Hooks{})
		} else {
			res, err = engine.New(nil, engine.Options{
				UserAgent: ua, Rate: 5, Timeout: 10 * time.Second, Concurrency: 10, Retries: 2,
			}).Scan(ctx, t, engine.Hooks{})
		}
		if ctx.Err() != nil {
			return exitCanceled
		}
		// The target, the fingerprint and the warnings can hold names from
		// the site (file names, plugin versions): never raw escapes.
		shown := report.SafeText(shownTarget(t))
		if err != nil {
			fmt.Fprintf(stderr, "rhythm tuner: %s: %s\n", shown, report.SafeText(err.Error()))
			ok = false
			continue
		}
		var pkgs []osv.Package
		if localTarget {
			// res.Target is the site folder's absolute path.
			if b, err := os.ReadFile(filepath.Join(res.Target, "composer.lock")); err == nil { //nolint:gosec // the user's own site folder
				pkgs, _ = osv.ParseLock(b) // a broken lock is already a scan warning
			}
		}
		warnings, status := c.Prefetch(ctx, res.Fingerprint)
		what := describeFingerprint(res.Fingerprint, len(pkgs))
		if len(pkgs) > 0 {
			r := oc.Check(ctx, pkgs)
			if w := oc.Warning(r); w != "" {
				warnings = append(warnings, w)
			}
			if r.Status() != vulns.StatusOK {
				status = r.Status()
			}
			if !slices.Contains(sources, osv.Source) {
				sources = append(sources, osv.Source)
			}
		}
		fmt.Fprintf(stdout, "Prefetched %s: %s\n", shown, report.SafeText(what))
		for _, w := range append(res.Warnings, warnings...) {
			fmt.Fprintf(stderr, "rhythm tuner: %s: %s\n", shown, report.SafeText(w))
		}
		// Local warnings (no php on PATH, say) don't fail a prefetch;
		// missing vulnerability data does.
		ok = ok && status == vulns.StatusOK
	}
	fmt.Fprintf(stdout, "Data: %s\nCache: %s\n", strings.Join(sources, "; "), c.CacheDir)
	if !ok {
		return exitError
	}
	return exitOK
}

// describeFingerprint lists what a prefetch looked up: "WordPress 6.4.1,
// 2 plugins, 1 theme, PHP 8.3.6, nginx/1.24.0, 12 Composer packages".
func describeFingerprint(fp fingerprint.Result, composer int) string {
	var parts []string
	if fp.Has("wordpress") && fp.WordPress != "" {
		parts = append(parts, "WordPress "+fp.WordPress)
	}
	counts := map[string]int{}
	for _, c := range fp.Components {
		counts[c.Type]++
	}
	for _, kind := range []string{"plugin", "theme"} {
		switch n := counts[kind]; n {
		case 0:
		case 1:
			parts = append(parts, "1 "+kind)
		default:
			parts = append(parts, fmt.Sprintf("%d %ss", n, kind))
		}
	}
	switch {
	case fp.PHP != "":
		parts = append(parts, "PHP "+fp.PHP)
	case fp.Has("php"):
		parts = append(parts, "PHP (version hidden)")
	}
	if s := strings.ToLower(fp.Server); strings.HasPrefix(s, "nginx/") || strings.HasPrefix(s, "apache/") {
		parts = append(parts, strings.Fields(fp.Server)[0])
	}
	switch composer {
	case 0:
	case 1:
		parts = append(parts, "1 Composer package")
	default:
		parts = append(parts, fmt.Sprintf("%d Composer packages", composer))
	}
	if len(parts) == 0 {
		return "nothing with known-vulnerability data found"
	}
	return strings.Join(parts, ", ")
}

// keptNote says how many records failed to refresh, if any.
func keptNote(failed int) string {
	if failed == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d failed; cached copies kept)", failed)
}

// updatePack refreshes the check pack and says which checks scans will use.
// A build that trusts no signing key (a fork or a dev build) never uses a
// pack, which is not a failure: its scans use the built-in checks.
func updatePack(ctx context.Context, pc *checkpack.Client, stdout, stderr io.Writer) bool {
	p, err := pc.Get(ctx)
	if errors.Is(err, checkpack.ErrNoTrustedKeys) {
		fmt.Fprintf(stdout, "Checks: built-in (rhythm-tuner %s)\n", version)
		return true
	}
	if err != nil {
		fmt.Fprintf(stderr, "rhythm tuner: check pack: %v\n", err)
		fmt.Fprintf(stdout, "Checks: built-in (rhythm-tuner %s)\n", version)
		return false
	}
	if p.Warning != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", p.Warning)
	}
	if p.Supersedes(checkpack.CurrentBuild()) {
		fmt.Fprintf(stdout, "Checks: pack %s, %d checks (commit %.7s)\n", p.Version, p.Checks, p.Commit)
	} else {
		fmt.Fprintf(stdout, "Checks: built-in (rhythm-tuner %s); they're as new as pack %s\n", version, p.Version)
	}
	return p.Warning == nil
}
