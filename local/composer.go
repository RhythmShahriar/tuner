// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
)

// isLaravel reports whether root is a Laravel project: an artisan script
// and a public/ document root.
func isLaravel(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "artisan")); err != nil {
		return false
	}
	fi, err := os.Stat(filepath.Join(root, "public"))
	return err == nil && fi.IsDir()
}

// laravelEnv reviews a Laravel project's .env, which lives outside the
// document root and is expected there.
func (s *scan) laravelEnv() []engine.Finding {
	if s.web == s.root {
		return nil
	}
	path := filepath.Join(s.root, ".env")
	b, err := readHead(path, maxRead)
	if err != nil {
		return nil
	}
	s.checks++
	env := parseEnv(b)
	if on := strings.ToLower(env["APP_DEBUG"]); on != "true" && on != "1" {
		return nil
	}
	ev := []string{"APP_DEBUG=true"}
	if e := env["APP_ENV"]; e != "" {
		ev = append(ev, "APP_ENV="+e)
	}
	return []engine.Finding{s.finding("local-laravel-debug", engine.Medium, path, "Laravel debug mode is on", ev,
		"Error pages show stack traces, source code, and environment values including secrets.",
		"Set APP_DEBUG=false in .env on production servers, then run: php artisan config:cache",
		"laravel", "config", "disclosure")}
}

// parseEnv reads KEY=value lines.
func parseEnv(b []byte) map[string]string {
	env := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		env[strings.TrimSpace(k)] = strings.Trim(v, `"'`)
	}
	return env
}

// lockPackages lists the packages pinned in composer.lock.
func lockPackages(b []byte) ([]Package, error) {
	var lock struct {
		Packages    []Package `json:"packages"`
		PackagesDev []Package `json:"packages-dev"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]bool{}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		p.Name = strings.ToLower(p.Name)
		p.Version = strings.TrimPrefix(p.Version, "v")
		if p.Name == "" || p.Version == "" || strings.HasPrefix(p.Version, "dev-") || seen[p.Name] {
			continue // branches have no release to match
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	return out, nil
}

// loadLock reads the packages pinned in composer.lock, if there is one.
func (s *scan) loadLock() {
	path := filepath.Join(s.root, "composer.lock")
	b, err := readHead(path, 16<<20)
	if err != nil {
		return
	}
	if s.pkgs, err = lockPackages(b); err != nil {
		s.warn("couldn't read composer.lock: %v", err)
	}
}

// composer matches composer.lock against OSV.dev.
func (s *scan) composer(ctx context.Context) []engine.Finding {
	findings, _ := s.composerStatus(ctx)
	return findings
}

// composerStatus is composer plus the OSV data status for
// engine.Result.VulnData: vulns.StatusOff without an OSV client, "" when
// there is no composer.lock to check, else what OSVResult.Status says.
func (s *scan) composerStatus(ctx context.Context) ([]engine.Finding, string) {
	path := filepath.Join(s.root, "composer.lock")
	pkgs := s.pkgs
	if s.opts.OSV == nil {
		return nil, vulns.StatusOff
	}
	if len(pkgs) == 0 {
		return nil, ""
	}
	s.checks++
	res := s.opts.OSV.Check(ctx, pkgs)
	found, failed, err := res.Vulns, res.Failed, res.Err
	switch {
	case res.Unreachable && (failed > 0 || res.Stale > 0):
		s.warn("%s", vulns.UnreachableWarning("Composer ", failed, res.Total, res.Stale, res.Oldest, time.Now()))
	case failed > 0:
		if s.opts.OSV.Offline {
			s.warn("vulnerability data not cached for %d Composer packages; run once online to cache it", failed)
		} else {
			s.warn("couldn't fetch vulnerability data for %d Composer packages (%v)", failed, err)
		}
	}

	var out []engine.Finding
	for _, p := range pkgs {
		if vs := found[p]; len(vs) > 0 {
			out = append(out, s.packageFinding(path, p, vs))
		}
	}
	return out, res.Status()
}

// packageFinding lists every advisory affecting one package, like the
// advisor's vuln-plugin-* findings.
func (s *scan) packageFinding(lock string, p Package, vs []OSVVuln) engine.Finding {
	worst := engine.Info
	fixedIn := ""
	unfixed := 0
	var advisories []engine.Advisory
	for _, v := range vs {
		sev := osvSeverity(v.DatabaseSpecific.Severity)
		if r := cmp.Or(sev, engine.Medium); r.Rank() < worst.Rank() {
			worst = r
		}
		fx := v.fixedIn(p)
		if fx == "" {
			unfixed++
		} else if fixedIn == "" || vulns.Compare(fx, fixedIn) > 0 {
			fixedIn = fx
		}
		ad := engine.Advisory{ID: v.ID, Title: cmp.Or(strings.TrimSpace(v.Summary), v.ID), Severity: sev, FixedIn: fx}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				ad.CVEs = append(ad.CVEs, a)
			}
		}
		for _, r := range v.References {
			if r.Type == "ADVISORY" || r.Type == "WEB" {
				ad.References = append(ad.References, r.URL)
			}
		}
		ad.References = append(ad.References, "https://osv.dev/vulnerability/"+v.ID)
		advisories = append(advisories, ad)
	}
	slices.SortStableFunc(advisories, func(x, y engine.Advisory) int {
		return cmp.Compare(rankOr(x.Severity), rankOr(y.Severity))
	})

	var ev []string
	for _, ad := range advisories[:min(len(advisories), 5)] {
		line := strings.ToUpper(string(cmp.Or(ad.Severity, "unrated")))
		if len(ad.CVEs) > 0 {
			line += " " + ad.CVEs[0]
		}
		line += " " + ad.Title
		if ad.FixedIn != "" {
			line += " (fixed in " + ad.FixedIn + ")"
		}
		ev = append(ev, line)
	}
	if n := len(advisories) - 5; n > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", n))
	}

	plural := "ies"
	if len(vs) == 1 {
		plural = "y"
	}
	fix := fmt.Sprintf("Update %s to %s or later: composer update %s --with-dependencies", p.Name, fixedIn, p.Name)
	switch {
	case fixedIn == "":
		fix = fmt.Sprintf("No fixed version is known. Remove or replace %s.", p.Name)
	case unfixed > 0:
		fix += fmt.Sprintf(". %d of the issues have no known fixed version.", unfixed)
	}
	tags := []string{"vuln", "composer"}
	if strings.HasPrefix(p.Name, "laravel/") {
		tags = append(tags, "laravel")
	}
	f := s.finding("vuln-composer-"+strings.ReplaceAll(p.Name, "/", "-"), worst, lock,
		fmt.Sprintf("%s %s: %d known vulnerabilit%s", p.Name, p.Version, len(vs), plural), ev,
		fmt.Sprintf("%d published vulnerabilities affect %s %s; the worst is rated %s.", len(vs), p.Name, p.Version, worst),
		fix)
	f.Tags = tags
	f.Evidence.Request = "version match"
	f.Advisories = advisories
	f.Source = OSVSource
	if len(advisories) > 0 {
		f.References = advisories[0].References
	}
	return f
}

// fixedIn returns the lowest fixed version above p's version, for p.
func (v OSVVuln) fixedIn(p Package) string {
	best := ""
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Name, p.Name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				fx := strings.TrimPrefix(e.Fixed, "v")
				if fx != "" && vulns.Compare(fx, p.Version) > 0 && (best == "" || vulns.Compare(fx, best) < 0) {
					best = fx
				}
			}
		}
	}
	return best
}

func osvSeverity(s string) engine.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return engine.Critical
	case "HIGH":
		return engine.High
	case "MODERATE", "MEDIUM":
		return engine.Medium
	case "LOW":
		return engine.Low
	}
	return ""
}

func rankOr(s engine.Severity) int {
	if r := s.Rank(); r >= 0 {
		return r
	}
	return engine.Medium.Rank()
}
