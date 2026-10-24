// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/osv"
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
		"Error pages show stack traces, source code and environment values including secrets.",
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

// loadLock reads the packages pinned in composer.lock, if there is one.
func (s *scan) loadLock() {
	path := filepath.Join(s.root, "composer.lock")
	b, err := readHead(path, 16<<20)
	if err != nil {
		return
	}
	if s.pkgs, err = osv.ParseLock(b); err != nil {
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
	if w := s.opts.OSV.Warning(res); w != "" {
		s.warn("%s", w)
	}

	var out []engine.Finding
	for _, p := range pkgs {
		if vs := res.Vulns[p]; len(vs) > 0 {
			out = append(out, s.packageFinding(path, p, vs))
		}
	}
	return out, res.Status()
}

// packageFinding lists every advisory affecting one package, like the
// advisor's vuln-plugin-* findings, at composer.lock.
func (s *scan) packageFinding(lock string, p Package, vs []OSVVuln) engine.Finding {
	f := osv.Finding(p, vs)
	at := s.finding(f.ID, f.Severity, lock, f.Title, nil, "", "")
	f.URL, f.Path = at.URL, at.Path
	return f
}
