// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
)

// ComposerAdvisor matches the packages in a composer.lock (or
// vendor/composer/installed.json) that a site exposes, as found by the
// leak-composer-manifest check, against OSV.dev. The leak finding says
// the file is public; these findings say which of its packages have
// known vulnerabilities. It implements engine.ResponseAdvisor.
type ComposerAdvisor struct {
	Client *Client // the data source; required
}

// Rules describes the findings ComposerAdvisor and local scans emit.
func Rules() []vulns.Rule {
	return []vulns.Rule{
		vulns.NewRule(FindingPrefix, true, engine.High, "Composer package with known vulnerabilities", "vuln", "composer"),
	}
}

// AdviseResponse implements engine.ResponseAdvisor. It looks only at
// leak-composer-* findings for composer.lock or installed.json; a file it
// can't read (truncated or not JSON) gives a warning, not a finding.
func (a *ComposerAdvisor) AdviseResponse(ctx context.Context, f engine.Finding, body []byte) ([]engine.Finding, []string) {
	file := path.Base(f.Path)
	if !strings.HasPrefix(f.ID, "leak-composer") || file != "composer.lock" && file != "installed.json" {
		return nil, nil
	}
	pkgs, err := ParseLock(body)
	if err != nil {
		return nil, []string{fmt.Sprintf("couldn't read the exposed %s, so its packages weren't matched: %v", f.Path, err)}
	}
	if len(pkgs) == 0 {
		return nil, nil
	}
	var warnings []string
	if len(pkgs) > MaxRemotePackages {
		warnings = append(warnings, fmt.Sprintf("the exposed %s lists %d packages; only the first %d were matched", f.Path, len(pkgs), MaxRemotePackages))
		pkgs = pkgs[:MaxRemotePackages]
	}
	res := a.Client.Check(ctx, pkgs)
	if w := a.Client.Warning(res); w != "" {
		warnings = append(warnings, w)
	}
	var out []engine.Finding
	for _, p := range pkgs {
		vs := res.Vulns[p]
		if len(vs) == 0 {
			continue
		}
		v := Finding(p, vs)
		v.Title += " (from exposed " + file + ")"
		v.URL, v.Path = f.URL, f.Path
		v.Evidence.Status = f.Evidence.Status
		v.Evidence.Matched = append(v.Evidence.Matched, "version from "+f.Path)
		out = append(out, v)
	}
	return out, warnings
}
