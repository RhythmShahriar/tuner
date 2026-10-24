// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/vulns"
)

// scanTarget scans a URL over HTTP, or a local directory in place.
func (p *scanPlan) scanTarget(ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error) {
	if !isLocalPath(target) {
		return s.Scan(ctx, target, h)
	}
	o := p.local
	o.PHP, o.Advisor, o.OSV, o.Select = p.o.php, p.engine.Advisor, p.osv, p.sel
	for _, f := range p.localFor {
		f(target, &o)
	}
	return local.Scan(ctx, target, o, h)
}

// osvClient builds the OSV.dev client for Composer packages. It caches
// next to the other vulnerability data, so rhythm tuner update --clear
// clears it too.
func osvClient(ua string, proxy *url.URL, offline bool) *local.OSV {
	cache := vulns.DefaultCacheDir()
	if cache != "" {
		cache = filepath.Join(cache, "osv")
	}
	return &local.OSV{
		HTTP:      httpClient(ua, proxy, 20*time.Second),
		UserAgent: ua,
		Base:      os.Getenv("TUNER_OSV_API"), // a mirror; default api.osv.dev
		CacheDir:  cache,
		Offline:   offline,
	}
}
