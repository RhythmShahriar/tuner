package main

import (
	"context"
	"net/http"
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
	return local.Scan(ctx, target, local.Options{
		PHP:     p.o.php,
		Advisor: p.engine.Advisor,
		OSV:     p.osv,
		Select:  p.sel,
	}, h)
}

// osvClient builds the OSV.dev client for Composer packages. It caches
// next to the other vulnerability data, so rhythm tuner update --clear
// clears it too.
func osvClient(ua string, proxy *url.URL, offline bool) *local.OSV {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	cache := vulns.DefaultCacheDir()
	if cache != "" {
		cache = filepath.Join(cache, "osv")
	}
	return &local.OSV{
		HTTP:      &http.Client{Transport: tr, Timeout: 20 * time.Second},
		UserAgent: ua,
		Base:      os.Getenv("TUNER_OSV_API"), // a mirror; default api.osv.dev
		CacheDir:  cache,
		Offline:   offline,
	}
}
