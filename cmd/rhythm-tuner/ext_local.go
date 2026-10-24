// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/vulns"
)

// localExtension adds the local-scan flags owned by the local-server
// lane: --integrity. It follows the scan-extension seam (Help, Flags,
// then a planning step that edits the local options), so registering it
// is one init() call once that seam exists.
type localExtension struct {
	integrity bool
}

// Help is the section printed under scan help.
func (e *localExtension) Help() string {
	return `Local integrity:
      --integrity          compare WordPress core and wordpress.org plugin files
                           with the checksums WordPress.org publishes (fetched
                           once per release and cached; --offline uses the
                           cache). TUNER_WPORG_API and TUNER_WPDL_API point it
                           at mirrors.
`
}

// Flags registers the extension's flags.
func (e *localExtension) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&e.integrity, "integrity", false, "")
}

// configure applies the flags to a local scan's options.
func (e *localExtension) configure(o *local.Options, ua string, proxy *url.URL, offline bool) {
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
