// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/url"
	"os"

	"github.com/RhythmShahriar/tuner/vulns"
)

// wordfenceHelp explains the optional second vulnerability source.
const wordfenceHelp = `With TUNER_WORDFENCE_KEY set to a free Wordfence Intelligence API key,
plugins, themes and core are also matched against the Wordfence
Intelligence feed (Copyright Defiant Inc.), merged with WPVulnerability by
CVE. The feed is cached with the other data. rhythm tuner update
refreshes it; a scan downloads it (which can take a few minutes) only
when no copy under a week old is cached. TUNER_WORDFENCE_API points
Tuner at a mirror.
`

// wordfenceClient builds the Wordfence Intelligence client when
// TUNER_WORDFENCE_KEY is set, else nil: the feed is opt-in. It goes
// through the same proxy as the scan and caches next to the other
// vulnerability data, so rhythm tuner update --clear clears it too.
func wordfenceClient(ua string, proxy *url.URL, offline bool) *vulns.Wordfence {
	key := os.Getenv("TUNER_WORDFENCE_KEY")
	if key == "" {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &vulns.Wordfence{
		HTTP:      &http.Client{Transport: tr},
		UserAgent: ua,
		Key:       key,
		Base:      os.Getenv("TUNER_WORDFENCE_API"), // default www.wordfence.com/api/intelligence/v3
		CacheDir:  vulns.DefaultCacheDir(),
		Offline:   offline,
	}
}
