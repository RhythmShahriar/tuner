// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/tuner/matchers"
)

// WAF and bot-wall detection. A site behind a challenge answers every path
// with the same block page, so a scan of it measures the firewall, not the
// site: no leaks found, "real 404s", a high score. Tuner marks such a scan
// partial instead of reporting a clean bill of health.

// wafVendor is one firewall and the markers its block pages carry.
type wafVendor struct {
	id    string // Result.BlockedBy value
	label string // how warnings name the block
	// strong markers only ever appear on a block or challenge page.
	strong func(r *matchers.Response) bool
	// weak markers also appear on normal pages behind the firewall, so
	// they only count on a refusal (403, 429 or 503).
	weak func(r *matchers.Response) bool
}

var wafVendors = []wafVendor{
	{
		id: "cloudflare", label: "Cloudflare challenge",
		strong: func(r *matchers.Response) bool {
			return strings.EqualFold(r.Header.Get("Cf-Mitigated"), "challenge") ||
				bodyHas(r, "__cf_chl") || bodyHas(r, "<title>Just a moment...</title>")
		},
	},
	{
		id: "sucuri", label: "Sucuri firewall",
		strong: func(r *matchers.Response) bool {
			return r.Header.Get("X-Sucuri-Block") != "" || bodyHas(r, "Sucuri WebSite Firewall - Access Denied")
		},
	},
	{
		id: "imperva", label: "Imperva Incapsula",
		strong: func(r *matchers.Response) bool { return bodyHas(r, "_Incapsula_Resource") },
		// Incapsula adds X-Iinfo to every response it proxies.
		weak: func(r *matchers.Response) bool { return r.Header.Get("X-Iinfo") != "" },
	},
	{
		id: "wordfence", label: "Wordfence",
		strong: func(r *matchers.Response) bool {
			return bodyHas(r, "Your access to this site has been limited by the site owner")
		},
		// wfvt_ is Wordfence's visitor cookie, set on normal pages too.
		weak: func(r *matchers.Response) bool {
			return slices.ContainsFunc(r.Header.Values("Set-Cookie"), func(c string) bool { return strings.HasPrefix(c, "wfvt_") })
		},
	},
	{
		id: "akamai", label: "Akamai",
		strong: func(r *matchers.Response) bool {
			return strings.Contains(r.Header.Get("Server"), "AkamaiGHost") && bodyHas(r, "Reference #")
		},
	},
}

func bodyHas(r *matchers.Response, s string) bool { return bytes.Contains(r.Body, []byte(s)) }

// detectWAF returns the vendor whose block page r is, or nil.
func detectWAF(r *matchers.Response) *wafVendor {
	if r == nil {
		return nil
	}
	refused := r.Status == 403 || r.Status == 429 || r.Status == 503
	for i := range wafVendors {
		v := &wafVendors[i]
		if v.strong(r) || refused && v.weak != nil && v.weak(r) {
			return v
		}
	}
	return nil
}

// blockedWarning is the warning for a scan a firewall got in the way of.
func blockedWarning(v *wafVendor, detail string) string {
	return fmt.Sprintf("blocked by %s%s: results are partial; allow-list the scanner or pass -H/--cookie from an allowed session", v.label, detail)
}

// homeStatusWarning is the warning for a home page that answered neither
// 2xx nor 3xx, e.g. 401 or 500.
func homeStatusWarning(status int) string {
	return fmt.Sprintf("the home page answered %d: results are partial; check the URL, or pass -H/--cookie if the site needs a login", status)
}

// wafTally counts check responses that carried a block page.
type wafTally struct {
	mu      sync.Mutex
	seen    int
	blocked int
	by      map[*wafVendor]int
}

func (t *wafTally) add(v *wafVendor) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen++
	if v != nil {
		t.blocked++
		if t.by == nil {
			t.by = map[*wafVendor]int{}
		}
		t.by[v]++
	}
}

// mostlyBlocked returns the commonest vendor when more than half of the
// check responses were block pages, or nil.
func (t *wafTally) mostlyBlocked() (v *wafVendor, blocked, seen int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.blocked*2 <= t.seen {
		return nil, t.blocked, t.seen
	}
	for i := range wafVendors {
		if c := &wafVendors[i]; v == nil || t.by[c] > t.by[v] {
			v = c
		}
	}
	return v, t.blocked, t.seen
}
