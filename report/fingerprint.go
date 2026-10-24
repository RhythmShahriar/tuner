// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// fingerprintPrefix versions the fingerprint scheme, so a later change to
// what goes into the hash can't be mistaken for a new finding.
const fingerprintPrefix = "v1:"

// Fingerprint returns a stable key for a finding: the same check at the
// same place gets the same key on every run, whatever host name served it
// (staging and production share one) and wherever a local copy lives.
//
// It is "v1:" and the first 32 hex digits of SHA-256 over the check ID, a
// NUL byte and the location. The location of a local finding is its path
// relative to root, the folder the scan started from; with root "" the
// finding's own Target is used, which local scans set to that folder. The
// location of a remote finding is its URL path, without scheme, host,
// user info or query.
func Fingerprint(f engine.Finding, root string) string {
	sum := sha256.Sum256([]byte(f.ID + "\x00" + location(f, root)))
	return fingerprintPrefix + hex.EncodeToString(sum[:])[:32]
}

func location(f engine.Finding, root string) string {
	u, err := url.Parse(f.URL)
	if err != nil || f.URL == "" {
		return cleanPath(f.Path)
	}
	if u.Scheme != "file" {
		return cleanPath(u.Path)
	}
	if root == "" {
		root = f.Target
	}
	// Compare without the leading slash so Windows paths match too:
	// file:///C:/site/wp-config.php against a root of C:\site. Backslashes
	// are swapped by hand because a report from Windows may be read here.
	p := strings.TrimPrefix(u.Path, "/")
	r := strings.TrimSuffix(strings.TrimPrefix(strings.ReplaceAll(root, "\\", "/"), "/"), "/")
	if r != "" && (p == r || strings.HasPrefix(p, r+"/")) {
		return cleanPath(strings.TrimPrefix(p, r))
	}
	return cleanPath(f.Path)
}

// cleanPath gives every location one spelling: forward slashes and a
// leading slash, "/" for the root itself.
func cleanPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// Stamp gives every finding in res its stable fingerprint, stored in
// Finding.Fingerprint. root is the folder a local scan started from; ""
// uses each finding's own Target, which local scans set to that folder.
// Call it before a baseline filters res.
func Stamp(res *engine.Result, root string) {
	if res == nil {
		return
	}
	for i := range res.Findings {
		res.Findings[i].Fingerprint = Fingerprint(res.Findings[i], root)
	}
}

// TargetKey pairs a target across scans: a URL by host and path without
// scheme or trailing slash, a folder as written. Batch baselines, diffs
// and the HTML report's NEW markers all pair sites this way.
func TargetKey(t string) string {
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		return strings.ToLower(u.Host) + strings.TrimSuffix(u.Path, "/")
	}
	return strings.TrimSuffix(t, "/")
}
