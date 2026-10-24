// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path"
	"strings"

	"github.com/RhythmShahriar/tuner/matchers"
)

// Soft-404 baselining: before trusting a hit on /.env, Tuner requests a
// random path of the same shape (same directory, same extension, dotfile
// or not) and compares. Servers that answer 200 to everything then stop
// producing false findings.

// probePath returns a random path shaped like p.
func probePath(p, token string) string {
	dir, file := path.Split(p)
	if file == "" {
		return dir + token + "/"
	}
	prefix, ext := "", path.Ext(file)
	if strings.HasPrefix(file, ".") {
		prefix = "."
		if ext == file {
			ext = ""
		}
	}
	return dir + prefix + token + ext
}

// isBaseline reports whether r, fetched from p for check c, looks like the
// server's response to a path that does not exist.
//
// A check that tests the body (a regex, words or magic bytes) has already
// proved what r holds, so its hit only counts as noise when the probe
// passes the same tests: a catch-all that serves env-like lines for every
// path. Comparing sizes instead would drop a real 78-byte .env next to an
// 80-byte "Not found" page. Status- and header-only checks have no such
// proof and fall back to comparing the two pages.
func (ss *session) isBaseline(ctx context.Context, c *Check, p string, r *matchers.Response) bool {
	probe := probePath(p, ss.token)
	b, err := ss.get(ctx, "GET", probe)
	if err != nil {
		return false
	}
	if c.Match.Content() {
		ok, _ := c.Match.Match(b, func() bool { return false })
		return ok
	}
	return similar(r, p, b, probe)
}

// soft404 reports whether the server answers 200 for a missing page.
func (ss *session) soft404(ctx context.Context) bool {
	b, err := ss.get(ctx, "GET", probePath("/x", ss.token))
	return err == nil && b.Status == 200
}

// baselineBlocked reports whether the soft-404 probe got a block page.
func (ss *session) baselineBlocked(ctx context.Context) bool {
	b, err := ss.get(ctx, "GET", probePath("/x", ss.token))
	return err == nil && detectWAF(b) != nil
}

// Bodies cut at maxBody all have the same length, so similar compares this
// much of their start instead.
const headSize = 64 << 10

// similar compares two responses, ignoring the requested path echoed in the
// body and allowing 5% size drift for pages with nonces or timestamps.
// When either body was cut at maxBody the sizes say nothing, so the first
// 64 KiB must hash the same instead.
func similar(a *matchers.Response, ap string, b *matchers.Response, bp string) bool {
	if a.Status != b.Status {
		return false
	}
	x := bytes.ReplaceAll(a.Body, []byte(ap), nil)
	y := bytes.ReplaceAll(b.Body, []byte(bp), nil)
	if bytes.Equal(x, y) {
		return true
	}
	if len(a.Body) >= maxBody || len(b.Body) >= maxBody {
		return sha256.Sum256(x[:min(len(x), headSize)]) == sha256.Sum256(y[:min(len(y), headSize)])
	}
	d := len(x) - len(y)
	if d < 0 {
		d = -d
	}
	return d <= max(len(x), len(y))/20
}
