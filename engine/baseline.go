// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"context"
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

// isBaseline reports whether r, fetched from p, looks like the server's
// response to a path that does not exist.
func (ss *session) isBaseline(ctx context.Context, p string, r *matchers.Response) bool {
	probe := probePath(p, ss.token)
	b, err := ss.get(ctx, "GET", probe)
	if err != nil {
		return false
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

// similar compares two responses, ignoring the requested path echoed in the
// body and allowing 5% size drift for pages with nonces or timestamps.
func similar(a *matchers.Response, ap string, b *matchers.Response, bp string) bool {
	if a.Status != b.Status {
		return false
	}
	x := bytes.ReplaceAll(a.Body, []byte(ap), nil)
	y := bytes.ReplaceAll(b.Body, []byte(bp), nil)
	if bytes.Equal(x, y) {
		return true
	}
	d := len(x) - len(y)
	if d < 0 {
		d = -d
	}
	return d <= max(len(x), len(y))/20
}
