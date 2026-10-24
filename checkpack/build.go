// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"runtime/debug"
	"time"
)

// BuildInfo identifies the checks compiled into a binary by the commit it
// was built from. Packs carry their commit's time too, so the two can be
// ordered without a separate version number to keep in sync.
type BuildInfo struct {
	Time     time.Time // commit time; zero when unknown (go install from the module proxy)
	Modified bool      // built from a working tree with uncommitted changes
}

// CurrentBuild reads the VCS stamp Go embeds in binaries built from a git
// checkout, as release builds are.
func CurrentBuild() BuildInfo {
	var b BuildInfo
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.time":
			b.Time, _ = time.Parse(time.RFC3339, s.Value)
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	return b
}

// Supersedes reports whether p should replace a binary's built-in checks.
// A pack built from a later commit wins. A binary with uncommitted changes
// keeps its own checks, so a check author always runs what they're
// editing. When the build time is unknown, a compatible pack wins: the
// pack is rebuilt from master on every checks change and releases are
// cut from master.
func (p *Pack) Supersedes(b BuildInfo) bool {
	return p.supersedes(b)
}

func (m Manifest) supersedes(b BuildInfo) bool {
	switch {
	case b.Modified:
		return false
	case b.Time.IsZero():
		return true
	}
	return m.Created.After(b.Time)
}
