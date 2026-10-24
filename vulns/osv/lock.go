// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"bytes"
	"encoding/json"
	"strings"
)

// MaxRemotePackages is the most packages a remote scan takes from a lock
// file a site exposes. The file comes from the site, so it decides how
// many lookups a scan would make; a real application rarely pins more
// than a few hundred.
const MaxRemotePackages = 500

// ParseLock lists the packages pinned in a composer.lock. It also reads
// vendor/composer/installed.json, which is a bare array of packages in
// Composer 1 and an object with "packages" in Composer 2. Each package is
// listed once, lowercased, with a leading "v" dropped from its version;
// branches (dev-main) have no release to match and are left out.
func ParseLock(b []byte) ([]Package, error) {
	var lock struct {
		Packages    []Package `json:"packages"`
		PackagesDev []Package `json:"packages-dev"`
	}
	if b = bytes.TrimSpace(b); len(b) > 0 && b[0] == '[' {
		if err := json.Unmarshal(b, &lock.Packages); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]bool{}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		p.Name = strings.ToLower(p.Name)
		p.Version = strings.TrimPrefix(p.Version, "v")
		if p.Name == "" || p.Version == "" || strings.HasPrefix(p.Version, "dev-") || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	return out, nil
}
