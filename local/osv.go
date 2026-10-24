// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import "github.com/RhythmShahriar/tuner/vulns/osv"

// The OSV.dev client and its types live in vulns/osv, where remote scans
// use them too; these names keep local's API unchanged.
const (
	DefaultOSVBase = osv.DefaultBase
	// OSVSource credits the data in reports.
	OSVSource = osv.Source
)

type (
	// OSV queries OSV.dev for known vulnerabilities in Composer packages.
	OSV = osv.Client
	// Package is a Composer package at an installed version.
	Package = osv.Package
	// OSVVuln is the part of an OSV record Tuner uses.
	OSVVuln = osv.Vuln
	// OSVResult is what one OSV.Check found.
	OSVResult = osv.Result
)
