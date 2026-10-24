// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"slices"
	"strings"
	"time"
)

// Score is how one tool did against the ground truth on one site.
type Score struct {
	Tool string
	Site string
	// NotRun or Error explain a missing score.
	NotRun bool
	Error  string

	// Plugins the tool reported, deduplicated and lower-cased.
	Reported []string
	// Found are reported plugins that are really installed; Missed are
	// installed plugins it didn't report; FalsePos are reported plugins
	// that aren't installed.
	Found     []string
	Missed    []string
	FalsePos  []string
	VulnFound []string // installed vulnerable plugins it reported

	// FilesFound and FilesMissed are the exposed files it reported, scored
	// only for tools that look for files (Tuner).
	ScoresFiles bool
	FilesFound  []string
	FilesMissed []string

	// Blocked is set when the tool reported the site as WAF-blocked, which
	// is the right answer for the waf site.
	Blocked bool

	Requests int64
	Duration time.Duration
}

// scorePlugins compares what a tool reported with the manifest.
func scorePlugins(m *Manifest, reported []string) (found, missed, falsePos, vulnFound []string) {
	seen := map[string]bool{}
	var clean []string
	for _, s := range reported {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	installed := map[string]Plugin{}
	for _, p := range m.Plugins {
		installed[p.Slug] = p
	}
	for _, s := range clean {
		if p, ok := installed[s]; ok {
			found = append(found, s)
			if p.Vulnerable {
				vulnFound = append(vulnFound, s)
			}
		} else {
			falsePos = append(falsePos, s)
		}
	}
	for _, p := range m.Plugins {
		if !slices.Contains(found, p.Slug) {
			missed = append(missed, p.Slug)
		}
	}
	slices.Sort(found)
	slices.Sort(missed)
	slices.Sort(falsePos)
	slices.Sort(vulnFound)
	return found, missed, falsePos, vulnFound
}

// scoreFiles compares reported file paths against a site's exposed files.
func scoreFiles(site Site, paths []string) (found, missed []string) {
	has := func(p string) bool {
		return slices.ContainsFunc(paths, func(r string) bool { return strings.EqualFold(r, p) })
	}
	for _, e := range site.Exposed {
		if has(e.Path) {
			found = append(found, e.Path)
		} else {
			missed = append(missed, e.Path)
		}
	}
	slices.Sort(found)
	slices.Sort(missed)
	return found, missed
}

// score builds a Score from a tool's raw report on a site.
func score(m *Manifest, tool, siteName string, site Site, rep *Report) Score {
	s := Score{Tool: tool, Site: siteName}
	if rep == nil {
		s.NotRun = true
		return s
	}
	if rep.Err != "" {
		s.Error = rep.Err
		return s
	}
	s.Requests, s.Duration, s.Blocked = rep.Requests, rep.Duration, rep.Blocked
	s.Reported = rep.Plugins
	s.Found, s.Missed, s.FalsePos, s.VulnFound = scorePlugins(m, rep.Plugins)
	if rep.ScoresFiles {
		s.ScoresFiles = true
		s.FilesFound, s.FilesMissed = scoreFiles(site, rep.Files)
	}
	return s
}

// Report is a tool's raw output on a site, before scoring.
type Report struct {
	Plugins     []string // plugin slugs it reported
	Files       []string // exposed file paths it reported (Tuner)
	ScoresFiles bool     // the tool looks for files at all
	Blocked     bool     // it reported the site as WAF-blocked
	Requests    int64    // how many HTTP requests it made, when known (-1 if not)
	Duration    time.Duration
	Err         string // why it produced nothing
}
