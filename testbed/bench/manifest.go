// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

// Command bench runs Tuner and three other scanners against the Tuner
// WordPress testbed and writes docs/benchmark.md. Build it with the
// testbed tag so it never enters an ordinary build:
//
//	go run -tags testbed ./testbed/bench        # needs the testbed up
//	go test -tags testbed ./testbed/bench       # the scoring, no Docker
//
// It scores every tool against testbed/ground-truth.yaml: the plugins it
// found against what is really installed, false positives, requests and
// time. Only Tuner looks for exposed files, so those columns are Tuner's
// alone. Nothing here holds a working exploit.
package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is testbed/ground-truth.yaml.
type Manifest struct {
	Sites   map[string]Site `yaml:"sites"`
	Plugins []Plugin        `yaml:"plugins"`
}

// Site is one testbed site.
type Site struct {
	URL       string    `yaml:"url"`
	Front     string    `yaml:"front"` // nginx, apache or challenge
	WordPress string    `yaml:"wordpress"`
	Blocked   bool      `yaml:"blocked"` // a WAF front: the expected result is "blocked"
	Exposed   []Exposed `yaml:"exposed"`
	Local     []Local   `yaml:"local"`
}

// Exposed is a file reachable over HTTP that a scan should report.
type Exposed struct {
	Path     string `yaml:"path"`
	Finding  string `yaml:"finding"`  // Tuner's finding id
	Severity string `yaml:"severity"` // critical, high, medium, low, info
}

// Local is a problem only a local (on-disk) scan can see.
type Local struct {
	Kind string `yaml:"kind"`
	Path string `yaml:"path"`
	Note string `yaml:"note"`
}

// Plugin is one installed plugin and how an outside scan can find it.
type Plugin struct {
	Slug         string `yaml:"slug"`
	Version      string `yaml:"version"`
	Discoverable string `yaml:"discoverable"` // readme, rest or asset
	Vulnerable   bool   `yaml:"vulnerable"`
	Active       bool   `yaml:"active"`
}

var (
	// The values a manifest may use for a plugin's discovery, a site's front
	// and a finding's severity.
	discoverable = []string{"readme", "rest", "asset"}
	fronts       = []string{"nginx", "apache", "challenge"}
	severities   = []string{"critical", "high", "medium", "low", "info"}
)

// LoadManifest reads and checks ground-truth.yaml.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the testbed's own manifest
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// check validates the manifest before anything runs.
func (m *Manifest) check() error {
	if len(m.Sites) == 0 {
		return fmt.Errorf("no sites")
	}
	for name, s := range m.Sites {
		switch {
		case s.URL == "":
			return fmt.Errorf("site %s: no url", name)
		case !slices.Contains(fronts, s.Front):
			return fmt.Errorf("site %s: front %q is not one of %v", name, s.Front, fronts)
		}
		for _, e := range s.Exposed {
			if e.Finding == "" || !slices.Contains(severities, e.Severity) {
				return fmt.Errorf("site %s: exposed %s needs a finding and a known severity", name, e.Path)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range m.Plugins {
		switch {
		case p.Slug == "" || seen[p.Slug]:
			return fmt.Errorf("missing or duplicate plugin slug %q", p.Slug)
		case p.Version == "":
			return fmt.Errorf("plugin %s: no version", p.Slug)
		case !slices.Contains(discoverable, p.Discoverable):
			return fmt.Errorf("plugin %s: discoverable %q is not one of %v", p.Slug, p.Discoverable, discoverable)
		}
		seen[p.Slug] = true
	}
	return nil
}

// Slugs returns every installed plugin slug.
func (m *Manifest) Slugs() []string {
	out := make([]string, len(m.Plugins))
	for i, p := range m.Plugins {
		out[i] = p.Slug
	}
	slices.Sort(out)
	return out
}

// VulnerableSlugs returns the installed plugins public advisories flag.
func (m *Manifest) VulnerableSlugs() []string {
	var out []string
	for _, p := range m.Plugins {
		if p.Vulnerable {
			out = append(out, p.Slug)
		}
	}
	slices.Sort(out)
	return out
}

// Installed reports whether slug is an installed plugin.
func (m *Manifest) Installed(slug string) bool {
	return slices.ContainsFunc(m.Plugins, func(p Plugin) bool { return p.Slug == slug })
}
