// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/matchers"
)

// Severity of a finding, from info to critical.
type Severity string

// Severities, as checks and JSON spell them.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Severities lists every severity, most severe first.
var Severities = []Severity{Critical, High, Medium, Low, Info}

// Rank is 0 for critical and grows as severity drops; -1 if unknown.
func (s Severity) Rank() int { return slices.Index(Severities, s) }

// Check is one YAML check from the checks/ directory.
type Check struct {
	ID         string         `yaml:"id"`         // unique, kebab-case; findings carry it
	Name       string         `yaml:"name"`       // the finding's title
	Severity   Severity       `yaml:"severity"`   // how bad a finding is
	Confidence Confidence     `yaml:"confidence"` // high (confirmed) or low (likely); default high
	Profile    Profile        `yaml:"profile"`    // cheapest scan profile that runs this check
	Tags       []string       `yaml:"tags"`
	Requires   []string       `yaml:"requires"`   // tech the fingerprint must find, e.g. wordpress
	Request    Request        `yaml:"request"`    // what to fetch; GET or HEAD only
	Match      matchers.Block `yaml:"match"`      // what the reply must look like for the check to fire
	Extract    Extract        `yaml:"extract"`    // what to attach to the finding
	Impact     string         `yaml:"impact"`     // what an attacker could do with it
	Fix        string         `yaml:"fix"`        // how to fix it
	References []string       `yaml:"references"` // links for further reading
	FixServer  FixServer      `yaml:"fix_server"` // server config that fixes it

	// File is the check's path inside the checks filesystem.
	File string `yaml:"-"`
}

// FixServer holds web server config snippets that fix a finding. They
// reach the finding as Finding.Fixes, keyed nginx and apache.
type FixServer struct {
	Nginx  string `yaml:"nginx"`  // snippet for an nginx server block
	Apache string `yaml:"apache"` // snippet for an Apache virtual host
}

// fixes returns the non-empty snippets by server name, or nil.
func (f FixServer) fixes() map[string]string {
	var m map[string]string
	for name, v := range map[string]string{"nginx": f.Nginx, "apache": f.Apache} {
		if v = strings.TrimSpace(v); v != "" {
			if m == nil {
				m = map[string]string{}
			}
			m[name] = v
		}
	}
	return m
}

// Request is what a check fetches: one request per path, GET unless
// Method says HEAD.
type Request struct {
	Method string   `yaml:"method"` // GET (default) or HEAD; anything that could change a site is refused
	Path   []string `yaml:"path"`   // {{host}} expands to the target hostname
}

// Extract lists what a check pulls out of a matching response.
type Extract struct {
	// Secrets adds the masked credentials found in the body to the
	// finding's evidence.
	Secrets bool `yaml:"secrets"`
}

// IsFixture reports whether a file in the checks tree is a test fixture
// rather than a check.
func IsFixture(name string) bool { return strings.HasSuffix(name, "_test.yaml") }

// LoadChecks reads and validates every check in fsys.
func LoadChecks(fsys fs.FS) ([]*Check, error) {
	var checks []*Check
	seen := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".yaml" || IsFixture(p) {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		c, err := ParseCheck(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if prev, ok := seen[c.ID]; ok {
			return fmt.Errorf("%s: id %q already used by %s", p, c.ID, prev)
		}
		seen[c.ID] = p
		c.File = p
		checks = append(checks, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(checks) == 0 {
		return nil, errors.New("no checks found")
	}
	slices.SortFunc(checks, func(a, b *Check) int { return strings.Compare(a.ID, b.ID) })
	return checks, nil
}

// safeQuery is the only query string a check path may carry: plain
// name=value pairs. Percent escapes, quotes, parentheses, semicolons and
// spaces are refused, so a check can never send an injection payload.
var safeQuery = regexp.MustCompile(`^[A-Za-z0-9_.~-]+=[A-Za-z0-9_.~/-]*(&[A-Za-z0-9_.~-]+=[A-Za-z0-9_.~/-]*)*$`)

// ParseCheck decodes and validates a single check. Unknown keys are errors,
// so a typo in a check fails loudly instead of silently matching nothing.
func ParseCheck(data []byte) (*Check, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Check
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	switch {
	case c.ID == "":
		return nil, errors.New("missing id")
	case c.Name == "":
		return nil, errors.New("missing name")
	case c.Severity.Rank() < 0:
		return nil, fmt.Errorf("severity %q: want one of %v", c.Severity, Severities)
	case len(c.Request.Path) == 0:
		return nil, errors.New("request.path is empty")
	}
	for _, p := range c.Request.Path {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("request.path %q must start with /", p)
		}
		if _, q, ok := strings.Cut(p, "?"); ok && !safeQuery.MatchString(q) {
			return nil, fmt.Errorf("request.path %q: the query may only hold plain name=value pairs (letters, digits, _ . ~ - and / in values)", p)
		}
	}
	// Checks only read: a write method such as DELETE or POST could change
	// the site, which Tuner never does.
	switch m := strings.ToUpper(c.Request.Method); m {
	case "":
		c.Request.Method = "GET"
	case "GET", "HEAD":
		c.Request.Method = m
	default:
		return nil, fmt.Errorf("request.method %q: checks may only use GET or HEAD", c.Request.Method)
	}
	if c.Profile == "" {
		c.Profile = ProfileDefault
	}
	if c.Profile.Rank() < 0 {
		return nil, fmt.Errorf("profile %q: want one of %v", c.Profile, Profiles)
	}
	if c.Confidence == "" {
		c.Confidence = ConfidenceHigh
	}
	if err := c.Match.Compile(); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	return &c, nil
}
