// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package tunerconfig reads .tuner.yml, the file that keeps a project's
// scan settings and accepted risks next to its code, so a CI line can be
// just "rhythm tuner scan".
//
// Every key is optional:
//
//	targets: [https://staging.example.com]
//	profile: quick
//	rate: 2
//	concurrency: 4
//	fail_on: high
//	min_confidence: confirmed
//	baseline: tuner-baseline.json
//	headers:
//	  Authorization: Bearer ${TUNER_STAGING_TOKEN}
//	tags: [leak, wordpress]
//	exclude_tags: [headers]
//	ids: [leak-*]
//	exclude_ids: [hdr-csp]
//	ignore:
//	  - id: leak-dotenv
//	    path: /staging/.env
//	    reason: fake keys for the demo site
//	    until: 2026-12-31
//
// A key Tuner does not know is an error, so a typo never quietly turns a
// setting off. Header values may name environment variables as ${NAME}
// when NAME starts with TUNER_; one that is unset or empty is an error.
// Header values never appear in an error message.
//
// The prefix is the trust boundary. A scan reads .tuner.yml from the
// current folder, so a cloned repository or a pull request can bring its
// own file, with targets of its choosing. If it could name any variable,
// it could send a CI runner's GITHUB_TOKEN or cloud keys to its own host.
// A TUNER_ variable is one the user set for Tuner on purpose. Even so a
// scan sends such a header only to targets the command line named: when
// the file chooses the targets, Config.EnvHeaders makes it refuse.
package tunerconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/engine"
)

// DefaultName is the file a scan reads from the current folder.
const DefaultName = ".tuner.yml"

// Config is a parsed .tuner.yml. Fields left out of the file are zero;
// Rate and Concurrency are nil then, as 0 is a valid rate.
type Config struct {
	// Path is the file the settings came from, as it was named.
	Path string

	Targets       []string
	Profile       string // quick or default (deep still works), lower-cased
	Rate          *float64
	Concurrency   *int
	FailOn        string // a severity, lower-cased
	MinConfidence string // confirmed or likely
	// Baseline is the baseline report's path, relative to the folder
	// that holds the config file unless it is absolute.
	Baseline string
	// Headers are "Name: value" lines with ${TUNER_NAME} already expanded,
	// sorted by name. Never print them: they hold credentials.
	Headers []string
	// EnvHeaders names the headers whose values read a ${TUNER_NAME}
	// variable, sorted. A scan sends those only to targets the command
	// line named, as the variables are often CI secrets.
	EnvHeaders  []string
	Tags        []string
	ExcludeTags []string
	IDs         []string
	ExcludeIDs  []string
	Ignore      []Ignore
}

// Ignore hides findings a project has accepted, until a date.
type Ignore struct {
	ID     string // a check ID glob, such as leak-* (path.Match syntax)
	Path   string // a finding path glob, such as /backup/*.zip
	Reason string // why the risk is accepted; required
	Until  string // YYYY-MM-DD, the last day it applies; "" never expires
}

// file is the YAML layout. Its field names are the keys people write.
type file struct {
	Targets       []string          `yaml:"targets"`
	Profile       string            `yaml:"profile"`
	Rate          *float64          `yaml:"rate"`
	Concurrency   *int              `yaml:"concurrency"`
	FailOn        string            `yaml:"fail_on"`
	MinConfidence string            `yaml:"min_confidence"`
	Baseline      string            `yaml:"baseline"`
	Headers       map[string]string `yaml:"headers"`
	Tags          []string          `yaml:"tags"`
	ExcludeTags   []string          `yaml:"exclude_tags"`
	IDs           []string          `yaml:"ids"`
	ExcludeIDs    []string          `yaml:"exclude_ids"`
	Ignore        []struct {
		ID     string `yaml:"id"`
		Path   string `yaml:"path"`
		Reason string `yaml:"reason"`
		Until  string `yaml:"until"`
	} `yaml:"ignore"`
}

// Find returns the path of .tuner.yml in dir, or "" when there is none.
func Find(dir string) (string, error) {
	p := filepath.Join(dir, DefaultName)
	fi, err := os.Stat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", nil
	case err != nil:
		return "", err
	case fi.IsDir():
		return "", fmt.Errorf("%s is a folder, not a config file", p)
	}
	return p, nil
}

// Load reads the config at path, expanding ${TUNER_NAME} from the
// environment.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the user's own config file
	if err != nil {
		return nil, err
	}
	return Parse(data, path, os.LookupEnv)
}

// Parse reads a config from data. name is where it came from, for errors
// and Config.Path; env looks up the variables headers name.
func Parse(data []byte, name string, env func(string) (string, bool)) (*Config, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, yamlError(name, err)
	}
	// Later documents would be skipped unchecked, typos and all.
	var more yaml.Node
	if err := dec.Decode(&more); err == nil && !empty(&more) {
		return nil, fmt.Errorf("%s: holds more than one YAML document; keep the settings in one", name)
	} else if err != nil && !errors.Is(err, io.EOF) {
		return nil, yamlError(name, err)
	}
	c := &Config{
		Path: name, Targets: f.Targets, Rate: f.Rate, Concurrency: f.Concurrency,
		Tags: f.Tags, ExcludeTags: f.ExcludeTags, IDs: f.IDs, ExcludeIDs: f.ExcludeIDs,
	}
	bad := func(key, format string, a ...any) error {
		return fmt.Errorf("%s: %s: %s", name, key, fmt.Sprintf(format, a...))
	}

	var err error
	// deep is accepted but left out of the message: no check uses it yet.
	if strings.EqualFold(strings.TrimSpace(f.Profile), string(engine.ProfileDeep)) {
		c.Profile = string(engine.ProfileDeep)
	} else if c.Profile, err = oneOf(f.Profile, []engine.Profile{engine.ProfileQuick, engine.ProfileDefault}); err != nil {
		return nil, bad("profile", "%v", err)
	}
	if c.FailOn, err = oneOf(f.FailOn, engine.Severities); err != nil {
		return nil, bad("fail_on", "%v", err)
	}
	if c.MinConfidence, err = oneOf(f.MinConfidence, []string{"confirmed", "likely"}); err != nil {
		return nil, bad("min_confidence", "%v", err)
	}
	if c.Rate != nil && *c.Rate < 0 {
		return nil, bad("rate", "want 0 or more (0 means no limit)")
	}
	if c.Concurrency != nil && *c.Concurrency < 1 {
		return nil, bad("concurrency", "want 1 or more")
	}
	if c.Baseline = f.Baseline; c.Baseline != "" && !filepath.IsAbs(c.Baseline) {
		c.Baseline = filepath.Join(filepath.Dir(name), c.Baseline)
	}
	for _, t := range c.Targets {
		if strings.TrimSpace(t) == "" {
			return nil, bad("targets", "a target is empty")
		}
	}
	for _, list := range []struct {
		key string
		ids []string
	}{{"ids", c.IDs}, {"exclude_ids", c.ExcludeIDs}} {
		for _, id := range list.ids {
			if _, err := path.Match(id, ""); err != nil {
				return nil, bad(list.key, "bad pattern %q", id)
			}
		}
	}

	names := make([]string, 0, len(f.Headers))
	for n := range f.Headers {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		v, err := expand(f.Headers[n], env)
		if err != nil {
			return nil, bad("headers", "%s %v", n, err)
		}
		if !token(n) {
			return nil, bad("headers", "%q is not a valid header name", n)
		}
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			// Say which header, never what it holds.
			return nil, bad("headers", "the value of %s has a line break or control character", n)
		}
		c.Headers = append(c.Headers, n+": "+v)
		if envRef.MatchString(f.Headers[n]) {
			c.EnvHeaders = append(c.EnvHeaders, n)
		}
	}

	for i, ig := range f.Ignore {
		which := fmt.Sprintf("ignore %d", i+1)
		if ig.ID != "" || ig.Path != "" {
			which += " (" + strings.Trim(ig.ID+" "+ig.Path, " ") + ")"
		}
		switch {
		case ig.ID == "" && ig.Path == "":
			return nil, bad(which, "needs an id or a path")
		case strings.TrimSpace(ig.Reason) == "":
			return nil, bad(which, "needs a reason, so the next person knows why it is accepted")
		}
		for _, p := range []string{ig.ID, ig.Path} {
			if _, err := path.Match(p, ""); err != nil {
				return nil, bad(which, "bad pattern %q", p)
			}
		}
		if ig.Until != "" {
			if _, err := time.Parse(time.DateOnly, ig.Until); err != nil {
				return nil, bad(which, "until %q: want a date such as 2026-12-31", ig.Until)
			}
		}
		c.Ignore = append(c.Ignore, Ignore{ID: ig.ID, Path: ig.Path, Reason: strings.TrimSpace(ig.Reason), Until: ig.Until})
	}
	return c, nil
}

// Ignores splits the ignore list into entries that still apply on now's
// date and ones that have expired. An entry applies through its Until day.
func (c *Config) Ignores(now time.Time) (active, expired []Ignore) {
	today := now.Format(time.DateOnly)
	for _, ig := range c.Ignore {
		if ig.Until != "" && ig.Until < today {
			expired = append(expired, ig)
		} else {
			active = append(active, ig)
		}
	}
	return active, expired
}

// Matches reports whether the entry covers a finding with this check ID
// and path. A leading slash is optional in both the pattern and the path.
func (ig Ignore) Matches(id, findingPath string) bool {
	if ig.ID != "" {
		if ok, _ := path.Match(ig.ID, id); !ok {
			return false
		}
	}
	if ig.Path != "" {
		ok, _ := path.Match(strings.TrimPrefix(ig.Path, "/"), strings.TrimPrefix(findingPath, "/"))
		return ok
	}
	return true
}

// Note says that an expired entry no longer hides anything, for example
// "ignore for leak-dotenv expired 2026-09-30: fake keys for the demo".
func (ig Ignore) Note() string {
	what := strings.Trim(ig.ID+" "+ig.Path, " ")
	return fmt.Sprintf("ignore for %s expired %s: %s", what, ig.Until, ig.Reason)
}

// envRef is a ${NAME} reference in a header value.
var envRef = regexp.MustCompile(`\$\{([^}]*)\}`)

// envName is what a variable name may look like.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvPrefix starts every variable a header value may name. See the
// package doc for why.
const EnvPrefix = "TUNER_"

// expand replaces each ${NAME} in v. A name without EnvPrefix is an
// error, so is an unset or empty variable: CI systems pass a missing
// secret as an empty string. A scan without its credentials would report
// a login page as the site.
func expand(v string, env func(string) (string, bool)) (string, error) {
	var err error
	out := envRef.ReplaceAllStringFunc(v, func(ref string) string {
		name := ref[2 : len(ref)-1]
		if !envName.MatchString(name) {
			err = fmt.Errorf("uses %s, which is not a variable name", ref)
			return ""
		}
		if !strings.HasPrefix(name, EnvPrefix) {
			if err == nil {
				err = fmt.Errorf("uses ${%s}; only variables that start with %s can be used, so set %s%s and name that", name, EnvPrefix, EnvPrefix, name)
			}
			return ""
		}
		val, ok := env(name)
		if (!ok || val == "") && err == nil {
			err = fmt.Errorf("uses ${%s}, which is not set", name)
		}
		return val
	})
	return out, err
}

// oneOf lower-cases v and checks it is one of options; "" stays "".
func oneOf[T ~string](v string, options []T) (string, error) {
	if v == "" {
		return "", nil
	}
	low := strings.ToLower(strings.TrimSpace(v))
	if slices.Contains(options, T(low)) {
		return low, nil
	}
	list := make([]string, len(options))
	for i, o := range options {
		list[i] = string(o)
	}
	return "", fmt.Errorf("%q: want %s or %s", v, strings.Join(list[:len(list)-1], ", "), list[len(list)-1])
}

// token reports whether s is an HTTP header name (RFC 9110 5.1).
func token(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// unknownKey matches yaml.v3's message for a key KnownFields rejects.
var unknownKey = regexp.MustCompile(`line (\d+): field (\S+) not found in type`)

// quotedValue is the value yaml.v3 quotes in a type error, such as the
// " `Bearer ...`" in "cannot unmarshal !!str `Bearer ...` into ...".
var quotedValue = regexp.MustCompile(" `[^`]*`")

// empty reports whether n is a YAML document with nothing in it, as a
// trailing "---" gives.
func empty(n *yaml.Node) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	return n.Kind == 0 || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

// yamlError rewords yaml.v3's errors to name the file and the key.
func yamlError(name string, err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		var lines []string
		for _, e := range te.Errors {
			if m := unknownKey.FindStringSubmatch(e); m != nil {
				lines = append(lines, fmt.Sprintf("%s line %s: unknown key %q", name, m[1], m[2]))
			} else {
				// yaml.v3 quotes the start of the value, which may be a
				// token given where the headers map belongs.
				lines = append(lines, name+" "+quotedValue.ReplaceAllString(e, ""))
			}
		}
		return errors.New(strings.Join(lines, "\n"))
	}
	return fmt.Errorf("%s: %w", name, err)
}
