package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/matchers"
)

// Severity of a finding, from info to critical.
type Severity string

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
	ID         string         `yaml:"id"`
	Name       string         `yaml:"name"`
	Severity   Severity       `yaml:"severity"`
	Confidence string         `yaml:"confidence"`
	Profile    Profile        `yaml:"profile"` // cheapest scan profile that runs this check
	Tags       []string       `yaml:"tags"`
	Requires   []string       `yaml:"requires"` // tech the fingerprint must find, e.g. wordpress
	Request    Request        `yaml:"request"`
	Match      matchers.Block `yaml:"match"`
	Extract    Extract        `yaml:"extract"`
	Impact     string         `yaml:"impact"`
	Fix        string         `yaml:"fix"`
	References []string       `yaml:"references"`

	// File is the check's path inside the checks filesystem.
	File string `yaml:"-"`
}

type Request struct {
	Method string   `yaml:"method"`
	Path   []string `yaml:"path"` // {{host}} expands to the target hostname
}

type Extract struct {
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
	}
	if c.Request.Method == "" {
		c.Request.Method = "GET"
	}
	if c.Profile == "" {
		c.Profile = ProfileDefault
	}
	if c.Profile.Rank() < 0 {
		return nil, fmt.Errorf("profile %q: want one of %v", c.Profile, Profiles)
	}
	if c.Confidence == "" {
		c.Confidence = "high"
	}
	if err := c.Match.Compile(); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	return &c, nil
}
