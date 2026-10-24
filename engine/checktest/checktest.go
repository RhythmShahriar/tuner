// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package checktest runs YAML checks against their fixtures. Every check
// ships with <name>_test.yaml next to it, describing mock servers it must
// fire on (positive) and stay quiet on (negative).
//
// Beyond firing, a positive case must render safely: its findings go
// through every report format and the case fails when a raw secret from
// the fixture body or a terminal control byte shows up in any of them.
//
// Test is for go test; Run is the same runner for tools without a
// testing.T, such as `rhythm-tuner checks test`.
package checktest

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/engine"
)

// StrictOutput makes output leaks fail Test rather than only being
// logged. It is on: the engine redacts before truncating and strips
// control bytes, and every report goes through one sanitizer.
const StrictOutput = true

// Result is the outcome of one fixture case, or of a check whose fixture
// file could not be used (Case is then empty).
type Result struct {
	Check    string   // check ID
	File     string   // fixture file
	Case     string   // fixture case name
	Positive bool     // a case the check must fire on
	Problems []string // the check misbehaved: no finding, a false positive, an unmasked secret
	Leaks    []string // a report showed a raw secret or a control byte
}

// Failed reports whether the case has a problem or, in strict mode, a leak.
func (r Result) Failed(strict bool) bool {
	return len(r.Problems) > 0 || (strict && len(r.Leaks) > 0)
}

func (r Result) String() string {
	kind := "negative"
	if r.Positive {
		kind = "positive"
	}
	if r.Case == "" {
		return r.File
	}
	return fmt.Sprintf("%s %q", kind, r.Case)
}

// Run loads every check in fsys and runs it against its fixtures, several
// checks at a time; results keep the checks' order. A check set that
// fails to load comes back as a single Result with the error.
func Run(fsys fs.FS) []Result {
	all, err := engine.LoadChecks(fsys)
	if err != nil {
		return []Result{{Problems: []string{err.Error()}}}
	}
	// Each case is a local server and a short scan, mostly waiting, so
	// a few per CPU keeps the machine busy without exhausting ports.
	per := make([][]Result, len(all))
	sem := make(chan struct{}, 4*runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, c := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			per[i] = RunCheck(fsys, c)
			<-sem
		}()
	}
	wg.Wait()
	var out []Result
	for _, rs := range per {
		out = append(out, rs...)
	}
	return out
}

// RunCheck runs one check, loaded from fsys, against its fixture file.
func RunCheck(fsys fs.FS, c *engine.Check) []Result {
	name := strings.TrimSuffix(c.File, ".yaml") + "_test.yaml"
	bad := func(format string, a ...any) []Result {
		return []Result{{Check: c.ID, File: name, Problems: []string{fmt.Sprintf(format, a...)}}}
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return bad("missing fixture %s: every check needs positive and negative cases", name)
	}
	var fx File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fx); err != nil {
		return bad("%s: %v", name, err)
	}
	if len(fx.Positive) == 0 || len(fx.Negative) == 0 {
		return bad("%s: needs at least one positive and one negative case", name)
	}
	source, _ := fs.ReadFile(fsys, c.File)

	var out []Result
	for _, fc := range fx.Positive {
		r := Result{Check: c.ID, File: name, Case: fc.Name, Positive: true}
		res, err := scan(c, fc)
		switch {
		case err != nil:
			r.Problems = append(r.Problems, err.Error())
		case len(res.Findings) == 0:
			r.Problems = append(r.Problems, "no finding")
		default:
			r.Problems = append(r.Problems, masked(res, fc.Secrets)...)
			r.Leaks = outputLeaks(res, fc, c, source)
		}
		out = append(out, r)
	}
	for _, fc := range fx.Negative {
		r := Result{Check: c.ID, File: name, Case: fc.Name}
		res, err := scan(c, fc)
		switch {
		case err != nil:
			r.Problems = append(r.Problems, err.Error())
		case len(res.Findings) > 0:
			f := res.Findings[0]
			r.Problems = append(r.Problems, fmt.Sprintf("unexpected finding on %s: %v", f.Path, f.Evidence.Matched))
		}
		out = append(out, r)
	}
	return out
}

// Test runs every check in fsys against its fixtures as subtests named
// after the check IDs.
func Test(t *testing.T, fsys fs.FS) {
	t.Helper()
	all, err := engine.LoadChecks(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		t.Run(c.ID, func(t *testing.T) {
			t.Parallel()
			for _, r := range RunCheck(fsys, c) {
				for _, p := range r.Problems {
					t.Errorf("%s: %s", r, p)
				}
				for _, l := range r.Leaks {
					if StrictOutput {
						t.Errorf("%s: %s", r, l)
					} else {
						t.Logf("%s: %s (not yet enforced)", r, l)
					}
				}
			}
		})
	}
}

// scan runs check c against the mock site fc describes.
func scan(c *engine.Check, fc Case) (*engine.Result, error) {
	srv, client, err := fc.server()
	if err != nil {
		return nil, err
	}
	defer srv.Close()
	s := engine.New([]*engine.Check{c}, engine.Options{UserAgent: "rhythm-tuner/test", HTTPClient: client})
	res, err := s.Scan(context.Background(), srv.URL, engine.Hooks{})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return res, nil
}

// masked checks the secrets the engine extracted: every one masked, and
// at least one per finding when the case expects them.
func masked(res *engine.Result, want bool) []string {
	var out []string
	for _, f := range res.Findings {
		if want && len(f.Evidence.Secrets) == 0 {
			out = append(out, "expected masked secrets, found none")
		}
		for _, sec := range f.Evidence.Secrets {
			if !strings.Contains(sec.Masked, mask) {
				out = append(out, fmt.Sprintf("secret %v is not masked", sec))
			}
		}
	}
	return out
}

// outputLeaks renders res in every format and looks for anything from
// the fixture bodies that must not be shown. KEY=value lines count as
// secret whatever the key is called when the check extracts secrets or
// the case expects them: a name like DB_PWD gives no hint and .env and
// config files are exactly where those lines live.
func outputLeaks(res *engine.Result, fc Case, c *engine.Check, source []byte) []string {
	outputs, err := render(res)
	if err != nil {
		return []string{"rendering reports: " + err.Error()}
	}
	var raw []string
	for _, b := range fc.bodies() {
		raw = append(raw, rawValues(b, fc.Secrets || c.Extract.Secrets)...)
	}
	var found []string
	for _, format := range []string{"plain", "json", "sarif", "md"} {
		found = append(found, leaks(format, outputs[format], raw, source)...)
	}
	return found
}
