// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/matchers"
)

// validator checks a JSON document against the subset of JSON Schema
// 2020-12 the published schemas use: type, required, properties, items,
// enum, additionalProperties, anyOf, $ref to "#/$defs/...", minimum,
// maximum and pattern. It keeps the module free of a schema dependency;
// anything else in a schema is a test failure, so the subset can't drift
// silently.
type validator struct {
	root map[string]any
	errs []string
	// strict treats an object schema with properties and no
	// additionalProperties as closed. The published schemas stay open so
	// a release that adds a field doesn't break other people's
	// validators; the tests stay strict so the schema can't fall behind
	// the writer.
	strict bool
}

var supported = []string{"$schema", "$id", "$defs", "title", "description", "format",
	"type", "required", "properties", "items", "enum", "additionalProperties", "anyOf", "$ref",
	"minimum", "maximum", "pattern", "minItems"}

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s
}

// validate returns every way doc breaks schema, or nil.
func validate(schema map[string]any, doc []byte) []string { return validateWith(schema, doc, false) }

// validateStrict is validate with unlisted properties refused.
func validateStrict(schema map[string]any, doc []byte) []string {
	return validateWith(schema, doc, true)
}

func validateWith(schema map[string]any, doc []byte, strict bool) []string {
	var v any
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return []string{err.Error()}
	}
	val := &validator{root: schema, strict: strict}
	val.check(schema, v, "$")
	return val.errs
}

func (val *validator) fail(path, format string, a ...any) {
	val.errs = append(val.errs, path+": "+fmt.Sprintf(format, a...))
}

func (val *validator) check(s map[string]any, v any, path string) {
	for k := range s {
		if !slices.Contains(supported, k) {
			val.fail(path, "schema keyword %q is outside the tested subset", k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		name, ok := strings.CutPrefix(ref, "#/$defs/")
		def, _ := val.root["$defs"].(map[string]any)[name].(map[string]any)
		if !ok || def == nil {
			val.fail(path, "unresolved $ref %q", ref)
			return
		}
		val.check(def, v, path)
	}
	if alts, ok := s["anyOf"].([]any); ok {
		var all []string
		matched := false
		for _, alt := range alts {
			sub := &validator{root: val.root, strict: val.strict}
			sub.check(alt.(map[string]any), v, path)
			if len(sub.errs) == 0 {
				matched = true
				break
			}
			all = append(all, sub.errs...)
		}
		if !matched {
			val.fail(path, "matches no anyOf branch: %s", strings.Join(all, "; "))
		}
	}
	if t, ok := s["type"]; ok && !typeMatches(t, v) {
		val.fail(path, "want type %v, got %s", t, jsonType(v))
		return
	}
	if enum, ok := s["enum"].([]any); ok && !slices.ContainsFunc(enum, func(e any) bool { return fmt.Sprint(e) == fmt.Sprint(v) }) {
		val.fail(path, "%v is not one of %v", v, enum)
	}
	if n, ok := v.(json.Number); ok {
		f, _ := n.Float64()
		if lo, ok := s["minimum"].(float64); ok && f < lo {
			val.fail(path, "%v is below %v", n, lo)
		}
		if hi, ok := s["maximum"].(float64); ok && f > hi {
			val.fail(path, "%v is above %v", n, hi)
		}
	}
	if p, ok := s["pattern"].(string); ok {
		if str, ok := v.(string); ok && !regexp.MustCompile(p).MatchString(str) {
			val.fail(path, "%q does not match %s", str, p)
		}
	}
	switch v := v.(type) {
	case map[string]any:
		for _, r := range asStrings(s["required"]) {
			if _, ok := v[r]; !ok {
				val.fail(path, "missing required %q", r)
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, sub := range v {
			if ps, ok := props[k].(map[string]any); ok {
				val.check(ps, sub, path+"."+k)
				continue
			}
			extra, ok := s["additionalProperties"]
			if !ok && val.strict && props != nil {
				extra = false
			}
			switch extra := extra.(type) {
			case bool:
				if !extra {
					val.fail(path, "unexpected property %q", k)
				}
			case map[string]any:
				val.check(extra, sub, path+"."+k)
			}
		}
	case []any:
		if lo, ok := s["minItems"].(float64); ok && float64(len(v)) < lo {
			val.fail(path, "want at least %v items, got %d", lo, len(v))
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range v {
				val.check(items, e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

func asStrings(v any) []string {
	var out []string
	for _, e := range asSlice(v) {
		out = append(out, e.(string))
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func typeMatches(t, v any) bool {
	if ts, ok := t.([]any); ok {
		return slices.ContainsFunc(ts, func(t any) bool { return typeMatches(t, v) })
	}
	got := jsonType(v)
	if t == "number" && got == "integer" {
		return true
	}
	return t == got
}

func jsonType(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if f, err := v.Float64(); err == nil && f == math.Trunc(f) && !strings.ContainsAny(v.String(), ".eE") {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// fullResult fills every field a report can carry, so the schema test
// notices a field the schema doesn't describe.
func fullResult() *engine.Result {
	return &engine.Result{
		Target: "https://a.test",
		Fingerprint: fingerprint.Result{Tech: []string{"wordpress", "php"}, WordPress: "6.5.2", PHP: "8.1.2",
			PHPBuild: "8.1.2-1ubuntu2.19", PHPSource: "x-powered-by /", Server: "nginx/1.24.0",
			Components: []fingerprint.Component{{Type: "plugin", Slug: "gallery", Version: "1.5", Source: "readme"}}},
		Soft404: true,
		TLS:     &matchers.TLSInfo{Version: "TLS 1.3", NotAfter: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), VerifyError: "expired", Legacy: []string{"TLS 1.0"}},
		Score:   40, Checks: 37, Requests: 80, Errors: 1, Throttled: 2, Duration: 1500 * time.Millisecond,
		Warnings: []string{"couldn't fetch vulnerability data"},
		Findings: []engine.Finding{
			{ID: "leak-dotenv", Title: ".env file exposed", Severity: engine.Critical, Confidence: "high",
				Target: "https://a.test", URL: "https://a.test/.env", Path: "/.env",
				Evidence: engine.Evidence{Request: "GET /.env", Status: 200, Matched: []string{"DB_PASSWORD=…"},
					Secrets: []matchers.Secret{{Kind: "env", Name: "DB_PASSWORD", Masked: "hu****42"}}},
				Impact: "Anyone can read it.", Fix: "Move it.", References: []string{"https://example.com/a"}, Tags: []string{"leak"}},
			{ID: "vuln-plugin-gallery", Title: "gallery 1.5: 1 known vulnerability", Severity: engine.High, Confidence: "low",
				Caveat: "the version comes from a readme", Target: "https://a.test", URL: "https://a.test/wp-content/plugins/gallery/",
				Path: "/wp-content/plugins/gallery/", Source: "WPVulnerability",
				Advisories: []engine.Advisory{{ID: "A1", Title: "SQL injection", CVEs: []string{"CVE-2026-1"}, Severity: engine.High,
					CVSS: 8.1, KEV: true, FixedIn: "1.6", References: []string{"https://example.com/b"}}}},
		},
	}
}

func encodeJSON(t *testing.T, reports []Report, o WriteOptions) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Write("json", &b, reports, o); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestJSONMatchesSchema(t *testing.T) {
	schema := loadSchema(t, "../schema/report-v0.json")
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v", schema["$schema"])
	}
	full := New(fullResult(), "0.4.0")
	full.CheckSet, full.CheckPack, full.Baselined = "pack", "2026.10.1", 3
	full.SetStatus(Status{Complete: false, StoppedBy: "waf", BlockedBy: "cloudflare", VulnData: "partial"})
	clean := New(&engine.Result{Target: "/srv/www"}, "0.4.0")
	failed := []TargetError{{Target: "https://down.test", Error: "connection refused"}}

	for name, doc := range map[string][]byte{
		"single":        encodeJSON(t, []Report{full}, WriteOptions{}),
		"clean":         encodeJSON(t, []Report{clean}, WriteOptions{}),
		"array":         encodeJSON(t, []Report{full}, WriteOptions{Array: true}),
		"batch":         encodeJSON(t, []Report{full, clean}, WriteOptions{Many: true}),
		"failed target": encodeJSON(t, []Report{clean}, WriteOptions{Many: true, Failed: failed}),
		"all failed":    encodeJSON(t, nil, WriteOptions{Failed: failed}),
		"empty":         encodeJSON(t, nil, WriteOptions{}),
	} {
		if errs := validateStrict(schema, doc); len(errs) > 0 {
			t.Errorf("%s: %s\n%s", name, strings.Join(errs, "\n"), doc)
		}
	}
}

// The validator must reject what the schema forbids, or the test above
// proves nothing.
func TestSchemaRejectsDrift(t *testing.T) {
	schema := loadSchema(t, "../schema/report-v0.json")
	good := string(encodeJSON(t, []Report{New(fullResult(), "0.4.0")}, WriteOptions{}))
	for name, doc := range map[string]string{
		"missing field":  strings.Replace(good, `"complete": true,`, "", 1),
		"unknown field":  strings.Replace(good, `"complete": true,`, `"complete": true, "surprise": 1,`, 1),
		"bad severity":   strings.Replace(good, `"severity": "critical"`, `"severity": "severe"`, 1),
		"string count":   strings.Replace(good, `"checks": 37`, `"checks": "37"`, 1),
		"bad fp":         regexp.MustCompile(`"fingerprint": "v1:[0-9a-f]+"`).ReplaceAllString(good, `"fingerprint": "abc"`),
		"bad array item": `[{"target": "x"}]`,
	} {
		if doc == good {
			t.Fatalf("%s: the replacement did nothing", name)
		}
		if errs := validateStrict(schema, []byte(doc)); len(errs) == 0 {
			t.Errorf("%s: validated, want an error", name)
		}
	}
	// The published schema itself lets a later release add fields.
	extra := strings.Replace(good, `"complete": true,`, `"complete": true, "surprise": 1,`, 1)
	if errs := validate(schema, []byte(extra)); len(errs) > 0 {
		t.Errorf("published schema refuses a new field: %s", strings.Join(errs, "\n"))
	}
}

func TestCleanSummaryHasEverySeverity(t *testing.T) {
	doc := encodeJSON(t, []Report{New(&engine.Result{Target: "https://a.test"}, "0.4.0")}, WriteOptions{})
	var r struct {
		Summary map[string]*int `json:"summary"`
	}
	if err := json.Unmarshal(doc, &r); err != nil {
		t.Fatal(err)
	}
	for _, s := range engine.Severities {
		if n := r.Summary[string(s)]; n == nil || *n != 0 {
			t.Errorf("summary.%s = %v, want 0:\n%s", s, n, doc)
		}
	}
}
