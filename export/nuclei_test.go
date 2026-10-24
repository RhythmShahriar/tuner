// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package export

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/engine/checktest"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/matchers"
)

var update = flag.Bool("update", false, "rewrite the golden templates in testdata/nuclei")

var testOpts = Options{Version: "test"}

func builtIn(t *testing.T) []*engine.Check {
	t.Helper()
	all, err := engine.LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func byID(t *testing.T, all []*engine.Check, id string) *engine.Check {
	t.Helper()
	i := slices.IndexFunc(all, func(c *engine.Check) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("no check %s", id)
	}
	return all[i]
}

// The golden checks cover each way a check converts: a regex with a
// negative regex, magic bytes in an any block with {{host}}, regexes in
// an any block, a header regex and a query route that needs WordPress.
func TestNucleiGolden(t *testing.T) {
	all := builtIn(t)
	for _, id := range []string{"leak-dotenv", "leak-archive-backup", "php-phpmyadmin", "hdr-powered-by-version", "wp-user-enum-rest-route"} {
		t.Run(id, func(t *testing.T) {
			tmpl := NucleiTemplate(byID(t, all, id), testOpts)
			if tmpl.Skipped != "" {
				t.Fatalf("skipped: %s", tmpl.Skipped)
			}
			golden := filepath.Join("testdata", "nuclei", tmpl.File)
			if *update {
				if err := os.WriteFile(golden, tmpl.Data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tmpl.Data, want) {
				t.Errorf("%s differs (go test ./export -update rewrites it):\n%s", golden, tmpl.Data)
			}
		})
	}
}

func TestNucleiSkips(t *testing.T) {
	all := builtIn(t)
	for id, want := range map[string]string{
		"tls-cert-expired":     "TLS conditions",
		"hdr-cookie-no-secure": "the scheme condition (https only)",
		"hdr-hsts-missing":     "the scheme condition (https only)",
		"tls-no-https":         "the scheme condition (http only)",
	} {
		if got := NucleiTemplate(byID(t, all, id), testOpts); got.Data != nil || !strings.Contains(got.Skipped, want) {
			t.Errorf("%s: skipped %q, want %q", id, got.Skipped, want)
		}
	}

	parse := func(yml string) *engine.Check {
		c, err := engine.ParseCheck([]byte("id: leak-x\nname: X\nseverity: low\nrequest: {path: [/x]}\n" + yml))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for yml, want := range map[string]string{
		"match: {all: [{status: 200}, {not_baseline: true}]}":                   "only the soft-404 comparison",
		"match: {all: [{status: 200}, {header: {X: y}}, {not_baseline: true}]}": "only the soft-404 comparison",
		"match: {any: [{magic: '00'}, {regex: x}]}":                             "mixes magic bytes with text patterns",
		"match: {any: [{status: 200, regex: x}, {regex: y}]}":                   "more than one condition",
		"match: {all: [{cookie: {missing_flag: secure}}]}":                      "cookie flag conditions",
	} {
		if got := NucleiTemplate(parse(yml), testOpts); !strings.Contains(got.Skipped, want) {
			t.Errorf("%s: skipped %q, want %q", yml, got.Skipped, want)
		}
	}

	// Words alternatives merge into one regex matcher.
	got := NucleiTemplate(parse("match: {any: [{words: [a.b]}, {regex: 'c+'}]}"), testOpts)
	if !bytes.Contains(got.Data, []byte("- a\\.b\n          - c+\n        condition: or")) {
		t.Errorf("merged any:\n%s", got.Data)
	}
}

// An ID that isn't a kebab-case name is never a file name, so a crafted
// check can't write outside the export directory.
func TestNucleiUnsafeID(t *testing.T) {
	for _, id := range []string{"../../../escaped", "leak/x", `leak-\x`, "Leak-X", "leak-x\x1b[2J", ".."} {
		c, err := engine.ParseCheck([]byte(fmt.Sprintf("id: %q\nname: X\nseverity: low\nrequest: {path: [/x]}\nmatch: {all: [{regex: x}]}\n", id)))
		if err != nil {
			t.Fatal(err)
		}
		got := NucleiTemplate(c, testOpts)
		if got.File != "" || got.Data != nil || !strings.Contains(got.Skipped, "can't name a file") {
			t.Errorf("%q: file %q, skipped %q", id, got.File, got.Skipped)
		}
		if strings.ContainsAny(got.DisplayID(), "\x1b") {
			t.Errorf("%q: display ID %q keeps a control byte", id, got.DisplayID())
		}
	}
	if got := (Template{CheckID: "leak-x"}).DisplayID(); got != "leak-x" {
		t.Errorf("valid ID shown as %q", got)
	}
}

func TestHeaderRegex(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\nX-Powered-By: PHP/8.2.1\r\nX-Empty:\r\n"
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"Server", `/\d`, true},
		{"server", `/\d`, true}, // names are case-insensitive
		{"Server", `^nginx`, true},
		{"Server", `^1\.27`, false}, // ^ is the start of the value
		{"Server", `NGINX`, false},  // values keep their case
		{"Server", `0$`, true},
		{"Server", `1$`, false},
		{"X-Powered-By", "", true},
		{"X-Empty", "", true},
		{"X-Missing", "", false},
	} {
		re := regexp.MustCompile(headerRegex(tc.name, tc.value))
		if got := re.MatchString(head); got != tc.want {
			t.Errorf("headerRegex(%q, %q) = %s: match %v, want %v", tc.name, tc.value, re, got, tc.want)
		}
	}
}

// idRule is the pattern Nuclei requires of template IDs.
var idRule = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)

var magicRule = regexp.MustCompile(`^starts_with\(hex_encode\(body\), "([0-9a-f]+)"\)$`)

// nucleiDoc is what the tests read back from an exported template.
type nucleiDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string         `yaml:"name"`
		Author      string         `yaml:"author"`
		Severity    string         `yaml:"severity"`
		Description string         `yaml:"description"`
		Remediation string         `yaml:"remediation"`
		Reference   []string       `yaml:"reference"`
		Tags        string         `yaml:"tags"`
		Metadata    map[string]any `yaml:"metadata"`
	} `yaml:"info"`
	HTTP []struct {
		Method            string          `yaml:"method"`
		Path              []string        `yaml:"path"`
		StopAtFirstMatch  bool            `yaml:"stop-at-first-match"`
		MatchersCondition string          `yaml:"matchers-condition"`
		Matchers          []nucleiMatcher `yaml:"matchers"`
	} `yaml:"http"`
}

// Every built-in check exports to a template with the fields Nuclei
// requires, or is skipped with a reason.
func TestNucleiBuiltInTemplates(t *testing.T) {
	all := builtIn(t)
	ts := Nuclei(all, testOpts)
	var written int
	for i, tmpl := range ts {
		c := all[i]
		if tmpl.Skipped != "" {
			continue
		}
		written++
		var d nucleiDoc
		dec := yaml.NewDecoder(bytes.NewReader(tmpl.Data))
		dec.KnownFields(true)
		if err := dec.Decode(&d); err != nil {
			t.Errorf("%s: %v", tmpl.File, err)
			continue
		}
		switch {
		case d.ID != "tuner-"+c.ID || !idRule.MatchString(d.ID):
			t.Errorf("%s: id %q", tmpl.File, d.ID)
		case d.Info.Name == "" || d.Info.Author == "" || !slices.Contains([]string{"info", "low", "medium", "high", "critical"}, d.Info.Severity):
			t.Errorf("%s: info %+v", tmpl.File, d.Info)
		case !strings.HasPrefix(d.Info.Tags, "tuner,") || d.Info.Metadata["tuner-id"] != c.ID:
			t.Errorf("%s: tags %q, metadata %v", tmpl.File, d.Info.Tags, d.Info.Metadata)
		case len(d.HTTP) != 1 || d.HTTP[0].Method != "GET" || d.HTTP[0].MatchersCondition != "and" || len(d.HTTP[0].Matchers) == 0:
			t.Errorf("%s: http %+v", tmpl.File, d.HTTP)
			continue
		}
		for _, p := range d.HTTP[0].Path {
			if !strings.HasPrefix(p, "{{BaseURL}}/") || strings.Contains(strings.NewReplacer("{{BaseURL}}", "", "{{Host}}", "").Replace(p), "{{") {
				t.Errorf("%s: path %q", tmpl.File, p)
			}
		}
		for _, m := range d.HTTP[0].Matchers {
			for _, re := range m.Regex {
				if _, err := regexp.Compile(re); err != nil {
					t.Errorf("%s: regex %q: %v", tmpl.File, re, err)
				}
			}
			for _, e := range m.DSL {
				if !magicRule.MatchString(e) {
					t.Errorf("%s: dsl %q", tmpl.File, e)
				}
			}
			if !slices.Contains([]string{"status", "word", "regex", "dsl"}, m.Type) {
				t.Errorf("%s: matcher type %q", tmpl.File, m.Type)
			}
		}
	}
	if written < len(all)*3/4 {
		t.Errorf("only %d of %d checks exported", written, len(all))
	}
}

// The exported matchers fire on each check's positive fixtures and stay
// quiet on its negative ones. Catch-all negatives are left out: they test
// the soft-404 comparison, which templates only approximate. So are
// negatives for a site without the technology a check requires, which
// templates don't look at.
func TestNucleiMatchesFixtures(t *testing.T) {
	all := builtIn(t)
	for _, c := range all {
		tmpl := NucleiTemplate(c, testOpts)
		if tmpl.Skipped != "" {
			continue
		}
		var d nucleiDoc
		if err := yaml.Unmarshal(tmpl.Data, &d); err != nil {
			t.Fatal(err)
		}
		data, err := fs.ReadFile(checks.FS, strings.TrimSuffix(c.File, ".yaml")+"_test.yaml")
		if err != nil {
			t.Fatal(err)
		}
		var fx checktest.File
		if err := yaml.Unmarshal(data, &fx); err != nil {
			t.Fatal(err)
		}
		for _, cs := range fx.Positive {
			if !fires(t, d.HTTP[0].Path, d.HTTP[0].Matchers, cs) {
				t.Errorf("%s: positive %q: template does not fire", tmpl.File, cs.Name)
			}
		}
		for _, cs := range fx.Negative {
			if cs.Default != nil || !hasTech(cs, c.Requires) {
				continue
			}
			if fires(t, d.HTTP[0].Path, d.HTTP[0].Matchers, cs) {
				t.Errorf("%s: negative %q: template fires", tmpl.File, cs.Name)
			}
		}
	}
}

// hasTech reports whether the fixture's home page shows every technology.
func hasTech(cs checktest.Case, tech []string) bool {
	if len(tech) == 0 {
		return true
	}
	status, header, body := reply(cs, "/")
	fp := fingerprint.Detect(&matchers.Response{Status: status, Header: header, Body: body})
	return !slices.ContainsFunc(tech, func(t string) bool { return !fp.Has(t) })
}

// reply is what the fixture server sends for uri, as checktest serves it.
func reply(cs checktest.Case, uri string) (int, http.Header, []byte) {
	r, ok := cs.Routes[uri]
	if !ok {
		path, _, _ := strings.Cut(uri, "?")
		r, ok = cs.Routes[path]
		if !ok && cs.Default != nil {
			r, ok = *cs.Default, true
			r.Body = strings.ReplaceAll(r.Body, "{{path}}", path)
		}
	}
	if !ok {
		return http.StatusNotFound, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte("404 page not found\n")
	}
	h := http.Header{}
	for k, v := range r.Headers {
		h.Set(k, v)
	}
	b, _ := hex.DecodeString(r.BodyHex)
	if r.Status == 0 {
		r.Status = http.StatusOK
	}
	return r.Status, h, append(b, r.Body...)
}

// fires evaluates the template the way Nuclei does: every matcher must
// hold (matchers-condition: and) on one of the paths; a matcher's list
// holds when any entry does unless its condition is and.
func fires(t *testing.T, paths []string, ms []nucleiMatcher, cs checktest.Case) bool {
	t.Helper()
	for _, p := range paths {
		uri := strings.NewReplacer("{{BaseURL}}", "", "{{Host}}", "127.0.0.1").Replace(p)
		status, header, body := reply(cs, uri)
		var head strings.Builder
		fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
		for _, k := range sortedKeys(flatten(header)) {
			fmt.Fprintf(&head, "%s: %s\r\n", k, header.Get(k))
		}
		if !slices.ContainsFunc(ms, func(m nucleiMatcher) bool { return !holds(t, m, status, head.String(), body) }) {
			return true
		}
	}
	return false
}

func flatten(h http.Header) map[string]string {
	m := map[string]string{}
	for k := range h {
		m[k] = h.Get(k)
	}
	return m
}

func holds(t *testing.T, m nucleiMatcher, status int, head string, body []byte) bool {
	part := string(body)
	if m.Part == "header" {
		part = head
	}
	var hits []bool
	switch m.Type {
	case "status":
		hits = []bool{slices.Contains(m.Status, status)}
	case "word":
		for _, w := range m.Words {
			hits = append(hits, strings.Contains(part, w))
		}
	case "regex":
		for _, re := range m.Regex {
			hits = append(hits, regexp.MustCompile(re).MatchString(part))
		}
	case "dsl":
		for _, e := range m.DSL {
			magic := magicRule.FindStringSubmatch(e)
			if magic == nil {
				t.Fatalf("dsl %q", e)
			}
			hits = append(hits, strings.HasPrefix(hex.EncodeToString(body), magic[1]))
		}
	default:
		t.Fatalf("matcher type %q", m.Type)
	}
	ok := slices.Contains(hits, true)
	if m.Condition == "and" {
		ok = !slices.Contains(hits, false)
	}
	return ok != m.Negative
}

func TestNucleiREADME(t *testing.T) {
	fsys := fstest.MapFS{
		"x/a.yaml": {Data: []byte("id: leak-a\nname: A\nseverity: low\nrequest: {path: [/a]}\nmatch: {all: [{regex: a}, {not_baseline: true}]}\n")},
		"x/b.yaml": {Data: []byte("id: tls-b\nname: B\nseverity: low\nrequest: {path: [/]}\nmatch: {all: [{tls: {expired: true}}]}\n")},
	}
	all, err := engine.LoadChecks(fsys)
	if err != nil {
		t.Fatal(err)
	}
	got := string(NucleiREADME(Nuclei(all, testOpts), testOpts, checks.License))
	for _, want := range []string{
		"1 template, generated by rhythm-tuner test",
		"Nuclei can't, so 1 template uses a negative matcher",
		"- `tls-b`: TLS conditions need a TLS probe",
		"https://github.com/RhythmShahriar/tuner/tree/master/checks",
		"MIT licensed",
		"Permission is hereby granted, free of charge",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("README lacks %q:\n%s", want, got)
		}
	}
}
