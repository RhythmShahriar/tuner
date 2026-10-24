// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"archive/tar"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func extras(data, local map[string]string) Extras {
	x := Extras{}
	if data != nil {
		m := fstest.MapFS{}
		for name, v := range data {
			m[name] = &fstest.MapFile{Data: []byte(v)}
		}
		x.Data = m
	}
	if local != nil {
		m := fstest.MapFS{}
		for name, v := range local {
			m[name] = &fstest.MapFile{Data: []byte(v)}
		}
		x.Local = m
	}
	return x
}

func TestPackCarriesDataAndLocalRules(t *testing.T) {
	b, err := BuildWith(source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), extras(
		map[string]string{"rest-namespaces.json": `{"acme/v1": "acme-forms"}`, "notes.txt": "skipped"},
		map[string]string{"stray-php.yaml": "id: local-stray-php\n", "stray-php_test.yaml": "positive: []\n"},
	), "abc1234def", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Manifest.Data) != 1 || b.Manifest.Data[0] != "rest-namespaces.json" || b.Manifest.Local != 1 || b.Manifest.Checks != 1 {
		t.Errorf("manifest = %+v", b.Manifest)
	}
	b.Sign(testKey)
	p, err := newRelease(t, b.Files).client(t.TempDir()).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := p.Data("rest-namespaces.json"); !ok || !strings.Contains(string(data), "acme-forms") {
		t.Errorf("Data = %q, %v", data, ok)
	}
	for _, name := range []string{"missing.json", "../pack.json", "notes.txt"} {
		if _, ok := p.Data(name); ok {
			t.Errorf("Data(%q) found", name)
		}
	}
	rules := p.LocalRules()
	if rules == nil {
		t.Fatal("no local rules")
	}
	if names, _ := fs.Glob(rules, "*"); len(names) != 1 || names[0] != "stray-php.yaml" {
		t.Errorf("local rules = %v", names)
	}

	// A pack without either falls back to the binary's copies.
	plain, err := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)).client(t.TempDir()).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.Data("rest-namespaces.json"); ok || plain.LocalRules() != nil {
		t.Error("plain pack claims data or rules")
	}
	var none *Pack
	if _, ok := none.Data("x.json"); ok || none.LocalRules() != nil {
		t.Error("nil pack claims data or rules")
	}
}

func TestBuildRejectsBadExtras(t *testing.T) {
	big := `{"x": "` + strings.Repeat("a", maxDataFile) + `"}`
	for name, tc := range map[string]struct {
		src  fstest.MapFS
		x    Extras
		want string
	}{
		"oversized data": {nil, extras(map[string]string{"top-plugins.json": big}, nil), "data/top-plugins.json: larger than 512 KB"},
		"invalid json":   {nil, extras(map[string]string{"a.json": "{"}, nil), "data/a.json: not valid JSON"},
		"bad data name":  {nil, extras(map[string]string{"Top Plugins.json": "{}"}, nil), "data files are <name>.json"},
		"oversized rule": {nil, extras(nil, map[string]string{"r.yaml": strings.Repeat("#", maxLocalFile+1)}), "local/r.yaml: larger than 256 KB"},
		"reserved dir":   {source("0.2.0", map[string]string{"data/x.yaml": goodCheck}), Extras{}, "the data/ folder is reserved"},
	} {
		t.Run(name, func(t *testing.T) {
			src := tc.src
			if src == nil {
				src = source("0.2.0", map[string]string{"a/x.yaml": goodCheck})
			}
			_, err := BuildWith(src, tc.x, "abc", t0)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A pack built by hand past the build checks is still refused when it is
// unpacked.
func TestExtractRejectsBadExtras(t *testing.T) {
	check := entry{name: "a/x.yaml", typ: tar.TypeReg, data: goodCheck}
	many := []entry{check}
	for i := range maxDataFiles + 1 {
		many = append(many, entry{name: "data/d" + strings.Repeat("x", i) + ".json", typ: tar.TypeReg, data: "{}"})
	}
	for name, tc := range map[string]struct {
		archive []byte
		want    string
	}{
		"oversized data": {tarGz(t, check, entry{name: "data/rest-namespaces.json", typ: tar.TypeReg, data: `"` + strings.Repeat("a", maxDataFile) + `"`}), "larger than 512 KB"},
		"nested data":    {tarGz(t, check, entry{name: "data/sub/a.json", typ: tar.TypeReg, data: "{}"}), "directly under data/"},
		"invalid json":   {tarGz(t, check, entry{name: "data/a.json", typ: tar.TypeReg, data: "nope"}), "not valid JSON"},
		"too many data":  {tarGz(t, many...), "data/: 33 files, at most 32"},
		"nested rule":    {tarGz(t, check, entry{name: "local/x/r.yaml", typ: tar.TypeReg, data: "id: r"}), "directly under local/"},
	} {
		t.Run(name, func(t *testing.T) {
			files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
			files[ArchiveName] = tc.archive
			_, err := newRelease(t, withSums(files)).client(t.TempDir()).Get(context.Background())
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want rejection with %q", err, tc.want)
			}
		})
	}
}

// Local rules are YAML too, but never loaded as checks.
func TestLocalRulesAreNotChecks(t *testing.T) {
	b, err := BuildWith(source("0.2.0", map[string]string{"a/x.yaml": goodCheck}),
		extras(nil, map[string]string{"r.yaml": "id: local-r\nfiles: ['*.php']\n"}), "abc", t0)
	if err != nil {
		t.Fatal(err)
	}
	_, loaded, err := Open(b.Manifest, b.Files[ArchiveName], "dev")
	if err != nil || len(loaded) != 1 || loaded[0].ID != "pack-test" {
		t.Errorf("loaded %v, %v", loaded, err)
	}
}
