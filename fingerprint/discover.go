// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package fingerprint

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Discovery methods, as they appear in Component.FoundBy.
const (
	FoundByAsset  = "asset"  // an asset URL on the home page
	FoundByREST   = "rest"   // a namespace in the REST API index (/wp-json/)
	FoundByReadme = "readme" // a readme.txt probe (--plugins deep)
)

// Component confidence values.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// Data is what plugin discovery knows about plugins beyond the site
// itself. The binary embeds a copy (Embedded); a check pack may ship a
// newer one (LoadData).
type Data interface {
	// RESTNamespaces maps a REST namespace, or its leading segments, to
	// the slug of the plugin that registers it, e.g. "wc" to woocommerce.
	// These are known from the plugin's code and give high confidence.
	RESTNamespaces() map[string]string
	// InferredNamespaces has the same shape for mappings nobody checked
	// against a real /wp-json/ index, or that a free plugin shares with its
	// premium edition. They give low confidence, so a wrong guess never
	// reads as a confirmed vulnerable plugin.
	InferredNamespaces() map[string]string
	// TopPlugins lists popular plugin slugs, most installed first.
	TopPlugins() []string
}

//go:embed data/rest-namespaces.json data/top-plugins.json
var embedded embed.FS

// Embedded returns the discovery data built into the binary.
var Embedded = sync.OnceValue(func() Data {
	d, err := LoadData(embedded)
	if err != nil {
		panic(err) // the files are part of the build; tests catch a bad edit
	}
	return d
})

// LoadData reads data/rest-namespaces.json and data/top-plugins.json from
// fsys, the layout of this package and of a check pack.
func LoadData(fsys fs.FS) (Data, error) {
	var ns struct {
		Namespaces map[string]string `json:"namespaces"`
		Inferred   map[string]string `json:"inferred"`
	}
	var top struct {
		Plugins []string `json:"plugins"`
	}
	for name, v := range map[string]any{"data/rest-namespaces.json": &ns, "data/top-plugins.json": &top} {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	d := &staticData{ns: map[string]string{}, inferred: map[string]string{}}
	for from, to := range map[*map[string]string]map[string]string{&ns.Namespaces: d.ns, &ns.Inferred: d.inferred} {
		for k, slug := range *from {
			if !ValidSlug(slug) {
				return nil, fmt.Errorf("data/rest-namespaces.json: %q is not a plugin slug", slug)
			}
			to[strings.ToLower(strings.Trim(k, "/"))] = slug
		}
	}
	for _, slug := range top.Plugins {
		if !ValidSlug(slug) {
			return nil, fmt.Errorf("data/top-plugins.json: %q is not a plugin slug", slug)
		}
		d.top = append(d.top, slug)
	}
	return d, nil
}

type staticData struct {
	ns, inferred map[string]string
	top          []string
}

func (d *staticData) RESTNamespaces() map[string]string     { return d.ns }
func (d *staticData) InferredNamespaces() map[string]string { return d.inferred }
func (d *staticData) TopPlugins() []string                  { return d.top }

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ValidSlug reports whether s is a plugin slug wordpress.org could issue.
// Slugs end up in request paths, so nothing else may get through.
func ValidSlug(s string) bool { return len(s) <= 200 && slugRe.MatchString(s) }

// The REST index lists namespaces before its (much longer) routes, so the
// array survives a body cut at the engine's read limit.
var namespacesRe = regexp.MustCompile(`"namespaces"\s*:\s*(\[[^\]]*\])`)

// RESTNamespaces returns the namespaces in a /wp-json/ index body, or nil
// when the body is not one.
func RESTNamespaces(body []byte) []string {
	m := namespacesRe.FindSubmatch(body)
	if m == nil {
		return nil
	}
	var out []string
	if json.Unmarshal(m[1], &out) != nil {
		return nil
	}
	return out
}

// Namespaces WordPress core registers; they say nothing about plugins.
var coreNamespaces = []string{"wp", "oembed", "wp-site-health", "wp-block-editor", "wp-abilities"}

// PluginsFromREST maps REST namespaces to plugins. A namespace is matched
// on its longest known leading segments: one in d.RESTNamespaces gives a
// high-confidence plugin, one in d.InferredNamespaces a low-confidence
// one. A namespace whose first segment is a popular plugin's slug also
// gives a low-confidence plugin: plugins often name their namespace after
// their slug but nothing guarantees it.
func PluginsFromREST(d Data, namespaces []string) []Component {
	known, inferred := d.RESTNamespaces(), d.InferredNamespaces()
	top := d.TopPlugins()
	var out []Component
	add := func(slug, confidence string) {
		if i := slices.IndexFunc(out, func(c Component) bool { return c.Slug == slug }); i >= 0 {
			if confidence == ConfidenceHigh {
				out[i].Confidence = ConfidenceHigh
			}
			return
		}
		out = append(out, Component{Type: "plugin", Slug: slug, FoundBy: FoundByREST, Confidence: confidence})
	}
	for _, ns := range namespaces {
		parts := strings.Split(strings.ToLower(strings.Trim(ns, "/")), "/")
		if parts[0] == "" || slices.Contains(coreNamespaces, parts[0]) {
			continue
		}
		slug, confidence := "", ""
		for n := len(parts); n > 0 && slug == ""; n-- {
			key := strings.Join(parts[:n], "/")
			if slug = known[key]; slug != "" {
				confidence = ConfidenceHigh
			} else if slug = inferred[key]; slug != "" {
				confidence = ConfidenceLow
			}
		}
		switch {
		case slug != "":
			add(slug, confidence)
		case slices.Contains(top, parts[0]):
			add(parts[0], ConfidenceLow)
		}
	}
	return out
}

var (
	readmeHeader = regexp.MustCompile(`(?m)^[ \t]*===[ \t]*\S.*===[ \t]*\r?$`)
	readmeField  = regexp.MustCompile(`(?mi)^[ \t]*(?:Stable tag|Requires at least|Tested up to|Contributors):`)
)

// IsReadme reports whether body looks like a WordPress plugin readme.txt:
// a "=== Plugin Name ===" line and one of its header fields, such as
// "Stable tag:".
func IsReadme(body []byte) bool {
	return readmeHeader.Match(body) && readmeField.Match(body)
}

// AddComponent adds c to the result, or merges it into the plugin or
// theme already there: discovery methods are combined, the higher
// confidence wins and a version is kept once known.
func (r *Result) AddComponent(c Component) {
	i := slices.IndexFunc(r.Components, func(x Component) bool { return x.Type == c.Type && x.Slug == c.Slug })
	if i < 0 {
		r.Components = append(r.Components, c)
		return
	}
	have := &r.Components[i]
	for _, m := range c.FoundBy.List() {
		have.FoundBy = have.FoundBy.With(m)
	}
	if c.Confidence == ConfidenceHigh || have.Confidence == "" {
		have.Confidence = c.Confidence
	}
	if have.Version == "" && c.Version != "" {
		have.Version, have.Source = c.Version, c.Source
	}
}
