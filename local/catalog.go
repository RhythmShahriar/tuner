// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// HelpBase is where each local finding is explained: the Finding
// Reference page of the wiki, one anchor per ID.
const HelpBase = "https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Finding-Reference#"

// Confidence values for findings, until engine has typed constants.
const (
	confidenceHigh = "high"
	confidenceLow  = "low"
)

// RuleInfo describes one finding ID local scans report, so selection,
// listings and SARIF know it without running a scan. Its fields match
// engine.Rule, so registering the catalog is a conversion.
type RuleInfo struct {
	ID       string
	Prefix   bool // ID is a prefix of the reported IDs (none are, today)
	Title    string
	Tags     []string        // every tag its findings can carry, "local" included
	Severity engine.Severity // the most severe its findings can be
	HelpURI  string
}

// goRules are the checks written in Go. Titles with a variable part
// (a plugin slug, a count) are written generically.
var goRules = []RuleInfo{
	{ID: "local-vcs-dir", Title: "Version control folder in the web root", Severity: engine.Medium, Tags: []string{"leak", "source"}},
	{ID: "local-db-admin", Title: "Database admin tool in the web root", Severity: engine.Medium, Tags: []string{"php", "database", "admin"}},
	{ID: "local-backup-archive", Title: "Backup archive in the web root", Severity: engine.High, Tags: []string{"leak", "backup"}},
	{ID: "local-composer-auth", Title: "Composer auth.json in the web root", Severity: engine.High, Tags: []string{"leak", "secrets"}},

	{ID: "local-wp-salts", Title: "WordPress keys and salts are not set", Severity: engine.Medium, Tags: []string{"wordpress", "config"}},
	{ID: "local-wp-debug", Title: "WordPress debug mode is on", Severity: engine.Medium, Tags: []string{"wordpress", "config", "disclosure"}},
	{ID: "local-wp-file-edit", Title: "The dashboard file editor is enabled", Severity: engine.Low, Tags: []string{"wordpress", "config", "hardening"}},
	{ID: "local-wp-table-prefix", Title: "Database tables use the default wp_ prefix", Severity: engine.Info, Tags: []string{"wordpress", "config", "hardening"}},
	{ID: "local-wp-force-ssl-admin", Title: "FORCE_SSL_ADMIN is not set", Severity: engine.Info, Tags: []string{"wordpress", "config", "hardening"}},
	{ID: "local-wp-config-perms", Title: "wp-config.php is readable by every user on the server", Severity: engine.Low, Tags: []string{"wordpress", "config", "permissions"}},
	{ID: "local-wp-mu-plugins", Title: "Must-use plugins installed", Severity: engine.Info, Tags: []string{"wordpress"}},

	{ID: "local-laravel-debug", Title: "Laravel debug mode is on", Severity: engine.Medium, Tags: []string{"laravel", "config", "disclosure"}},

	{ID: sessionCheckID, Title: sessionCVE + " PHP session upload progress", Severity: engine.High, Tags: []string{"php", "session", "vuln", strings.ToLower(sessionCVE)}},

	{ID: "local-integrity-core-modified", Title: "Modified WordPress core file", Severity: engine.Critical, Tags: []string{"integrity", "wordpress", "malware"}},
	{ID: "local-integrity-core-unknown", Title: "Unexpected PHP file in WordPress core", Severity: engine.High, Tags: []string{"integrity", "wordpress", "malware"}},
	{ID: "local-integrity-core-missing", Title: "WordPress core files missing", Severity: engine.Low, Tags: []string{"integrity", "wordpress"}},
	{ID: "local-integrity-plugin-modified", Title: "Modified file in a wordpress.org plugin", Severity: engine.High, Tags: []string{"integrity", "wordpress", "malware"}},
	{ID: "local-integrity-plugin-unknown", Title: "Unexpected PHP file in a wordpress.org plugin", Severity: engine.Medium, Tags: []string{"integrity", "wordpress", "malware"}},
	{ID: "local-integrity-plugin-unchecked", Title: "Plugins not on wordpress.org weren't compared", Severity: engine.Info, Tags: []string{"integrity", "wordpress"}},
	{ID: "local-integrity-plugin-unlisted", Title: "wordpress.org plugin at a version it never released", Severity: engine.Medium, Tags: []string{"integrity", "wordpress", "malware"}},
}

// Catalog lists every finding ID local scans report: the Go checks and
// the built-in rules, sorted by ID. An ID used by both (local-db-admin:
// phpMyAdmin in Go, Adminer as a rule) is listed once, with the tags of
// both and the higher severity.
func Catalog() []RuleInfo {
	byID := map[string]*RuleInfo{}
	add := func(r RuleInfo) {
		r.Tags = append([]string{"local"}, r.Tags...)
		if prev := byID[r.ID]; prev != nil {
			for _, t := range r.Tags {
				if !slices.Contains(prev.Tags, t) {
					prev.Tags = append(prev.Tags, t)
				}
			}
			if r.Severity.Rank() < prev.Severity.Rank() {
				prev.Severity = r.Severity
			}
			return
		}
		r.Tags = slices.Clone(r.Tags)
		r.HelpURI = HelpBase + r.ID
		byID[r.ID] = &r
	}
	for _, r := range goRules {
		add(r)
	}
	for _, r := range BuiltinRules() {
		add(r.info())
	}
	out := make([]RuleInfo, 0, len(byID))
	for _, r := range byID {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b RuleInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// info describes a rule for the catalog.
func (r *Rule) info() RuleInfo {
	sev := r.Severity
	if r.Extract.Severity != "" && r.Extract.Severity.Rank() < sev.Rank() {
		sev = r.Extract.Severity
	}
	return RuleInfo{
		ID:       r.ID,
		Title:    strings.ReplaceAll(r.Name, "{file}", fileLabel(r.Files)),
		Tags:     slices.Clone(r.Tags),
		Severity: sev,
	}
}

// fileLabel stands in for {file} in a catalog title: the name of the
// rule's first file glob when it has no wildcard (".env" for **/.env),
// else "A".
func fileLabel(globs []string) string {
	if len(globs) > 0 {
		if b := path.Base(globs[0]); !strings.ContainsAny(b, "*?[") {
			return b
		}
	}
	return "A"
}
