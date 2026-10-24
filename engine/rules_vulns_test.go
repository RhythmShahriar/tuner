// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

// The vulns, osv and local packages register their rules from init().
// They import engine, so engine's own tests can't load them. These
// stand in with the same IDs and tags.
func init() {
	RegisterRules("test-vulns",
		Rule{ID: "vuln-plugin-", Prefix: true, Title: "Plugin with known vulnerabilities", Tags: []string{"vuln", "wordpress", "plugin", "known-exploited"}, Severity: High},
		Rule{ID: "vuln-core", Title: "WordPress core with known vulnerabilities", Tags: []string{"vuln", "wordpress", "core"}, Severity: High},
		Rule{ID: "wp-core-outdated", Title: "WordPress core out of date", Tags: []string{"wordpress", "core", "outdated"}, Severity: Low},
		Rule{ID: "wp-components-outdated", Title: "Plugins or themes out of date", Tags: []string{"wordpress", "plugin", "theme", "outdated"}, Severity: Low},
		Rule{ID: "php-eol", Title: "PHP branch past end of life", Tags: []string{"php", "outdated"}, Severity: High},
		Rule{ID: "php-version-hidden", Title: "PHP version hidden while recent critical flaws are out", Tags: []string{"php"}, Severity: Medium},
		Rule{ID: "local-", Prefix: true, Title: "Local scan finding", Tags: []string{"local"}, Severity: Medium},
	)
}
