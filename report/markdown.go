// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// Markdown writes reports for pasting into issues and pull requests.
func Markdown(w io.Writer, reports []Report) error {
	var b strings.Builder
	for i, r := range reports {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&b, "# Tuner report: %s\n\n", r.Target)
		fmt.Fprintf(&b, "**Tune score %d/100** · %s · %d checks · %d requests · rhythm-tuner %s\n\n",
			r.Score, r.Fingerprint, r.Checks, r.Requests, r.Version)

		if len(r.Fingerprint.Components) > 0 {
			b.WriteString("<details><summary>Plugins and themes</summary>\n\n| Type | Slug | Version | Source |\n|---|---|---|---|\n")
			for _, c := range r.Fingerprint.Components {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.Type, c.Slug, or(c.Version, "unknown"), c.Source)
			}
			b.WriteString("\n</details>\n\n")
		}

		if len(r.Findings) == 0 {
			b.WriteString("✅ Nothing out of tune.\n")
			continue
		}
		b.WriteString("| Severity | Finding | Path |\n|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s | %s | `%s` |\n", strings.ToUpper(string(f.Severity)), mdEscape(f.Title), f.Path)
		}
		b.WriteString("\n## Details\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "\n### %s %s\n\n", sevEmoji(f.Severity), mdEscape(f.Title))
			fmt.Fprintf(&b, "- **Check:** `%s` · **Severity:** %s · **Confidence:** %s\n", f.ID, f.Severity, f.Confidence)
			if f.Confidence == "low" && f.Caveat != "" {
				fmt.Fprintf(&b, "- **Why only likely:** %s\n", strings.TrimPrefix(f.Caveat, "likely: "))
			}
			if f.Evidence.Status != 0 {
				fmt.Fprintf(&b, "- **Request:** `%s` → %d\n", f.Evidence.Request, f.Evidence.Status)
			}
			for _, m := range f.Evidence.Matched[:matchedLimit(f)] {
				fmt.Fprintf(&b, "- **Evidence:** `%s`\n", strings.ReplaceAll(m, "`", "'"))
			}
			for _, s := range f.Evidence.Secrets {
				fmt.Fprintf(&b, "- **Secret (masked):** `%s`\n", s)
			}
			if f.Impact != "" {
				fmt.Fprintf(&b, "\n%s\n", f.Impact)
			}
			if len(f.Advisories) > 0 {
				b.WriteString("\n| Severity | CVE | Advisory | Fixed in |\n|---|---|---|---|\n")
				for _, a := range f.Advisories {
					cve := strings.Join(a.CVEs, ", ")
					title := mdEscape(a.Title)
					if a.KEV {
						title += " ⚠️ actively exploited"
					}
					if len(a.References) > 0 {
						title = "[" + title + "](" + a.References[len(a.References)-1] + ")"
					}
					fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", or(string(a.Severity), "unrated"), or(cve, "—"), title, or(a.FixedIn, "—"))
				}
			}
			if f.Source != "" {
				fmt.Fprintf(&b, "\n_Data: %s_\n", f.Source)
			}
			if f.Fix != "" {
				fmt.Fprintf(&b, "\n**Fix**\n\n```\n%s\n```\n", f.Fix)
			}
			for _, ref := range f.References {
				fmt.Fprintf(&b, "\n- %s", ref)
			}
			if len(f.References) > 0 {
				b.WriteString("\n")
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func sevEmoji(s engine.Severity) string {
	switch s {
	case engine.Critical:
		return "🔴"
	case engine.High:
		return "🟠"
	case engine.Medium:
		return "🟡"
	case engine.Low:
		return "🔵"
	}
	return "⚪"
}

func mdEscape(s string) string { return strings.NewReplacer("|", "\\|", "<", "&lt;").Replace(s) }

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// Advisory findings get a table instead of evidence lines.
func matchedLimit(f engine.Finding) int {
	if len(f.Advisories) > 0 {
		return 0
	}
	return len(f.Evidence.Matched)
}
