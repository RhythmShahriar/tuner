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
	return Write("md", w, reports, WriteOptions{})
}

func writeMarkdown(w io.Writer, reports []Report, o WriteOptions) error {
	var b strings.Builder
	for i, r := range reports {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&b, "# Tuner report: %s\n\n", MDText(r.Target))
		fmt.Fprintf(&b, "**Tune score %d/100** · %s · %d checks · %d requests · rhythm-tuner %s\n\n",
			r.Score, MDText(r.Fingerprint.String()), r.Checks, r.Requests, MDText(r.Version))

		if len(r.Fingerprint.Components) > 0 {
			b.WriteString("<details><summary>Plugins and themes</summary>\n\n| Type | Slug | Version | Source |\n|---|---|---|---|\n")
			for _, c := range r.Fingerprint.Components {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", MDText(c.Type), MDText(c.Slug), MDText(or(c.Version, "unknown")), MDText(c.Source))
			}
			b.WriteString("\n</details>\n\n")
		}

		if len(r.Findings) == 0 {
			b.WriteString("✅ Nothing out of tune.\n")
			continue
		}
		b.WriteString("| Severity | Finding | Path |\n|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", MDText(strings.ToUpper(string(f.Severity))), MDText(f.Title), MDCode(f.Path))
		}
		b.WriteString("\n## Details\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "\n### %s %s\n\n", sevEmoji(f.Severity), MDText(f.Title))
			fmt.Fprintf(&b, "- **Check:** %s · **Severity:** %s · **Confidence:** %s\n", MDCode(f.ID), MDText(string(f.Severity)), MDText(f.Confidence))
			if f.Confidence == "low" && f.Caveat != "" {
				fmt.Fprintf(&b, "- **Why only likely:** %s\n", MDText(strings.TrimPrefix(f.Caveat, "likely: ")))
			}
			if f.Evidence.Status != 0 {
				fmt.Fprintf(&b, "- **Request:** %s → %d\n", MDCode(f.Evidence.Request), f.Evidence.Status)
			}
			for _, m := range f.Evidence.Matched[:matchedLimit(f)] {
				fmt.Fprintf(&b, "- **Evidence:** %s\n", MDCode(m))
			}
			for _, s := range f.Evidence.Secrets {
				fmt.Fprintf(&b, "- **Secret (masked):** %s\n", MDCode(s.String()))
			}
			if f.Impact != "" {
				fmt.Fprintf(&b, "\n%s\n", MDText(f.Impact))
			}
			if len(f.Advisories) > 0 {
				b.WriteString("\n| Severity | CVE | Advisory | Fixed in |\n|---|---|---|---|\n")
				for _, a := range f.Advisories {
					cve := strings.Join(a.CVEs, ", ")
					title := MDText(a.Title)
					if len(a.References) > 0 {
						title = SafeLink(a.Title, a.References[len(a.References)-1])
					}
					if a.KEV {
						title += " ⚠️ actively exploited"
					}
					fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", MDText(or(string(a.Severity), "unrated")), MDText(or(cve, "—")), title, MDText(or(a.FixedIn, "—")))
				}
			}
			if f.Source != "" {
				fmt.Fprintf(&b, "\n_Data: %s_\n", MDText(f.Source))
			}
			if f.Fix != "" {
				fmt.Fprintf(&b, "\n**Fix**\n\n%s\n", mdFence(f.Fix))
			}
			for _, ref := range f.References {
				fmt.Fprintf(&b, "\n- %s", SafeLink(ref, ref))
			}
			if len(f.References) > 0 {
				b.WriteString("\n")
			}
		}
	}
	if len(o.Failed) > 0 {
		if len(reports) > 0 {
			b.WriteString("\n---\n\n")
		}
		b.WriteString("# Not scanned\n\n| Target | Error |\n|---|---|\n")
		for _, f := range o.Failed {
			fmt.Fprintf(&b, "| %s | %s |\n", MDText(f.Target), MDText(f.Error))
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
