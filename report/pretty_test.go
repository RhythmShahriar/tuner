// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/tuner/engine"
)

// Plain output (logs, CI, screen readers) must not present a
// low-confidence finding as confirmed.
func TestPlainShowsLikely(t *testing.T) {
	var buf bytes.Buffer
	p := NewPretty(&buf, &buf, PrettyOptions{Plain: true})
	p.Finding(engine.Finding{Severity: engine.High, Title: "Apache 2.4.57: 3 known vulnerabilities", URL: "https://yoursite.com/",
		Confidence: "low", Caveat: "likely: a distro build may already include the fix"})
	p.Finding(engine.Finding{Severity: engine.Critical, Title: ".env file exposed", URL: "https://yoursite.com/.env", Confidence: "high"})
	out := buf.String()
	for _, want := range []string{"[HIGH, likely] Apache", "  likely: a distro build may already include the fix", "[CRITICAL] .env file exposed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// longURL is wider than any card, so it shows whether the view cuts it.
const longURL = "https://api.wordpress.org/secret-key/1.1/salt/?a-very-long-query-that-keeps-going-past-the-edge"

// viewResult is a scan with one finding of every kind the view draws
// differently, local and remote.
func viewResult() *engine.Result {
	return &engine.Result{
		Target: "https://a.test", Score: 12, Checks: 40, Requests: 61,
		Findings: []engine.Finding{
			{ID: "local-wp-debug", Title: "WordPress debug mode is on", Severity: engine.Medium, Confidence: "high",
				Target: "/tmp/ci/wp", URL: "file:///tmp/ci/wp/wp-config.php", Path: "/wp-config.php",
				Fix: "Turn off WP_DEBUG_LOG on production or point it outside the web root:\n\n    define( 'WP_DEBUG_LOG', false );"},
			{ID: "xmlrpc", Title: "XML-RPC enabled", Severity: engine.Low, Confidence: "high",
				URL: "https://a.test/xmlrpc.php", Path: "/xmlrpc.php", Fix: "Block xmlrpc.php in the server config."},
			{ID: "leak-dotenv", Title: ".env file exposed", Severity: engine.Critical, Confidence: "high",
				URL: "https://a.test/.env", Path: "/.env", Evidence: engine.Evidence{Status: 200, Matched: []string{"DB_PASSWORD=..."}},
				Fix: "Move it above the web root, or block dotfiles in the server config, then rotate every secret in it."},
			{ID: "local-wp-salts", Title: "Keys and salts are the sample placeholders", Severity: engine.High, Confidence: "high",
				Target: "/tmp/ci/wp", URL: "file:///tmp/ci/wp/wp-config.php", Path: "/wp-config.php",
				Fix: "Generate fresh keys at " + longURL + " and paste them into wp-config.php."},
			{ID: "vuln-php", Title: "PHP 8.1.2: 3 known vulnerabilities", Severity: engine.High, Confidence: "low",
				Caveat: "a distro build may already include the fix", URL: "https://a.test/", Path: "/",
				Advisories: []engine.Advisory{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}},
				Evidence:   engine.Evidence{Matched: []string{"HIGH CVE-2024-1 one", "HIGH CVE-2024-2 two", "MEDIUM CVE-2024-3 three"}},
				Fix:        "Upgrade PHP to a supported release."},
			{ID: "hdr-referrer-policy-missing", Title: "No Referrer-Policy header", Severity: engine.Info, Confidence: "high",
				URL: "https://a.test/", Path: "/"},
		},
	}
}

func ascii(t *testing.T) {
	t.Helper()
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.Ascii)
	t.Cleanup(func() { lipgloss.SetColorProfile(old) })
}

// render runs a whole scan through the view: the streamed findings, then
// the summary.
func render(o PrettyOptions, res *engine.Result, suppressed int) string {
	var b bytes.Buffer
	p := NewPretty(&b, &b, o)
	for _, f := range res.Findings {
		p.Finding(f)
	}
	p.Summary(res, res.Target, suppressed)
	return b.String()
}

func TestViewGolden(t *testing.T) {
	ascii(t)
	for _, cols := range []int{80, 120} {
		for _, plain := range []bool{false, true} {
			mode := map[bool]string{false: "tty", true: "plain"}[plain]
			name := fmt.Sprintf("view-%s-%d.golden", mode, cols)
			out := render(PrettyOptions{Plain: plain, Columns: cols}, viewResult(), 0)
			golden(t, name, out)
			if !strings.Contains(out, longURL) {
				t.Errorf("%s: the long URL was cut:\n%s", name, out)
			}
			if strings.Contains(out, "file://") {
				t.Errorf("%s: local findings should show paths, not file:// URLs:\n%s", name, out)
			}
		}
	}
}

// Every piece of the color view, at both widths, in one file each.
func TestPartsGolden(t *testing.T) {
	ascii(t)
	res := viewResult()
	for _, cols := range []int{80, 120} {
		w := contentWidth(cols, nil)
		var b strings.Builder
		b.WriteString(section(engine.High, 2, w) + "\n")
		for _, f := range res.Findings {
			if f.Severity.Rank() <= engine.Medium.Rank() {
				b.WriteString(card(f, w) + "\n")
			} else {
				b.WriteString(compact(f, w) + "\n")
			}
		}
		b.WriteString(scorePanel(100, 0, map[engine.Severity]int{}, w) + "\n")
		b.WriteString(scorePanel(42, 0, map[engine.Severity]int{engine.High: 1, engine.Low: 3}, w) + "\n")
		b.WriteString(scorePanel(100, 15, map[engine.Severity]int{}, w) + "\n")
		golden(t, fmt.Sprintf("parts-%d.golden", cols), b.String())
	}
}

func TestPlainPrintsEveryFix(t *testing.T) {
	out := render(PrettyOptions{Plain: true}, viewResult(), 0)
	for _, want := range []string{
		// medium and low get fixes too; a multi-line fix says there is more
		"  fix: Turn off WP_DEBUG_LOG on production or point it outside the web root (see report)\n",
		"  fix: Block xmlrpc.php in the server config.\n",
		"[MEDIUM] WordPress debug mode is on - /wp-config.php\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The block after the stream is sorted, most severe first.
	_, block, ok := strings.Cut(out, "Findings by severity:\n")
	if !ok {
		t.Fatalf("no sorted block:\n%s", out)
	}
	var sevs []int
	for l := range strings.Lines(block) {
		if sev, _, ok := strings.Cut(strings.TrimPrefix(l, "["), "]"); ok && strings.HasPrefix(l, "[") {
			sev, _, _ = strings.Cut(sev, ",")
			sevs = append(sevs, engine.Severity(strings.ToLower(sev)).Rank())
		}
	}
	if len(sevs) != len(viewResult().Findings) || !slices.IsSorted(sevs) {
		t.Errorf("sorted block out of order (%v):\n%s", sevs, block)
	}
}

func TestQuietKeepsOneLineSummary(t *testing.T) {
	ascii(t)
	for _, plain := range []bool{true, false} {
		out := render(PrettyOptions{Plain: plain, Quiet: true}, viewResult(), 0)
		if !strings.Contains(out, "\nScore 12/100 - 1 critical, 2 high, 1 medium, 1 low, 1 info - 40 checks, 61 requests, 0s\n") {
			t.Errorf("plain=%v: -q lost the summary line:\n%s", plain, out)
		}
		if strings.Contains(out, "Findings by severity") || strings.Contains(out, "TUNE SCORE") || strings.Contains(out, "full report") {
			t.Errorf("plain=%v: -q printed more than one summary line:\n%s", plain, out)
		}
	}
}

func TestBaselinedScoreSaysSo(t *testing.T) {
	ascii(t)
	clean := &engine.Result{Target: "https://a.test", Score: 100, Checks: 40}
	plain := render(PrettyOptions{Plain: true}, clean, 15)
	if !strings.Contains(plain, "Score 100/100 after baseline (15 hidden) - no findings - 40 checks, 0s\n") {
		t.Errorf("plain:\n%s", plain)
	}
	tty := render(PrettyOptions{}, clean, 15)
	if !strings.Contains(tty, "100 / 100 after baseline (15 hidden)") || strings.Contains(tty, "baselined") {
		t.Errorf("tty:\n%s", tty)
	}
}

func TestWrapKeepsLongWords(t *testing.T) {
	got := wrap("see "+longURL+" now", 20)
	want := []string{"see", longURL, "now"}
	if !slices.Equal(got, want) {
		t.Errorf("wrap = %q, want %q", got, want)
	}
	if got := wrap("a b c", 3); !slices.Equal(got, []string{"a b", "c"}) {
		t.Errorf("wrap = %q", got)
	}
}

func TestContentWidth(t *testing.T) {
	for cols, want := range map[int]int{0: 72, 40: minWidth, 80: 72, 120: maxWidth, 300: maxWidth} {
		if got := contentWidth(cols, io.Discard); got != want {
			t.Errorf("contentWidth(%d) = %d, want %d", cols, got, want)
		}
	}
}

// The explain hint shows only when a fix was cut short and names Tuner
// as it was started.
func TestExplainHint(t *testing.T) {
	long := engine.Finding{ID: "x", Title: "X", Severity: engine.High, Fix: "Do this:\n\n    block it"}
	short := engine.Finding{ID: "y", Title: "Y", Severity: engine.High, Fix: "Block it."}
	for _, plain := range []bool{true, false} {
		for _, c := range []struct {
			f    engine.Finding
			want bool
		}{{long, true}, {short, false}} {
			var b bytes.Buffer
			p := NewPretty(&b, &b, PrettyOptions{Plain: plain, Columns: 80, Command: "rhythm-tuner"})
			p.Finding(c.f)
			p.Summary(&engine.Result{Findings: []engine.Finding{c.f}, Score: 80}, "https://a.test", 0)
			if got := strings.Contains(b.String(), "run rhythm-tuner explain <id> for the full fix"); got != c.want {
				t.Errorf("plain %v, fix %q: hint %v, want %v\n%s", plain, c.f.Fix, got, c.want, b.String())
			}
			if !plain && !strings.Contains(b.String(), "full report: rhythm-tuner scan https://a.test -o report.md") {
				t.Errorf("full report hint names the wrong command:\n%s", b.String())
			}
		}
	}
}
