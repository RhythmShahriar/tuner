package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/RhythmShahriar/rhythm/kit"
	"github.com/RhythmShahriar/rhythm/kit/ui"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

const width = 64

type PrettyOptions struct {
	Plain    bool // no color, box drawing or decorative glyphs; for screen readers and logs
	Quiet    bool // findings only
	Progress bool // redraw a progress line; only for interactive terminals
}

// Pretty streams a scan to a terminal. Its methods match engine.Hooks.
type Pretty struct {
	w, errw io.Writer
	o       PrettyOptions
	start   time.Time
	drawn   bool // a progress line is on screen and must be cleared first

	sawAdvisories bool // a vulnerability finding was shown, so credit the data source
}

func NewPretty(w, errw io.Writer, o PrettyOptions) *Pretty {
	return &Pretty{w: w, errw: errw, o: o, start: time.Now()}
}

func (p *Pretty) clear() {
	if p.drawn {
		fmt.Fprint(p.w, "\r\x1b[2K")
		p.drawn = false
	}
}

func (p *Pretty) Header(version, target string) {
	if p.o.Quiet {
		return
	}
	if p.o.Plain {
		fmt.Fprintf(p.w, "rhythm tuner %s - scanning %s\n\n", version, target)
		return
	}
	left := ui.Brand.Render(kit.Banner("rhythm tuner", version))
	gap := max(2, width-lipgloss.Width(left)-lipgloss.Width(target))
	fmt.Fprintf(p.w, "\n  %s%s%s\n\n", left, strings.Repeat(" ", gap), ui.Dim.Render(target))
}

func (p *Pretty) step(label, value string) {
	if p.o.Quiet {
		return
	}
	p.clear()
	if p.o.Plain {
		fmt.Fprintf(p.w, "%s: %s\n", label, value)
		return
	}
	fmt.Fprintf(p.w, "  %s %s %s\n", ui.Good.Render("●"), ui.Label.Width(16).Render(label), value)
}

func (p *Pretty) Fingerprint(fp fingerprint.Result) {
	p.step("Fingerprint", fp.String())
	if n := len(fp.Components); n > 0 {
		var names []string
		for _, c := range fp.Components[:min(n, 6)] {
			names = append(names, c.String())
		}
		if n > 6 {
			names = append(names, fmt.Sprintf("+%d more", n-6))
		}
		p.step("Components", strings.Join(names, " · "))
	}
}

func (p *Pretty) Baseline(soft404 bool) {
	if soft404 {
		p.step("Baseline", "soft-404 detected, filtering enabled")
	} else {
		p.step("Baseline", "server returns real 404s")
	}
	if !p.o.Quiet {
		fmt.Fprintln(p.w)
	}
}

var spinner = []string{"◐", "◓", "◑", "◒"}

func (p *Pretty) Progress(done, total int) {
	if !p.o.Progress || p.o.Plain || p.o.Quiet || total == 0 {
		return
	}
	if done >= total {
		p.clear()
		return
	}
	const bar = 20
	fill := bar * done / total
	fmt.Fprintf(p.w, "\r\x1b[2K  %s %s %s  %d/%d · %s",
		ui.Label.Render(spinner[done%len(spinner)]), ui.Label.Width(16).Render("Checks"),
		ui.Brand.Render(strings.Repeat("█", fill))+ui.Dim.Render(strings.Repeat("░", bar-fill)),
		done, total, time.Since(p.start).Round(100*time.Millisecond))
	p.drawn = true
}

// Request logs one HTTP exchange to stderr, for --verbose.
func (p *Pretty) Request(l engine.RequestLog) {
	p.clear()
	status := fmt.Sprint(l.Status)
	if l.Err != nil {
		status = "ERR " + l.Err.Error()
	}
	retry := ""
	if l.Attempt > 1 {
		retry = fmt.Sprintf(" (attempt %d)", l.Attempt)
	}
	line := fmt.Sprintf("%s %s %s %s%s", l.Method, status, l.URL, l.Duration.Round(time.Millisecond), retry)
	if !p.o.Plain {
		line = ui.Dim.Render("  → " + line)
	}
	fmt.Fprintln(p.errw, line)
}

var glyphs = map[engine.Severity]string{
	engine.Critical: "✖", engine.High: "▲", engine.Medium: "■", engine.Low: "●", engine.Info: "·",
}

func (p *Pretty) Finding(f engine.Finding) {
	p.clear()
	sev := strings.ToUpper(string(f.Severity))
	var secrets []string
	for _, s := range f.Evidence.Secrets {
		secrets = append(secrets, s.String())
	}
	fix := firstLine(f.Fix)
	detail := ""
	if len(f.Evidence.Matched) > 0 && len(secrets) == 0 {
		detail = f.Evidence.Matched[0]
	}
	// Vulnerability findings list their worst advisories.
	var advisories []string
	if len(f.Advisories) > 0 {
		advisories = f.Evidence.Matched[:min(3, len(f.Evidence.Matched))]
		if n := len(f.Advisories) - len(advisories); n > 0 {
			advisories = append(advisories, fmt.Sprintf("…and %d more", n))
		}
		detail = ""
		p.sawAdvisories = true
	}

	if p.o.Plain {
		fmt.Fprintf(p.w, "[%s] %s - %s\n", sev, f.Title, f.URL)
		if detail != "" {
			fmt.Fprintf(p.w, "  evidence: %s\n", detail)
		}
		for _, a := range advisories {
			fmt.Fprintf(p.w, "  - %s\n", a)
		}
		if len(secrets) > 0 {
			fmt.Fprintf(p.w, "  secrets: %s\n", strings.Join(secrets, "  "))
		}
		if fix != "" && f.Severity.Rank() <= engine.High.Rank() {
			fmt.Fprintf(p.w, "  fix: %s\n", fix)
		}
		return
	}

	color := ui.SeverityColor(string(f.Severity))
	tag := lipgloss.NewStyle().Foreground(color).Bold(true)
	if f.Severity == engine.Critical {
		lines := []string{tag.Render(glyphs[f.Severity]+" "+sev) + "  " + f.Title + "  " + ui.Dim.Render(f.Path)}
		if len(secrets) > 0 {
			lines = append(lines, "  "+strings.Join(secrets, "  "))
		} else if detail != "" {
			lines = append(lines, ui.Dim.Render("  "+detail))
		}
		for _, a := range advisories {
			lines = append(lines, ui.Dim.Render(truncate("  "+a, width-4)))
		}
		if fix != "" {
			lines = append(lines, ui.Dim.Render(truncate("  fix → "+fix, width-4)))
		}
		box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(color).
			Padding(0, 1).MarginLeft(2).Width(width)
		fmt.Fprintln(p.w, box.Render(strings.Join(lines, "\n")))
		return
	}
	fmt.Fprintf(p.w, "  %s  %s  %s\n", tag.Render(fmt.Sprintf("%s %-6s", glyphs[f.Severity], sev)), f.Title, ui.Dim.Render(f.Path))
	if len(secrets) > 0 {
		fmt.Fprintf(p.w, "             %s\n", strings.Join(secrets, "  "))
	}
	for _, a := range advisories {
		fmt.Fprintf(p.w, "             %s\n", ui.Dim.Render(truncate(a, width)))
	}
	if f.Severity == engine.High {
		if detail != "" {
			fmt.Fprintf(p.w, "             %s\n", ui.Dim.Render(detail))
		}
		if fix != "" {
			fmt.Fprintf(p.w, "             %s\n", ui.Dim.Render("fix → "+fix))
		}
	}
}

// Summary prints the score and totals. suppressed counts findings hidden
// by a baseline file.
func (p *Pretty) Summary(res *engine.Result, target string, suppressed int) {
	p.clear()
	if p.o.Quiet {
		return
	}
	counts := res.Counts()
	var parts []string
	for _, s := range engine.Severities {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	stats := []string{fmt.Sprintf("%d checks", res.Checks), fmt.Sprintf("%d requests", res.Requests), res.Duration.Round(100 * time.Millisecond).String()}
	if suppressed > 0 {
		stats = append(stats, fmt.Sprintf("%d baselined", suppressed))
	}
	if res.Throttled > 0 {
		stats = append(stats, fmt.Sprintf("throttled %d× (slowed down)", res.Throttled))
	}
	if res.Errors > 0 {
		stats = append(stats, fmt.Sprintf("%d errors", res.Errors))
	}
	score := fmt.Sprintf("Score %d/100", res.Score)

	var notes []string
	notes = append(notes, res.Warnings...)
	if p.sawAdvisories {
		notes = append(notes, "vulnerability data: WPVulnerability (wpvulnerability.com, CC0)")
	}

	if p.o.Plain {
		if len(parts) == 0 {
			parts = []string{"no findings"}
		}
		fmt.Fprintf(p.w, "\n%s - %s - %s\n", score, strings.Join(parts, ", "), strings.Join(stats, ", "))
		for _, n := range notes {
			fmt.Fprintf(p.w, "note: %s\n", n)
		}
		return
	}
	scoreColor := ui.Danger
	switch {
	case res.Score >= 80:
		scoreColor = ui.Ok
	case res.Score >= 50:
		scoreColor = ui.Warn
	}
	score = lipgloss.NewStyle().Foreground(lipgloss.Color(scoreColor)).Bold(true).Render(score)
	if len(parts) == 0 {
		parts = []string{ui.Good.Render("✔ nothing out of tune")}
	}
	fmt.Fprintf(p.w, "\n  %s · %s\n  %s\n", score, strings.Join(parts, " · "), ui.Dim.Render(strings.Join(stats, " · ")))
	for _, n := range notes {
		fmt.Fprintf(p.w, "  %s\n", ui.Dim.Render("! "+n))
	}
	fmt.Fprintf(p.w, "  %s\n\n", ui.Dim.Render("→ rhythm tuner scan "+target+" --md > report.md"))
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
