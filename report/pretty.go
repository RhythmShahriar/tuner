package report

import (
	"cmp"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/RhythmShahriar/rhythm/kit/ui"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

const (
	width       = 72 // content width of the report
	badgeWidth  = 10 // a severity badge, padded, is this wide
	titleIndent = badgeWidth + 2
)

type PrettyOptions struct {
	Plain    bool // no color, box drawing or decorative glyphs; for screen readers and logs
	Quiet    bool // findings only
	Progress bool // redraw a progress line; only for interactive terminals
}

// Pretty renders a scan for a terminal. Its methods match engine.Hooks.
//
// In plain mode findings stream as they are found, one per line, for logs
// and screen readers. Otherwise a live progress line keeps a running tally
// while the scan runs, and Summary prints the findings grouped by severity
// once the scan (and any baseline filtering) is done.
type Pretty struct {
	w, errw io.Writer
	o       PrettyOptions
	start   time.Time
	drawn   bool // a progress line is on screen and must be cleared first
	spaced  bool // a blank line already separates the scan steps from the report
	tally   map[engine.Severity]int
}

func NewPretty(w, errw io.Writer, o PrettyOptions) *Pretty {
	return &Pretty{w: w, errw: errw, o: o, start: time.Now(), tally: map[engine.Severity]int{}}
}

var (
	muted = lipgloss.NewStyle().Foreground(lipgloss.Color(ui.Muted))
	bold  = lipgloss.NewStyle().Bold(true)
)

func sevStyle(s engine.Severity) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ui.SeverityColor(string(s))).Bold(true)
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
	left := ui.Brand.Render("♪") + " " + bold.Render("rhythm tuner") + " " + muted.Render(version)
	gap := max(2, width-lipgloss.Width(left)-lipgloss.Width(target))
	fmt.Fprintf(p.w, "\n  %s%s%s\n  %s\n\n", left, strings.Repeat(" ", gap), muted.Render(target),
		muted.Render(strings.Repeat("─", width)))
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
	fmt.Fprintf(p.w, "  %s %s %s\n", ui.Brand.Render("▸"), muted.Bold(true).Width(13).Render(label), value)
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
		p.spaced = true
	}
}

var spinner = []string{"◐", "◓", "◑", "◒"}

var glyphs = map[engine.Severity]string{
	engine.Critical: "✖", engine.High: "▲", engine.Medium: "■", engine.Low: "●", engine.Info: "·",
}

func (p *Pretty) Progress(done, total int) {
	if !p.o.Progress || p.o.Plain || p.o.Quiet || total == 0 {
		return
	}
	if done >= total {
		p.clear()
		return
	}
	const bar = 24
	fill := bar * done / total
	var found []string
	for _, s := range engine.Severities[:3] {
		if n := p.tally[s]; n > 0 {
			found = append(found, sevStyle(s).Render(fmt.Sprintf("%s %d", glyphs[s], n)))
		}
	}
	tally := ""
	if len(found) > 0 {
		tally = "  " + strings.Join(found, " ")
	}
	fmt.Fprintf(p.w, "\r\x1b[2K  %s %s %s  %s%s",
		ui.Brand.Render(spinner[done%len(spinner)]),
		muted.Bold(true).Width(13).Render("Scanning"),
		ui.Brand.Render(strings.Repeat("━", fill))+muted.Render(strings.Repeat("━", bar-fill)),
		muted.Render(fmt.Sprintf("%d/%d · %s", done, total, time.Since(p.start).Round(100*time.Millisecond))),
		tally)
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
		line = muted.Render("  → " + line)
	}
	fmt.Fprintln(p.errw, line)
}

// Finding streams a line in plain mode; otherwise it only updates the
// running tally, and Summary renders the grouped report.
func (p *Pretty) Finding(f engine.Finding) {
	p.tally[f.Severity]++
	if !p.o.Plain {
		return
	}
	p.clear()
	var secrets []string
	for _, s := range f.Evidence.Secrets {
		secrets = append(secrets, s.String())
	}
	fmt.Fprintf(p.w, "[%s] %s - %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.URL)
	switch {
	case len(f.Advisories) > 0:
		for _, a := range advisoryLines(f, 3) {
			fmt.Fprintf(p.w, "  - %s\n", a)
		}
	case len(secrets) > 0:
		fmt.Fprintf(p.w, "  secrets: %s\n", strings.Join(secrets, "  "))
	case len(f.Evidence.Matched) > 0:
		fmt.Fprintf(p.w, "  evidence: %s\n", f.Evidence.Matched[0])
	}
	if fix := firstLine(f.Fix); fix != "" && f.Severity.Rank() <= engine.High.Rank() {
		fmt.Fprintf(p.w, "  fix: %s\n", fix)
	}
}

func advisoryLines(f engine.Finding, n int) []string {
	lines := f.Evidence.Matched[:min(n, len(f.Evidence.Matched))]
	if more := len(f.Advisories) - len(lines); more > 0 {
		lines = append(lines, fmt.Sprintf("…and %d more", more))
	}
	return lines
}

// badge renders a severity label. Confirmed findings get a filled badge;
// low-confidence ones (a version a distro may have patched) get an outline
// badge, so "confirmed" and "likely" read apart at a glance.
func badge(sev engine.Severity, lowConf bool) string {
	label := fmt.Sprintf(" %-8s", strings.ToUpper(string(sev)))
	if lowConf {
		return sevStyle(sev).Render(label + " ")
	}
	return lipgloss.NewStyle().Background(ui.SeverityColor(string(sev))).
		Foreground(lipgloss.Color("#0B0B0C")).Bold(true).Render(label + " ")
}

// card renders a critical, high or medium finding with its evidence and fix.
func card(f engine.Finding) string {
	lowConf := f.Confidence == "low"
	titleCol := width - titleIndent - 2
	title, path := f.Title, f.Path
	if path == "/" || lipgloss.Width(title)+len(path)+2 > titleCol {
		path = ""
	}
	head := badge(f.Severity, lowConf) + "  "
	if path != "" {
		head += pad(bold.Render(title), titleCol-len(path)) + muted.Render(path)
	} else {
		head += bold.Render(truncate(title, titleCol))
	}

	body := []string{head}
	indent := strings.Repeat(" ", titleIndent)
	add := func(s string, style lipgloss.Style) {
		body = append(body, indent+style.Render(truncate(s, width-titleIndent-2)))
	}
	if lowConf {
		add("~ likely: "+cmp.Or(f.Caveat, "not confirmed from outside"), muted.Italic(true))
	}
	var secrets []string
	for _, s := range f.Evidence.Secrets {
		secrets = append(secrets, s.String())
	}
	switch {
	case len(f.Advisories) > 0:
		for _, a := range advisoryLines(f, 3) {
			add(a, muted)
		}
	case len(secrets) > 0:
		add(strings.Join(secrets, "   "), lipgloss.NewStyle().Foreground(lipgloss.Color(ui.High)))
	case len(f.Evidence.Matched) > 0 && f.Evidence.Status != 0:
		add(f.Evidence.Matched[0], muted)
	}
	if fix := firstLine(f.Fix); fix != "" {
		// The arrow carries the brand color; the text stays readable and
		// neutral so it doesn't compete with the severity colors.
		body = append(body, indent+ui.Brand.Render("→")+" "+truncate(fix, width-titleIndent-4))
	}

	rail := lipgloss.NewStyle().Border(lipgloss.Border{Left: "▌"}, false, false, false, true).
		BorderForeground(ui.SeverityColor(string(f.Severity))).PaddingLeft(1).MarginLeft(1)
	return rail.Render(strings.Join(body, "\n"))
}

// compact renders a low or info finding as a single line.
func compact(f engine.Finding) string {
	marker := sevStyle(f.Severity).Render(glyphs[f.Severity])
	line := truncate(f.Title, width-8)
	if f.Path != "" && f.Path != "/" && lipgloss.Width(line)+len(f.Path)+3 <= width-6 {
		line = pad(line, width-6-len(f.Path)) + muted.Render(f.Path)
	}
	return "    " + marker + "  " + line
}

func section(sev engine.Severity, n int) string {
	label := sevStyle(sev).Render(fmt.Sprintf("%s  %d", strings.ToUpper(string(sev)), n))
	rule := muted.Render(strings.Repeat("─", max(2, width-lipgloss.Width(label)-1)))
	return "  " + label + " " + rule
}

// Summary prints the grouped report (unless plain), the score panel and
// totals. suppressed counts findings hidden by a baseline file.
func (p *Pretty) Summary(res *engine.Result, target string, suppressed int) {
	p.clear()
	if !p.o.Plain {
		p.report(res.Findings)
	}
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
	stats := []string{fmt.Sprintf("%d checks", res.Checks)}
	if res.Requests > 0 { // local scans make none
		stats = append(stats, fmt.Sprintf("%d requests", res.Requests))
	}
	stats = append(stats, res.Duration.Round(100*time.Millisecond).String())
	if suppressed > 0 {
		stats = append(stats, fmt.Sprintf("%d baselined", suppressed))
	}
	if res.Throttled > 0 {
		stats = append(stats, fmt.Sprintf("throttled %d× (slowed down)", res.Throttled))
	}
	if res.Errors > 0 {
		stats = append(stats, fmt.Sprintf("%d errors", res.Errors))
	}

	var notes []string
	notes = append(notes, res.Warnings...)
	for _, f := range res.Findings {
		if f.Source != "" {
			notes = append(notes, "vulnerability data: "+f.Source)
			break
		}
	}

	if p.o.Plain {
		if len(parts) == 0 {
			parts = []string{"no findings"}
		}
		fmt.Fprintf(p.w, "\nScore %d/100 - %s - %s\n", res.Score, strings.Join(parts, ", "), strings.Join(stats, ", "))
		for _, n := range notes {
			fmt.Fprintf(p.w, "note: %s\n", n)
		}
		return
	}

	fmt.Fprintln(p.w, scorePanel(res.Score, counts))
	fmt.Fprintf(p.w, "  %s\n", muted.Render(strings.Join(stats, " · ")))
	for _, n := range notes {
		fmt.Fprintf(p.w, "  %s\n", muted.Render("! "+n))
	}
	fmt.Fprintf(p.w, "\n  %s %s\n\n", ui.Brand.Render("→"),
		muted.Render("full report: rhythm tuner scan "+target+" -o report.md"))
}

// report prints findings grouped by severity: cards for critical, high and
// medium, a compact list for low and info.
func (p *Pretty) report(findings []engine.Finding) {
	if !p.spaced && !p.o.Quiet && len(findings) > 0 {
		fmt.Fprintln(p.w) // local scans have no baseline step to print it
	}
	groups := map[engine.Severity][]engine.Finding{}
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	for _, sev := range engine.Severities {
		fs := groups[sev]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintln(p.w, section(sev, len(fs)))
		fmt.Fprintln(p.w)
		for _, f := range fs {
			if sev.Rank() <= engine.Medium.Rank() {
				fmt.Fprintln(p.w, card(f))
				fmt.Fprintln(p.w)
			} else {
				fmt.Fprintln(p.w, compact(f))
			}
		}
		if sev.Rank() > engine.Medium.Rank() {
			fmt.Fprintln(p.w)
		}
	}
}

// scorePanel draws the Tune score: the number, a proportional bar, and a
// colored severity breakdown.
func scorePanel(score int, counts map[engine.Severity]int) string {
	color := ui.Ok
	switch {
	case score < 50:
		color = ui.Danger
	case score < 80:
		color = ui.Warn
	}
	const barW = width - 8
	fill := barW * score / 100
	if score > 0 && fill == 0 {
		fill = 1
	}
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
	bar := accent.Render(strings.Repeat("█", fill)) + muted.Render(strings.Repeat("░", barW-fill))

	label := bold.Render("TUNE SCORE")
	num := accent.Render(fmt.Sprint(score)) + muted.Render(" / 100")
	top := label + strings.Repeat(" ", max(1, barW-lipgloss.Width(label)-lipgloss.Width(num))) + num

	var parts []string
	for _, s := range engine.Severities {
		if n := counts[s]; n > 0 {
			parts = append(parts, sevStyle(s).Render(fmt.Sprintf("%s %d", glyphs[s], n))+" "+muted.Render(string(s)))
		}
	}
	breakdown := ui.Good.Render("✔ nothing out of tune")
	if len(parts) > 0 {
		breakdown = strings.Join(parts, "   ")
	}

	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(color)).
		Padding(0, 2).MarginLeft(1)
	return box.Render(strings.Join([]string{top, bar, breakdown}, "\n"))
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:max(0, n-1)]) + "…"
	}
	return s
}

func pad(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}
