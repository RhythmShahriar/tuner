// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"cmp"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"

	"github.com/RhythmShahriar/rhythm/kit/ui"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

const (
	badgeWidth  = 10 // a severity badge, padded, is this wide
	titleIndent = badgeWidth + 2

	// The report is as wide as the terminal less a margin, within these
	// bounds: narrower breaks the card layout, wider is hard to read.
	minWidth, maxWidth = 56, 100
	defaultColumns     = 80 // when the output is not a terminal
)

// PrettyOptions configures the terminal view.
type PrettyOptions struct {
	Plain    bool // no color, box drawing or decorative glyphs; for screen readers and logs
	Quiet    bool // findings and a one-line summary only
	Progress bool // redraw a progress line; only for interactive terminals
	Columns  int  // terminal width; 0 reads it from the output, or assumes 80
	// Command is how the hints name Tuner, as it was started: "rhythm
	// tuner" (the default) or "rhythm-tuner".
	Command string
}

// Pretty renders a scan for a terminal. Its methods match engine.Hooks.
//
// In plain mode findings stream as they are found, one per line, for logs
// and screen readers. Otherwise a live progress line keeps a running tally
// while the scan runs; Summary prints the findings grouped by severity
// once the scan (and any baseline filtering) is done.
type Pretty struct {
	w, errw io.Writer
	o       PrettyOptions
	start   time.Time
	drawn   bool // a progress line is on screen and must be cleared first
	spaced  bool // a blank line already separates the scan steps from the report
	tally   map[engine.Severity]int
	status  Status
	width   int // content width of the report
	// shortFix is set once a fix was cut to its first line, so Summary
	// points at explain for the full text.
	shortFix bool
}

// NewPretty returns a view that writes the report to w and request logs
// (for --verbose) to errw.
func NewPretty(w, errw io.Writer, o PrettyOptions) *Pretty {
	return &Pretty{w: w, errw: errw, o: o, start: time.Now(), tally: map[engine.Severity]int{},
		status: Status{Complete: true}, width: contentWidth(o.Columns, w)}
}

// contentWidth picks the report width for a terminal of cols columns,
// reading the size from w when cols is 0.
func contentWidth(cols int, w io.Writer) int {
	if cols <= 0 {
		cols = defaultColumns
		if f, ok := w.(*os.File); ok && term.IsTerminal(f.Fd()) {
			if c, _, err := term.GetSize(f.Fd()); err == nil && c > 0 {
				cols = c
			}
		}
	}
	return min(max(cols-8, minWidth), maxWidth)
}

// SetStatus tells Summary how complete the scan was, so a partial scan
// says so above its score.
func (p *Pretty) SetStatus(s Status) { p.status = s }

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

// Header prints the tool name and the target before a scan starts.
func (p *Pretty) Header(version, target string) {
	version, target = SafeText(version), SafeText(target)
	if p.o.Quiet {
		return
	}
	if p.o.Plain {
		fmt.Fprintf(p.w, "rhythm tuner %s - scanning %s\n\n", version, target)
		return
	}
	left := ui.Brand.Render("♪") + " " + bold.Render("rhythm tuner") + " " + muted.Render(version)
	gap := max(2, p.width-lipgloss.Width(left)-lipgloss.Width(target))
	fmt.Fprintf(p.w, "\n  %s%s%s\n  %s\n\n", left, strings.Repeat(" ", gap), muted.Render(target),
		muted.Render(strings.Repeat("─", p.width)))
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

// Fingerprint prints what the scan learned about the target.
func (p *Pretty) Fingerprint(fp fingerprint.Result) {
	fp = sanitized(fp)
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

// Baseline prints whether the server answers missing pages with a real 404.
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

// Progress redraws the progress line with a running tally.
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
		status = "ERR " + SafeText(l.Err.Error()) // errors quote URLs and server replies
	}
	retry := ""
	if l.Attempt > 1 {
		retry = fmt.Sprintf(" (attempt %d)", l.Attempt)
	}
	line := fmt.Sprintf("%s %s %s %s%s", SafeText(l.Method), status, SafeText(l.URL), l.Duration.Round(time.Millisecond), retry)
	if !p.o.Plain {
		line = muted.Render("  → " + line)
	}
	fmt.Fprintln(p.errw, line)
}

// Finding streams a line in plain mode; otherwise it only updates the
// running tally. Summary renders the grouped report.
func (p *Pretty) Finding(f engine.Finding) {
	f = sanitized(f)
	p.tally[f.Severity]++
	if !p.o.Plain {
		return
	}
	p.clear()
	var secrets []string
	for _, s := range f.Evidence.Secrets {
		secrets = append(secrets, s.String())
	}
	label := strings.ToUpper(string(f.Severity))
	if f.Confidence == "low" {
		label += ", likely"
	}
	fmt.Fprintf(p.w, "[%s] %s - %s\n", label, f.Title, Place(f))
	if f.Confidence == "low" && f.Caveat != "" {
		fmt.Fprintf(p.w, "  %s\n", f.Caveat)
	}
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
	if fix := fixLine(f.Fix); fix != "" {
		fmt.Fprintf(p.w, "  fix: %s\n", fix)
		p.shortFix = p.shortFix || fixShortened(f.Fix)
	}
}

// Place is where a finding is, for the terminal: its URL, or for a local
// finding its path inside the scanned folder. JSON keeps the full file://
// URL; on screen it is mostly the temporary folder's name repeated.
func Place(f engine.Finding) string {
	if u, err := url.Parse(f.URL); err == nil && u.Scheme == "file" && f.Path != "" {
		return f.Path
	}
	return f.URL
}

// fixLine is the first line of a fix. When more lines follow it says so,
// so a fix that leads into a snippet doesn't end on a dangling colon.
func fixLine(fix string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(fix), "\n")
	first = strings.TrimSpace(first)
	if fixShortened(fix) {
		return strings.TrimRight(first, ": ") + " (see report)"
	}
	return first
}

// fixShortened reports whether fixLine leaves lines of fix out.
func fixShortened(fix string) bool {
	_, rest, more := strings.Cut(strings.TrimSpace(fix), "\n")
	return more && strings.TrimSpace(rest) != ""
}

// command is the name the hints give Tuner.
func (p *Pretty) command() string { return cmp.Or(p.o.Command, "rhythm tuner") }

// explainHint is the footer under a report whose fixes were cut short.
func (p *Pretty) explainHint() string {
	return "run " + p.command() + " explain <id> for the full fix"
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
// The fix and lines that hold a URL wrap rather than lose their end.
func card(f engine.Finding, width int) string {
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
		if !strings.Contains(s, "://") {
			body = append(body, indent+style.Render(truncate(s, width-titleIndent-2)))
			return
		}
		for _, l := range wrap(s, width-titleIndent-2) {
			body = append(body, indent+style.Render(l))
		}
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
	if fix := fixLine(f.Fix); fix != "" {
		// The arrow carries the brand color; the text stays readable and
		// neutral so it doesn't compete with the severity colors.
		for i, l := range wrap(fix, width-titleIndent-4) {
			lead := "  "
			if i == 0 {
				lead = ui.Brand.Render("→") + " "
			}
			body = append(body, indent+lead+l)
		}
	}

	rail := lipgloss.NewStyle().Border(lipgloss.Border{Left: "▌"}, false, false, false, true).
		BorderForeground(ui.SeverityColor(string(f.Severity))).PaddingLeft(1).MarginLeft(1)
	// One line at a time: rendered as a block, every line would be padded
	// to the widest: one long URL would make each of them wrap.
	for i, l := range body {
		body[i] = rail.Render(l)
	}
	return strings.Join(body, "\n")
}

// compact renders a low or info finding as a single line.
func compact(f engine.Finding, width int) string {
	marker := sevStyle(f.Severity).Render(glyphs[f.Severity])
	line := truncate(f.Title, width-8)
	if f.Path != "" && f.Path != "/" && lipgloss.Width(line)+len(f.Path)+3 <= width-6 {
		line = pad(line, width-6-len(f.Path)) + muted.Render(f.Path)
	}
	return "    " + marker + "  " + line
}

func section(sev engine.Severity, n, width int) string {
	label := sevStyle(sev).Render(fmt.Sprintf("%s  %d", strings.ToUpper(string(sev)), n))
	rule := muted.Render(strings.Repeat("─", max(2, width-lipgloss.Width(label)-1)))
	return "  " + label + " " + rule
}

// Summary prints the grouped report (in plain mode a severity-sorted list
// after the stream), the score panel and totals. suppressed counts
// findings hidden by a baseline file. With Quiet it prints the findings
// and a one-line summary, so a quiet CI log still has the score.
func (p *Pretty) Summary(res *engine.Result, target string, suppressed int) {
	clean := sanitized(*res)
	res, target = &clean, SafeText(target)
	p.clear()
	switch {
	case !p.o.Plain:
		p.report(res.Findings)
	case !p.o.Quiet:
		p.sorted(res.Findings)
	}

	counts := res.Counts()
	var parts []string
	for _, s := range engine.Severities {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	stats := []string{plural(int64(res.Checks), "check")}
	if res.Requests > 0 { // local scans make none
		stats = append(stats, plural(res.Requests, "request"))
	}
	stats = append(stats, res.Duration.Round(100*time.Millisecond).String())
	if res.Throttled > 0 {
		stats = append(stats, fmt.Sprintf("throttled %d× (slowed down)", res.Throttled))
	}
	if res.Errors > 0 {
		stats = append(stats, plural(res.Errors, "error"))
	}

	var notes []string
	notes = append(notes, res.Warnings...)
	for _, f := range res.Findings {
		if f.Source != "" {
			notes = append(notes, "vulnerability data: "+f.Source)
			break
		}
	}

	if len(parts) == 0 {
		parts = []string{"no findings"}
	}
	line := fmt.Sprintf("Score %s - %s - %s", scoreText(res.Score, suppressed), strings.Join(parts, ", "), strings.Join(stats, ", "))

	if p.o.Plain || p.o.Quiet {
		fmt.Fprintln(p.w)
		for _, n := range p.status.Notes() {
			fmt.Fprintln(p.w, n)
		}
		fmt.Fprintln(p.w, line)
		if p.o.Quiet {
			return
		}
		for _, n := range notes {
			fmt.Fprintf(p.w, "note: %s\n", n)
		}
		if p.shortFix {
			fmt.Fprintln(p.w, p.explainHint())
		}
		return
	}

	warn := lipgloss.NewStyle().Foreground(lipgloss.Color(ui.Warn)).Bold(true)
	for _, n := range p.status.Notes() {
		fmt.Fprintf(p.w, "  %s\n", warn.Render("! "+n))
	}
	fmt.Fprintln(p.w, scorePanel(res.Score, suppressed, counts, p.width))
	fmt.Fprintf(p.w, "  %s\n", muted.Render(strings.Join(stats, " · ")))
	for _, n := range notes {
		fmt.Fprintf(p.w, "  %s\n", muted.Render("! "+n))
	}
	fmt.Fprintln(p.w)
	if p.shortFix {
		fmt.Fprintf(p.w, "  %s %s\n", ui.Brand.Render("→"), muted.Render(p.explainHint()))
	}
	fmt.Fprintf(p.w, "  %s %s\n\n", ui.Brand.Render("→"),
		muted.Render("full report: "+p.command()+" scan "+target+" -o report.md"))
}

// scoreText is the score as the summary line shows it. After a baseline it
// says so: a run with every finding baselined is not an all-clear.
func scoreText(score, suppressed int) string {
	if suppressed > 0 {
		return fmt.Sprintf("%d/100 after baseline (%d hidden)", score, suppressed)
	}
	return fmt.Sprintf("%d/100", score)
}

// sorted lists the findings most severe first, one line each, after the
// plain stream, which prints them in the order they were found.
func (p *Pretty) sorted(findings []engine.Finding) {
	if len(findings) == 0 {
		return
	}
	fs := slices.Clone(findings)
	slices.SortStableFunc(fs, func(a, b engine.Finding) int { return cmp.Compare(a.Severity.Rank(), b.Severity.Rank()) })
	fmt.Fprintln(p.w)
	fmt.Fprintln(p.w, "Findings by severity:")
	for _, f := range fs {
		label := strings.ToUpper(string(f.Severity))
		if f.Confidence == "low" {
			label += ", likely"
		}
		fmt.Fprintf(p.w, "[%s] %s - %s\n", label, f.Title, Place(f))
	}
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
		fmt.Fprintln(p.w, section(sev, len(fs), p.width))
		fmt.Fprintln(p.w)
		for _, f := range fs {
			if sev.Rank() <= engine.Medium.Rank() {
				p.shortFix = p.shortFix || fixShortened(f.Fix)
				fmt.Fprintln(p.w, card(f, p.width))
				fmt.Fprintln(p.w)
			} else {
				fmt.Fprintln(p.w, compact(f, p.width))
			}
		}
		if sev.Rank() > engine.Medium.Rank() {
			fmt.Fprintln(p.w)
		}
	}
}

// scorePanel draws the Tune score: the number, a proportional bar and a
// colored severity breakdown. suppressed findings were hidden by a baseline.
func scorePanel(score, suppressed int, counts map[engine.Severity]int, width int) string {
	color := ui.Ok
	switch {
	case score < 50:
		color = ui.Danger
	case score < 80:
		color = ui.Warn
	}
	barW := width - 8
	fill := barW * score / 100
	if score > 0 && fill == 0 {
		fill = 1
	}
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
	bar := accent.Render(strings.Repeat("█", fill)) + muted.Render(strings.Repeat("░", barW-fill))

	label := bold.Render("TUNE SCORE")
	num := accent.Render(fmt.Sprint(score)) + muted.Render(" / 100")
	if suppressed > 0 {
		num += muted.Render(fmt.Sprintf(" after baseline (%d hidden)", suppressed))
	}
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

// plural renders a count with its noun: "1 error", "3 errors".
func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:max(0, n-1)]) + "…"
	}
	return s
}

// wrap breaks s into lines of at most n columns at spaces. A word longer
// than n, such as a URL, gets a line of its own and is never cut, so it
// can still be copied.
func wrap(s string, n int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case lipgloss.Width(line)+1+lipgloss.Width(word) <= n:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func pad(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}
