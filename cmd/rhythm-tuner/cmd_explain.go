// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/engine"
)

// findingReference is the wiki page with one section per finding ID.
const findingReference = "https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Finding-Reference"

func init() {
	registerCommand(command{Name: "explain", Summary: "show a check's full fix offline", Run: cmdExplain})
}

// cmdExplain runs `rhythm tuner explain <id>`: everything Tuner knows about
// one finding ID, with the full fix the terminal report shortens. It reads
// the checks a scan would use (built-in or the active check pack) and the
// rule registry for findings that come from Go code, such as vuln-*.
//
// It is registered with registerCommand (cmd/rhythm-tuner/extend.go) once
// that lands; until then only tests call it.
func cmdExplain(args []string, stdout, stderr io.Writer) int {
	var (
		dir               string
		asJSON, noUpdates bool
	)
	flags := flag.NewFlagSet("explain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&dir, "checks", "", "")
	flags.BoolVar(&asJSON, "json", false, "")
	// explain never fetches, so --offline changes nothing; it's accepted
	// because people pass the same flags as to scan.
	flags.Bool("offline", false, "")
	flags.BoolVar(&noUpdates, "no-check-updates", false, "")
	pos, err := cli.ParseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, explainUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, explainUsage)
		return exitUsage
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "rhythm tuner: explain takes one finding ID\n\n%s", explainUsage)
		return exitUsage
	}
	id := strings.TrimSpace(pos[0])

	// Offline: looking up a finding must not wait on the pack host. The
	// cached pack is what the last scan used, or close to it.
	ua := fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	set, err := loadCheckSet(dir, !noUpdates, true, ua, nil)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner: loading checks:", err)
		return exitError
	}
	for _, w := range set.warnings {
		fmt.Fprintln(stderr, "rhythm tuner:", w)
	}

	e, ok := lookupExplanation(id, set.checks, engine.Rules())
	if !ok {
		msg := fmt.Sprintf("no check or rule %q", id)
		if s := suggestIDs(id, knownIDs(set.checks, engine.Rules())); len(s) > 0 {
			msg += "; did you mean " + strings.Join(s, " or ") + "?"
		} else {
			msg += "; list them with: rhythm tuner checks"
		}
		fmt.Fprintln(stderr, "rhythm tuner:", msg)
		return exitUsage
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(e); err != nil {
			return exitError
		}
		return exitOK
	}
	e.write(stdout)
	return exitOK
}

const explainUsage = `Usage:
  rhythm tuner explain <id> [flags]

Shows what a finding means and how to fix it: severity, impact, the full
fix with nginx and Apache snippets, references and the wiki page. <id> is
a check ID such as leak-dotenv or a vulnerability rule such as
vuln-plugin-akismet. It never goes online: it reads the cached check pack
when one is newer than the built-in checks (refresh it with rhythm tuner
update).

Flags:
      --json               machine-readable output
      --checks <dir>       explain a check from a directory
      --no-check-updates   ignore check packs; use the built-in checks
`

// explanation is what explain prints, also its --json shape.
type explanation struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"` // check or rule
	Name       string          `json:"name"`
	Severity   engine.Severity `json:"severity,omitempty"`
	Confidence string          `json:"confidence,omitempty"`
	Profile    engine.Profile  `json:"profile,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Requires   []string        `json:"requires,omitempty"`
	Paths      []string        `json:"paths,omitempty"`
	Impact     string          `json:"impact,omitempty"`
	Fix        string          `json:"fix,omitempty"`
	FixServer  *fixServer      `json:"fix_server,omitempty"`
	References []string        `json:"references,omitempty"`
	Reference  string          `json:"reference"` // the wiki section or the rule's own help page
}

type fixServer struct {
	Nginx  string `json:"nginx,omitempty"`
	Apache string `json:"apache,omitempty"`
}

// lookupExplanation finds id among the checks, then among the rules. A
// prefix rule such as vuln-plugin- explains every ID it covers.
func lookupExplanation(id string, checks []*engine.Check, rules []engine.Rule) (explanation, bool) {
	for _, c := range checks {
		if c.ID != id {
			continue
		}
		e := explanation{
			ID: c.ID, Kind: "check", Name: c.Name, Severity: c.Severity,
			Confidence: string(c.Confidence), Profile: c.Profile, Tags: c.Tags,
			Requires: c.Requires, Paths: c.Request.Path,
			Impact: strings.TrimSpace(c.Impact), Fix: withoutSnippets(c.Fix, c.FixServer),
			References: c.References, Reference: findingReference + "#" + c.ID,
		}
		if n, a := strings.TrimSpace(c.FixServer.Nginx), strings.TrimSpace(c.FixServer.Apache); n != "" || a != "" {
			e.FixServer = &fixServer{Nginx: n, Apache: a}
		}
		return e, true
	}
	// An exact ID wins, then the longest prefix, so vuln-plugin- beats vuln-.
	var best *engine.Rule
	for i, r := range rules {
		switch {
		case r.ID == id:
			best = &rules[i]
		case r.Prefix && strings.HasPrefix(id, r.ID) && (best == nil || best.ID != id && len(r.ID) > len(best.ID)):
			best = &rules[i]
		}
		if best != nil && best.ID == id {
			break
		}
	}
	if best == nil {
		return explanation{}, false
	}
	ref := best.HelpURI
	if ref == "" {
		ref = findingReference + "#" + strings.TrimSuffix(best.ID, "-")
	}
	return explanation{
		ID: id, Kind: "rule", Name: best.Title, Severity: best.Severity,
		Tags: best.Tags, Reference: ref,
	}, true
}

// withoutSnippets drops the "nginx: ..." and "apache: ..." lines of a fix
// that only repeat its fix_server snippets, which explain shows in full
// under their own headings. Other lines, such as a different nginx
// directive, stay.
func withoutSnippets(fix string, fs engine.FixServer) string {
	snippets := map[string]string{"nginx": fs.Nginx, "apache": fs.Apache}
	var keep []string
	for _, line := range strings.Split(strings.TrimSpace(fix), "\n") {
		server, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && repeats(snippets[strings.ToLower(server)], rest) {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

// repeats reports whether text is the snippet, or one of its lines, with
// spacing ignored.
func repeats(snippet, text string) bool {
	text = strings.Join(strings.Fields(text), " ")
	if snippet == "" || text == "" {
		return false
	}
	if strings.Join(strings.Fields(snippet), " ") == text {
		return true
	}
	for _, line := range strings.Split(snippet, "\n") {
		if strings.Join(strings.Fields(line), " ") == text {
			return true
		}
	}
	return false
}

// write prints e for people. Long text keeps its own line breaks, indented
// under its heading, so snippets can be copied as they are.
func (e explanation) write(w io.Writer) {
	fmt.Fprintf(w, "%s: %s\n", e.ID, e.Name)
	field := func(label, value string) {
		if value != "" {
			fmt.Fprintf(w, "  %-11s %s\n", label+":", value)
		}
	}
	field("Severity", string(e.Severity))
	field("Confidence", e.Confidence)
	field("Profile", string(e.Profile))
	field("Tags", strings.Join(e.Tags, ", "))
	field("Requires", strings.Join(e.Requires, ", "))
	field("Requests", strings.Join(e.Paths, " "))
	if e.Kind == "rule" {
		fmt.Fprintln(w, "  Reported by vulnerability matching or a local scan, not a YAML check.")
	}
	section := func(title, body string) {
		if body == "" {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, line := range strings.Split(body, "\n") {
			fmt.Fprintln(w, strings.TrimRight("  "+line, " "))
		}
	}
	section("Impact", e.Impact)
	section("Fix", e.Fix)
	if e.FixServer != nil {
		section("nginx", e.FixServer.Nginx)
		section("Apache", e.FixServer.Apache)
	}
	section("References", strings.Join(e.References, "\n"))
	section("More", e.Reference)
}

// knownIDs lists every ID explain can resolve exactly, for suggestions.
// Prefix rules are left out: their ID alone is not a finding.
func knownIDs(checks []*engine.Check, rules []engine.Rule) []string {
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	for _, r := range rules {
		if !r.Prefix {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// suggestIDs returns up to three known IDs close to id: within a third of
// its length in edits (at least 2) or starting with it.
func suggestIDs(id string, known []string) []string {
	type cand struct {
		id   string
		dist int
	}
	limit := max(2, len(id)/3)
	var cs []cand
	for _, k := range known {
		d := editDistance(id, k)
		if d <= limit || len(id) >= 3 && strings.HasPrefix(k, id) {
			cs = append(cs, cand{k, d})
		}
	}
	slices.SortStableFunc(cs, func(a, b cand) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		return strings.Compare(a.id, b.id)
	})
	var out []string
	for _, c := range cs {
		if !slices.Contains(out, c.id) {
			out = append(out, c.id)
		}
		if len(out) == 3 {
			break
		}
	}
	return out
}
