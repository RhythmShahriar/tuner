// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package fixgen turns Tuner JSON reports into one web server config
// bundle: the nginx or Apache snippets that fix the findings, deduplicated
// and grouped, each block commented with the checks and URLs it addresses.
//
// It only produces text. Nothing here edits a config file, reloads a
// server or makes a request; people review the bundle and apply it.
package fixgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// Servers lists the web servers a bundle can target, as the keys of
// engine.Finding.Fixes.
var Servers = []string{"nginx", "apache"}

// Finding is the part of a report finding a bundle needs. Reports from
// before fix_server have no Fixes; Build then falls back to the check.
type Finding struct {
	ID    string            `json:"id"`
	URL   string            `json:"url"`
	Fixes map[string]string `json:"fixes,omitempty"`
}

// ParseReport reads the findings of a Tuner JSON report: one target's
// report object or an array of them, as --json writes for a batch.
func ParseReport(data []byte) ([]Finding, error) {
	type report struct {
		Schema   string    `json:"schema"`
		Findings []Finding `json:"findings"`
	}
	data = bytes.TrimSpace(data)
	var reports []report
	switch {
	case len(data) > 0 && data[0] == '[':
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, err
		}
	case len(data) > 0 && data[0] == '{':
		var r report
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		reports = []report{r}
	default:
		return nil, errors.New("not a JSON report; write one with: rhythm tuner scan <url> --json")
	}
	var out []Finding
	for i, r := range reports {
		if !strings.HasPrefix(r.Schema, "rhythm-tuner/") {
			return nil, fmt.Errorf("report %d is not a Tuner JSON report (schema %q)", i+1, r.Schema)
		}
		out = append(out, r.Findings...)
	}
	return out, nil
}

// Block is one snippet and what it fixes.
type Block struct {
	Snippet string   // config text, trimmed
	Checks  []string // check IDs, sorted
	URLs    []string // finding URLs, in report order without repeats
	// FromReport is set when the snippet came from a report for an ID no
	// known check has, so nothing vouches for it but the report itself.
	FromReport bool
}

// Bundle is the config for one server.
type Bundle struct {
	Server   string
	Blocks   []Block
	Findings int      // findings the blocks cover
	Without  []string // check IDs found with no snippet for this server, sorted
}

// Build collects the snippets for server from findings. For an ID that a
// check in checks has (normally the built-in checks), the check's snippet
// is used and the report's ignored: a report is only JSON that may have
// been shared or edited. The bundle carries Tuner's name, so it must not
// pass on directives such as proxy_pass or include that no check wrote. A finding from any other check uses the report's own Fixes and
// its block says so. Identical
// snippets, after trimming, become one block listing every check that
// needs it, so two checks with the same dotfile rule give one rule.
func Build(findings []Finding, server string, checks []*engine.Check) (*Bundle, error) {
	if !slices.Contains(Servers, server) {
		return nil, fmt.Errorf("unknown server %q: want nginx or apache", server)
	}
	byID := map[string]*engine.Check{}
	for _, c := range checks {
		byID[c.ID] = c
	}
	b := &Bundle{Server: server}
	index := map[string]int{} // snippet → position in b.Blocks
	without := map[string]bool{}
	seen := map[[2]string]bool{} // the same finding from two copies of a report counts once
	for _, f := range findings {
		key := [2]string{f.ID, f.URL}
		if seen[key] {
			continue
		}
		seen[key] = true
		var snippet string
		c := byID[f.ID]
		if c != nil {
			snippet = strings.TrimSpace(snippetFor(c.FixServer, server))
		} else {
			snippet = strings.TrimSpace(f.Fixes[server])
		}
		if snippet == "" {
			without[f.ID] = true
			continue
		}
		i, ok := index[snippet]
		if !ok {
			i = len(b.Blocks)
			index[snippet] = i
			b.Blocks = append(b.Blocks, Block{Snippet: snippet})
		}
		blk := &b.Blocks[i]
		blk.FromReport = blk.FromReport || c == nil
		if !slices.Contains(blk.Checks, f.ID) {
			blk.Checks = append(blk.Checks, f.ID)
			slices.Sort(blk.Checks)
		}
		if f.URL != "" && !slices.Contains(blk.URLs, f.URL) {
			blk.URLs = append(blk.URLs, f.URL)
		}
		b.Findings++
	}
	// Order by check ID so the same reports always give the same bundle,
	// whatever order the targets were scanned in.
	slices.SortStableFunc(b.Blocks, func(x, y Block) int { return strings.Compare(x.Checks[0], y.Checks[0]) })
	for id := range without {
		b.Without = append(b.Without, id)
	}
	slices.Sort(b.Without)
	return b, nil
}

func snippetFor(fs engine.FixServer, server string) string {
	if server == "apache" {
		return fs.Apache
	}
	return fs.Nginx
}

// maxURLs is how many URLs a block's comment lists before it sums up the rest,
// so a batch of a hundred sites still gives a readable bundle.
const maxURLs = 10

// Write prints the bundle as config text: a header saying where it goes,
// then each block under a comment naming its checks and URLs.
func (b *Bundle) Write(w io.Writer, version string) error {
	var buf bytes.Buffer
	for _, line := range b.header(version) {
		buf.WriteString(comment(line))
	}
	if len(b.Blocks) == 0 {
		buf.WriteString(comment("No " + b.Server + " snippets for these findings."))
	}
	for _, blk := range b.Blocks {
		buf.WriteString("\n")
		buf.WriteString(comment(strings.Join(blk.Checks, ", ")))
		for i, u := range blk.URLs {
			if i == maxURLs {
				buf.WriteString(comment(fmt.Sprintf("  and %d more", len(blk.URLs)-maxURLs)))
				break
			}
			buf.WriteString(comment("  " + u))
		}
		if blk.FromReport {
			buf.WriteString(comment("Taken from the report: no Tuner check has this ID. Review it with care."))
		}
		buf.WriteString(inertSnippet(blk.Snippet))
		buf.WriteString("\n")
	}
	if len(b.Without) > 0 {
		buf.WriteString("\n")
		buf.WriteString(comment("No " + b.Server + " snippet for: " + strings.Join(b.Without, ", ")))
		buf.WriteString(comment("See: rhythm tuner explain <id>"))
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// WritePlan prints what the bundle holds without the config text, for
// --dry-run: one line per block with its checks and finding count.
func (b *Bundle) WritePlan(w io.Writer) error {
	var buf bytes.Buffer
	// IDs come from the report, so they go through inert like the
	// bundle's comments do.
	fmt.Fprintf(&buf, "%s bundle: %s for %s\n", b.Server, plural(len(b.Blocks), "snippet"), plural(b.Findings, "finding"))
	for _, blk := range b.Blocks {
		fmt.Fprintf(&buf, "  %s (%s)\n", inert(strings.Join(blk.Checks, ", ")), plural(len(blk.URLs), "URL"))
	}
	if len(b.Without) > 0 {
		fmt.Fprintf(&buf, "no %s snippet: %s\n", b.Server, inert(strings.Join(b.Without, ", ")))
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func (b *Bundle) header(version string) []string {
	lines := []string{
		fmt.Sprintf("Tuner fix bundle for %s, from rhythm-tuner %s.", b.Server, version),
		fmt.Sprintf("%s for %s. Review every block before you use it.", plural(len(b.Blocks), "snippet"), plural(b.Findings, "finding")),
	}
	if b.Server == "apache" {
		return append(lines,
			"Put it inside the site's <VirtualHost> block. Header lines need",
			"mod_headers and SSLProtocol needs mod_ssl. Then run: apachectl -t",
		)
	}
	return append(lines,
		"Put it inside the site's server { } block, above any location ~ \\.php$",
		"block. A location with its own add_header lines drops these headers, so",
		"repeat them there. Then run: nginx -t",
	)
}

// comment makes one line of text a config comment; both servers use #.
// Report text is made inert first: a URL with a line break must not turn
// the rest of its line into config.
func comment(s string) string {
	return strings.TrimRight("# "+inert(s), " ") + "\n"
}

// inert drops control characters from report text, so a crafted report
// can't send escape sequences to a terminal or break a line.
func inert(s string) string { return drop(s, "") }

// inertSnippet is inert for config text, which keeps its line breaks and
// tabs.
func inertSnippet(s string) string { return drop(s, "\n\t") }

// drop removes C0 and C1 control characters other than those in keep.
func drop(s, keep string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0) && !strings.ContainsRune(keep, r) {
			return -1
		}
		return r
	}, s)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
