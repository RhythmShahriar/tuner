// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
	"github.com/RhythmShahriar/tuner/report"
)

// mask is what matchers.Mask puts in place of the hidden part of a secret.
const mask = "•••••"

// minLeak is the shortest raw value worth looking for; shorter ones match
// ordinary words in a report by chance.
const minLeak = 6

// window is how much of a hidden value must appear for it to count as a
// leak. Looking for windows rather than the whole value also catches a
// secret cut short by truncation, which redaction no longer recognizes.
const window = 8

// render returns res as each output format a user can pick: plain
// terminal text, JSON, SARIF and Markdown.
func render(res *engine.Result) (map[string][]byte, error) {
	reports := []report.Report{report.New(res, "test")}
	out := map[string][]byte{}

	var plain bytes.Buffer
	p := report.NewPretty(&plain, &plain, report.PrettyOptions{Plain: true})
	for _, f := range res.Findings {
		p.Finding(f)
	}
	p.Summary(res, res.Target, report.Hidden{})
	out["plain"] = plain.Bytes()

	var js, sarif, md bytes.Buffer
	if err := report.JSON(&js, reports, false); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if err := report.SARIF(&sarif, reports, "test"); err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}
	if err := report.Markdown(&md, reports); err != nil {
		return nil, fmt.Errorf("markdown: %w", err)
	}
	out["json"], out["sarif"], out["md"] = js.Bytes(), sarif.Bytes(), md.Bytes()
	return out, nil
}

// envLine is a KEY=value line as in a .env file, shell profile or ini.
var envLine = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=[ \t]*(.*?)[ \t]*$`)

// jsonPair is a "key": "value" string pair, as in auth.json.
var jsonPair = regexp.MustCompile(`"[^"\n]+"\s*:\s*"([^"\n]*)"`)

// rawValues lists the strings from a fixture body that must never reach a
// report: the hidden part of every secret matchers finds and, when
// keyValues is set, every value of a KEY=value line or a JSON string
// pair, whatever the key.
func rawValues(body []byte, keyValues bool) []string {
	var out []string
	for _, v := range hiddenParts(string(body), matchers.Redact(string(body))) {
		out = append(out, windows(v)...)
	}
	if keyValues {
		for _, re := range []*regexp.Regexp{envLine, jsonPair} {
			for _, m := range re.FindAllSubmatch(body, -1) {
				v := strings.Trim(string(m[1]), `"'`)
				if utf8.RuneCountInString(v) >= minLeak {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// hiddenParts recovers the text matchers.Redact hid in body, by lining
// body up against its redacted form. Redact keeps everything outside a
// secret as is and puts the mask after a secret's kept prefix, so the
// text between two masks in redacted is the text that follows the hidden
// part in body. When that text also occurs inside the secret, the hidden
// part found is shorter than the real one: still raw secret text, so the
// check only gets stricter.
func hiddenParts(body, redacted string) []string {
	parts := strings.Split(redacted, mask)
	if len(parts) == 1 {
		return nil
	}
	var out []string
	pos := 0
	for i := 0; i < len(parts)-1; i++ {
		if !strings.HasPrefix(body[pos:], parts[i]) {
			return out // the body itself holds a mask; nothing more to line up
		}
		start := pos + len(parts[i])
		next := parts[i+1]
		var end int
		switch {
		case i+1 == len(parts)-1:
			end = len(body) - len(next)
		case next == "":
			// Two masks in a row: the hidden part runs to the next space.
			end = start + strings.IndexFunc(body[start:]+" ", isSpace)
		default:
			// The first place after at least one hidden byte where the
			// following text resumes.
			n := strings.Index(body[min(start+1, len(body)):], next)
			if n < 0 {
				return out
			}
			end = start + 1 + n
		}
		if end <= start {
			return out
		}
		out = append(out, body[start:end])
		pos = end
	}
	return out
}

// isSpace reports whether r is ASCII whitespace.
func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }

// windows splits v into every run of window runes, or returns v whole
// when it is shorter. Values shorter than minLeak are skipped.
func windows(v string) []string {
	r := []rune(v)
	if len(r) < minLeak {
		return nil
	}
	if len(r) <= window {
		return []string{v}
	}
	out := make([]string, 0, len(r)-window+1)
	for i := 0; i+window <= len(r); i++ {
		out = append(out, string(r[i:i+window]))
	}
	return out
}

// controlBytes are the terminal escape introducers: ESC, BEL and the
// 8-bit CSI. Any of them in a report lets a site rewrite a terminal.
var controlBytes = map[rune]string{0x1b: "ESC (0x1b)", 0x07: "BEL (0x07)", 0x9b: "CSI (0x9b)"}

// leaks checks one rendered report for raw values and control bytes. It
// skips values that also appear in the check's own source, such as a word
// in its title, since those did not come from the site.
func leaks(format string, out []byte, raw []string, source []byte) []string {
	var found []string
	seen := map[string]bool{}
	for _, v := range raw {
		if seen[v] || bytes.Contains(source, []byte(v)) || !bytes.Contains(out, []byte(v)) {
			continue
		}
		seen[v] = true
		found = append(found, fmt.Sprintf("%s output shows raw value %q", format, v))
	}
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRune(out[i:])
		if r == utf8.RuneError && size == 1 {
			r = rune(out[i]) // a lone byte, such as a raw 0x9b
		}
		if name, ok := controlBytes[r]; ok && !seen[name] {
			seen[name] = true
			found = append(found, fmt.Sprintf("%s output holds control byte %s at offset %d", format, name, i))
		}
		i += size
	}
	return found
}
