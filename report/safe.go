// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Everything a scanned site or a scanned folder can write ends up in a
// report: response bodies, the Server header, plugin slugs, file names,
// mu-plugin headers. A terminal treats control bytes in them as commands
// (OSC 52 writes the clipboard, ESC[2K erases the finding that names the
// attacker) and Markdown treats markup in them as images and links. The
// functions here make such strings inert for each output.

// SafeText replaces control characters (C0 except tab, DEL and C1) and
// invalid UTF-8 with U+FFFD, so a string prints as text on any terminal.
func SafeText(s string) string { return clean(s, false) }

// safeBlock is SafeText for multi-line text such as a fix: it keeps line
// breaks (as \n) and replaces every other control character.
func safeBlock(s string) string {
	return clean(strings.ReplaceAll(s, "\r\n", "\n"), true)
}

func clean(s string, keepNewline bool) string {
	unsafe := func(r rune) bool {
		switch {
		case r == '\t', keepNewline && r == '\n':
			return false
		case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
			return true
		}
		return false
	}
	if utf8.ValidString(s) && strings.IndexFunc(s, unsafe) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s { // invalid bytes arrive as utf8.RuneError
		if unsafe(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
	}
	return b.String()
}

var mdReplacer = func() *strings.Replacer {
	var pairs []string
	for _, c := range "\\`*_[]()!<>|#~" {
		pairs = append(pairs, string(c), "\\"+string(c))
	}
	// Entities would let "&lt;img" through as an image once rendered.
	pairs = append(pairs, "&", "&amp;", "\r\n", " ", "\n", " ", "\r", " ")
	// A site-derived "@org/team" pasted into an issue would ping real
	// people. GitHub drops Markdown escapes and decodes entities before it
	// looks for mentions, so only a character between the @ and the name
	// stops it: U+2060 WORD JOINER is invisible and doesn't break the line.
	pairs = append(pairs, "@", "@\u2060")
	return strings.NewReplacer(pairs...)
}()

// MDText makes s safe as inline Markdown text: control characters are
// replaced, Markdown and HTML punctuation is escaped, line breaks become
// spaces and @mentions are broken, so s can't open an image, link,
// heading or table cell or ping anyone.
func MDText(s string) string { return mdReplacer.Replace(SafeText(oneLine(s))) }

// MDCode renders s as an inline code span. The fence is one backtick
// longer than the longest run of backticks in s, so s can't close it.
// Use MDCodeCell inside a table.
func MDCode(s string) string { return mdCode(s, false) }

// MDCodeCell is MDCode for a table cell: pipes are escaped so they can't
// end the cell. GitHub strips the backslash there but would show it in
// a code span outside a table.
func MDCodeCell(s string) string { return mdCode(s, true) }

func mdCode(s string, cell bool) string {
	s = SafeText(oneLine(s))
	if s == "" {
		return "` `"
	}
	fence := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	if cell {
		s = strings.ReplaceAll(s, "|", `\|`)
	}
	return fence + s + fence
}

// mdFence renders multi-line s as a fenced code block that s can't close.
func mdFence(s string) string {
	s = safeBlock(s)
	fence := strings.Repeat("`", max(3, longestRun(s, '`')+1))
	return fence + "\n" + s + "\n" + fence
}

// SafeLink renders a Markdown link to target with text as its label, or
// only the escaped text when target is not an http or https URL.
func SafeLink(text, target string) string {
	label := MDText(text)
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return label
	}
	u.User = nil
	// url.String leaves these as they are; each would end the link early,
	// start markup inside it or split a table cell.
	href := strings.NewReplacer("(", "%28", ")", "%29", "<", "%3C", ">", "%3E", " ", "%20", "`", "%60", "\\", "%5C", "[", "%5B", "]", "%5D", "|", "%7C").
		Replace(SafeText(u.String()))
	return "[" + label + "](" + href + ")"
}

func oneLine(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

func longestRun(s string, c byte) int {
	best, n := 0, 0
	for i := range len(s) {
		if s[i] == c {
			n++
			best = max(best, n)
		} else {
			n = 0
		}
	}
	return best
}

// multiLine names the struct fields whose text has line breaks on purpose.
// They come from check definitions. Advisor fixes quote slugs and
// versions, so they are cleaned too (keeping \n).
var multiLine = map[string]bool{"Fix": true, "Impact": true}

// sanitized returns a deep copy of v with every string cleaned by
// SafeText (safeBlock for multi-line fields). It walks the value with
// reflection so a field added to engine.Result later is covered without
// anyone remembering to list it here.
func sanitized[T any](v T) T {
	rv := reflect.ValueOf(&v).Elem()
	out := reflect.New(rv.Type()).Elem()
	copyClean(out, rv, false)
	return out.Interface().(T) // out was made from v's type, so this cannot fail
}

func copyClean(dst, src reflect.Value, block bool) {
	switch src.Kind() {
	case reflect.String:
		if block {
			dst.SetString(safeBlock(src.String()))
		} else {
			dst.SetString(SafeText(src.String()))
		}
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		p := reflect.New(src.Type().Elem())
		copyClean(p.Elem(), src.Elem(), block)
		dst.Set(p)
	case reflect.Struct:
		dst.Set(src) // unexported fields (time.Time's) keep their values
		t := src.Type()
		for i := range src.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			copyClean(dst.Field(i), src.Field(i), multiLine[t.Field(i).Name])
		}
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			copyClean(s.Index(i), src.Index(i), block)
		}
		dst.Set(s)
	case reflect.Array:
		for i := range src.Len() {
			copyClean(dst.Index(i), src.Index(i), block)
		}
	case reflect.Map:
		if src.IsNil() {
			return
		}
		m := reflect.MakeMapWithSize(src.Type(), src.Len())
		it := src.MapRange()
		for it.Next() {
			k := reflect.New(src.Type().Key()).Elem()
			copyClean(k, it.Key(), false)
			e := reflect.New(src.Type().Elem()).Elem()
			copyClean(e, it.Value(), block)
			m.SetMapIndex(k, e)
		}
		dst.Set(m)
	default: // numbers, bools, interfaces (errors are cleaned where printed)
		dst.Set(src)
	}
}
