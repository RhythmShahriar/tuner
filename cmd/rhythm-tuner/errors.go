// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Every error Tuner prints reads "<name> <command>: <message>", such as
// "rhythm tuner scan: unknown flag --jsn; did you mean --json?", so a
// line in a CI log says which command failed.

// errPrefix starts an error line for cmd, or for Tuner itself when cmd is
// empty.
func errPrefix(cmd string) string {
	if cmd == "" {
		return cmdName() + ":"
	}
	return cmdName() + " " + cmd + ":"
}

// printErr writes one error line for cmd.
func printErr(w io.Writer, cmd string, a ...any) {
	fmt.Fprintln(w, append([]any{errPrefix(cmd)}, a...)...)
}

// The messages flag.Parse returns. They have read the same since Go 1.0.
var (
	flagUndefined = regexp.MustCompile(`^flag provided but not defined: -(.+)$`)
	flagNoValue   = regexp.MustCompile(`^flag needs an argument: -(.+)$`)
	flagBadValue  = regexp.MustCompile(`^invalid value "(.*)" for flag -([^:]+): (.*)$`)
	flagBadBool   = regexp.MustCompile(`^invalid boolean value "(.*)" for -([^:]+): `)
)

// flagError turns an error from parsing fs into a usage error that names
// the flag as people type it (--json, not -json) and says what to do.
func flagError(fs *flag.FlagSet, err error) error {
	msg := err.Error()
	if m := flagUndefined.FindStringSubmatch(msg); m != nil {
		// -Q may be -q while --x should not turn into -o: compare long
		// names with long names and letters with letters.
		typed := strings.TrimLeft(m[1], "-")
		var names []string
		fs.VisitAll(func(f *flag.Flag) {
			if len(f.Name) > 1 == (len(typed) > 1) {
				names = append(names, f.Name)
			}
		})
		out := "unknown flag " + dashed(m[1])
		if s := suggest(typed, names); s != "" {
			out += "; did you mean " + dashed(s) + "?"
		}
		return usageError{Msg: out}
	}
	if m := flagNoValue.FindStringSubmatch(msg); m != nil {
		return usagef("%s needs a value", dashed(m[1]))
	}
	if m := flagBadBool.FindStringSubmatch(msg); m != nil {
		return usagef("%s=%s: want true or false", dashed(m[2]), m[1])
	}
	if m := flagBadValue.FindStringSubmatch(msg); m != nil {
		value, name := m[1], m[2]
		var want string
		if f := fs.Lookup(name); f != nil {
			if g, ok := f.Value.(flag.Getter); ok {
				switch g.Get().(type) {
				case time.Duration:
					want = "want a duration, for example 10s or 2m"
					if _, err := strconv.ParseFloat(value, 64); err == nil {
						want = "use a unit, for example " + value + "s"
					}
				case int:
					want = "want a whole number"
				case float64:
					want = "want a number"
				}
			}
		}
		if want == "" {
			want = m[3]
		}
		return usagef("%s %s: %s", dashed(name), value, want)
	}
	return usageError{Msg: msg}
}

// dashed writes a flag name the way the help shows it: -o, --output.
func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// suggest returns the option closest to word, for "did you mean", or ""
// when none is within two edits. Short words need a closer match, so "x"
// doesn't turn into "o".
func suggest(word string, options []string) string {
	best, bestDist := "", 3
	limit := 2
	switch len(word) {
	case 0:
		return ""
	case 1:
		limit = 0 // only another case: -Q for -q
	case 2:
		limit = 1
	}
	for _, o := range options {
		if d := editDistance(strings.ToLower(word), strings.ToLower(o)); d <= limit && d < bestDist {
			best, bestDist = o, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b, counting a
// swap of two adjacent letters (scna, scan) as one edit.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(rb)]
}

// unknownCommand explains a first argument that is not a command, with a
// suggestion when one is close, instead of printing the whole help.
func unknownCommand(arg string) error {
	names := []string{"scan", "checks", "update", "help", "version"}
	for _, c := range commands {
		names = append(names, c.Name)
	}
	hint := fmt.Sprintf("\n  run '%s --help' for the commands", cmdName())
	if s := suggest(arg, names); s != "" {
		return usagef("unknown command %s; did you mean %s?%s", shown(arg), s, hint)
	}
	// rhythm tuner example.com: the scan command was left out.
	if !strings.HasPrefix(arg, "-") && strings.ContainsAny(arg, "./:") {
		return usagef("unknown command %s; to scan it, run: %s scan %s", shown(arg), cmdName(), arg)
	}
	return usagef("unknown command %s%s", shown(arg), hint)
}

// oneOf lower-cases value and checks it against options, so --fail-on
// HIGH works. The error names the flag and every valid value.
func oneOf[T ~string](flagName, value string, options []T) (T, error) {
	v := T(strings.ToLower(strings.TrimSpace(value)))
	if slices.Contains(options, v) {
		return v, nil
	}
	list := make([]string, len(options))
	for i, o := range options {
		list[i] = string(o)
	}
	msg := fmt.Sprintf("--%s %s: want %s", flagName, shown(value), orList(list))
	if s := suggest(strings.ToLower(value), list); s != "" {
		msg += "; did you mean " + s + "?"
	}
	return "", usageError{Msg: msg}
}

// shown prints a flag value in a message: as typed, or quoted when it is
// empty or holds spaces, so the message still reads.
func shown(v string) string {
	if v == "" || strings.ContainsAny(v, " \t") || !printable(v) {
		return strconv.Quote(v)
	}
	return v
}

// orList joins options as "a, b or c".
func orList(options []string) string {
	if len(options) < 2 {
		return strings.Join(options, "")
	}
	return strings.Join(options[:len(options)-1], ", ") + " or " + options[len(options)-1]
}

// unwrapPath drops the operation and path from a *os.PathError, for a
// message that already names the file: "-l x.txt: permission denied"
// rather than "-l x.txt: open x.txt: permission denied".
func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
