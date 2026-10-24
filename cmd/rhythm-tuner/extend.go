// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"
	"strings"

	"github.com/RhythmShahriar/tuner/report"
)

// Commands and scan extensions let a feature add a subcommand or scan flags
// from its own file, registered in init(), instead of editing main.go and
// scan.go. Each lane of work owns its cmd_<name>.go or ext_<area>.go file,
// so parallel changes never touch the same lines.

// command is a subcommand such as "diff" or "serve".
type command struct {
	Name    string // what users type: rhythm tuner <Name>
	Alias   string // optional short form, like "s" for scan
	Args    string // what follows the name in the usage list, e.g. "<old.json> <new.json>"
	Summary string // one line for the usage list, e.g. "compare two JSON reports"
	Run     func(args []string, stdout, stderr io.Writer) int
}

// scanExtension adds flags and behavior to rhythm tuner scan.
type scanExtension interface {
	// Help returns a section for the scan help, a heading line followed by
	// flag lines in the same layout as the built-in ones.
	Help() string
	// Flags registers the extension's flags on the scan flag set.
	Flags(fs *flag.FlagSet)
	// Plan runs after the built-in planning and may edit p.targets,
	// p.engine, p.local and p.write. Return a usageError (usagef) for bad flags.
	Plan(p *scanPlan) error
	// Finished runs after the report is written. The highest exit code
	// among the scan and every extension wins; an error is printed and
	// counts as a scan error.
	Finished(p *scanPlan, reports []report.Report, stderr io.Writer) (exit int, err error)
}

var (
	commands       []command
	scanExtensions []scanExtension
)

// registerCommand adds a subcommand. It panics on a name that is already
// taken, which init() turns into a failure every test run catches.
func registerCommand(c command) {
	for _, name := range []string{c.Name, c.Alias} {
		if name == "" {
			continue
		}
		if lookupCommand(name) != nil || builtinCommand(name) {
			panic("rhythm tuner: command " + name + " registered twice")
		}
	}
	commands = append(commands, c)
}

// registerScanExtension adds flags and behavior to scan. Extensions run in
// registration order, which follows file names because init() does.
func registerScanExtension(e scanExtension) { scanExtensions = append(scanExtensions, e) }

func lookupCommand(name string) *command {
	for i := range commands {
		if commands[i].Name == name || commands[i].Alias != "" && commands[i].Alias == name {
			return &commands[i]
		}
	}
	return nil
}

// builtinCommand reports whether run handles name itself.
func builtinCommand(name string) bool {
	switch name {
	case "-h", "--help", "help", "-v", "--version", "version", "scan", "s", "checks", "ls", "update":
		return true
	}
	return false
}

// commandUsage lists the registered commands for the Usage list; name is
// what starts Tuner, as cmdName gives it.
func commandUsage(name string) []usageLine {
	var lines []usageLine
	for _, c := range commands {
		cmd := name + " " + c.Name
		if c.Args != "" {
			cmd += " " + c.Args
		}
		lines = append(lines, usageLine{cmd: cmd, summary: c.Summary})
	}
	return lines
}

// extensionHelp joins every scan extension's help section.
func extensionHelp() string {
	var b strings.Builder
	for _, e := range scanExtensions {
		if h := strings.TrimRight(e.Help(), "\n"); h != "" {
			b.WriteString(h + "\n\n")
		}
	}
	return b.String()
}
