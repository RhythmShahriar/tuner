// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Bench holds a run's settings.
type Bench struct {
	TunerBin  string        // the rhythm-tuner binary to score
	DockerNet string        // docker network the WPScan container joins; "host" reaches the loopback testbed
	Timeout   time.Duration // per tool, per site
	Tools     []*Tool       // the tools to run (Tuner always)
}

// main runs the benchmark: every tool against every testbed site.
func main() {
	var (
		manifestPath = flag.String("manifest", "testbed/ground-truth.yaml", "the ground-truth manifest")
		out          = flag.String("o", "docs/benchmark.md", "where to write the scoreboard")
		tunerBin     = flag.String("tuner", "", "the rhythm-tuner binary (default: build this checkout)")
		only         = flag.String("tools", "", "comma-separated tool keys to run (default all): tuner,wpscan,wpprobe,nuclei")
		dockerNet    = flag.String("docker-net", "host", "docker network for the WPScan container")
		timeout      = flag.Duration("timeout", 5*time.Minute, "per tool, per site")
	)
	flag.Parse()

	if err := runMain(*manifestPath, *out, *tunerBin, *only, *dockerNet, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

// runMain loads the manifest, runs the tools and writes the scoreboard.
func runMain(manifestPath, out, tunerBin, only, dockerNet string, timeout time.Duration) error {
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	tools, err := pickTools(only)
	if err != nil {
		return err
	}
	bin := tunerBin
	if bin == "" {
		if bin, err = buildTuner(); err != nil {
			return fmt.Errorf("building rhythm-tuner: %w", err)
		}
	}
	b := &Bench{TunerBin: bin, DockerNet: dockerNet, Timeout: timeout, Tools: tools}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sites := siteOrder(m)
	version := tunerVersion(bin)
	var scores []Score
	for _, name := range sites {
		site := m.Sites[name]
		for _, t := range b.Tools {
			fmt.Fprintf(os.Stderr, "== %s on %s (%s)\n", t.Name, name, site.URL)
			rep := t.Scan(ctx, b, name, site)
			s := score(m, t.Name, name, site, rep)
			scores = append(scores, s)
			fmt.Fprintln(os.Stderr, "   "+summary(s))
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}

	board := newBoard(m, sites, scores)
	md := scoreboard(board, version, time.Now())
	if err := os.WriteFile(out, []byte(md), 0o644); err != nil { //nolint:gosec // a docs file
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return nil
}

// pickTools returns the tools named in only, Tuner always first.
func pickTools(only string) ([]*Tool, error) {
	if only == "" {
		return allTools, nil
	}
	want := map[string]bool{"tuner": true}
	for _, k := range strings.Split(only, ",") {
		want[strings.TrimSpace(k)] = true
	}
	var out []*Tool
	for _, t := range allTools {
		if want[t.Key] {
			out = append(out, t)
			delete(want, t.Key)
		}
	}
	delete(want, "tuner")
	if len(want) > 0 {
		var bad []string
		for k := range want {
			bad = append(bad, k)
		}
		sort.Strings(bad)
		return nil, fmt.Errorf("unknown tool(s): %s", strings.Join(bad, ", "))
	}
	return out, nil
}

// siteOrder lists site names with "main" first, then the rest sorted.
func siteOrder(m *Manifest) []string {
	var names []string
	for n := range m.Sites {
		names = append(names, n)
	}
	sort.Strings(names)
	if i := slices.Index(names, "main"); i > 0 {
		names = append([]string{"main"}, slices.Delete(names, i, i+1)...)
	}
	return names
}

// buildTuner compiles this checkout's rhythm-tuner.
func buildTuner() (string, error) {
	dir, err := os.MkdirTemp("", "tuner-bench-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "rhythm-tuner")
	out, err := run(context.Background(), 5*time.Minute, "go", "build", "-o", bin, "./cmd/rhythm-tuner")
	if err != nil {
		return "", fmt.Errorf("%w\n%s", err, out)
	}
	return bin, nil
}

// tunerVersion is the version bin reports, or "".
func tunerVersion(bin string) string {
	out, err := run(context.Background(), 30*time.Second, bin, "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "rhythm-tuner"))
}

// summary is one line on how a tool did on a site.
func summary(s Score) string {
	switch {
	case s.NotRun:
		return "not run"
	case s.Error != "":
		return "error: " + firstLine(s.Error)
	default:
		msg := fmt.Sprintf("%d plugins (%d vulnerable), %d false, %s", len(s.Found), len(s.VulnFound), len(s.FalsePos), s.Duration.Round(100*time.Millisecond))
		if s.ScoresFiles {
			msg += fmt.Sprintf(", %d files", len(s.FilesFound))
		}
		if s.Blocked {
			msg += ", blocked"
		}
		return msg
	}
}
