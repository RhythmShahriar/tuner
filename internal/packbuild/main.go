// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// packbuild builds the check pack release assets from checks/. CI and
// `make pack` both run it, so a local build matches the published one byte
// for byte given the same commit:
//
//	go run ./internal/packbuild -commit "$(git rev-parse HEAD)" -time "$(git log -1 --format=%cI)"
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/RhythmShahriar/tuner/checkpack"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("packbuild", flag.ContinueOnError)
	flags.SetOutput(stderr)
	src := flags.String("src", "checks", "checks directory")
	out := flags.String("out", "dist/checks-pack", "output directory")
	commit := flags.String("commit", "", "commit SHA the pack is built from (required)")
	at := flags.String("time", "", "that commit's time, RFC 3339 (required)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	created, err := time.Parse(time.RFC3339, *at)
	if *commit == "" || err != nil {
		fmt.Fprintln(stderr, "packbuild: -commit and an RFC 3339 -time are required")
		return 2
	}

	built, err := checkpack.Build(os.DirFS(*src), *commit, created)
	if err != nil {
		fmt.Fprintln(stderr, "packbuild:", err)
		return 1
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fmt.Fprintln(stderr, "packbuild:", err)
		return 1
	}
	names := make([]string, 0, len(built.Files))
	for name := range built.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		p := filepath.Join(*out, name)
		if err := os.WriteFile(p, built.Files[name], 0o644); err != nil { //nolint:gosec // public release assets
			fmt.Fprintln(stderr, "packbuild:", err)
			return 1
		}
		fmt.Fprintln(stdout, p)
	}
	m := built.Manifest
	fmt.Fprintf(stdout, "pack %s: %d checks, min rhythm-tuner %s, commit %s\n", m.Version, m.Checks, m.MinTuner, m.Commit)
	return 0
}
