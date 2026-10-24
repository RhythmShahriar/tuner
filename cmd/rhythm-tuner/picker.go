// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"io"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/local"
)

// pick asks for a target, profile and report format, then scans.
func pick(stdout, stderr io.Writer) int {
	var target string
	profile, output := string(engine.ProfileDefault), "terminal"
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Which site should Tuner scan? (a URL, or a folder on this server)").
			Description("Only scan sites you own or are authorised to test.").
			Placeholder("example.com").
			Value(&target).
			Validate(func(s string) error {
				s = strings.TrimSpace(s)
				if s == "" {
					return errors.New("enter a URL, a hostname, or a site folder")
				}
				if isLocal, err := classifyTarget(s); err != nil || isLocal {
					if err == nil {
						_, err = local.Root(s)
					}
					return err
				}
				_, _, err := engine.ParseTarget(s)
				return err
			}),
		huh.NewSelect[string]().
			Title("Profile").
			Options(
				huh.NewOption("Quick: top checks, about 30 requests", string(engine.ProfileQuick)),
				huh.NewOption("Default: every polite check", string(engine.ProfileDefault)),
			).
			Value(&profile),
		huh.NewSelect[string]().
			Title("Report").
			Options(
				huh.NewOption("Terminal only", "terminal"),
				huh.NewOption("Markdown file (tuner-report.md)", "md"),
				huh.NewOption("JSON file (tuner-report.json)", "json"),
				huh.NewOption("SARIF file (tuner-report.sarif)", "sarif"),
			).
			Value(&output),
	)).WithTheme(huh.ThemeCharm())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return exitCanceled
		}
		printErr(stderr, "", err)
		return exitError
	}
	args := []string{strings.TrimSpace(target), "--profile", profile}
	if output != "terminal" {
		args = append(args, "-o", "tuner-report."+output)
	}
	return scan(args, stdout, stderr)
}
