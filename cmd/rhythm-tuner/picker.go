package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/RhythmShahriar/tuner/engine"
)

// pick asks for a target, profile and report format, then scans.
func pick(stdout, stderr io.Writer) int {
	var target string
	profile, output := string(engine.ProfileDefault), "terminal"
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Which site should Tuner scan?").
			Description("Only scan sites you own or are authorised to test.").
			Placeholder("example.com").
			Value(&target).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("enter a URL or hostname")
				}
				_, _, err := engine.ParseTarget(strings.TrimSpace(s))
				return err
			}),
		huh.NewSelect[string]().
			Title("Profile").
			Options(
				huh.NewOption("Quick: top checks, about 30 requests", string(engine.ProfileQuick)),
				huh.NewOption("Default: every polite check", string(engine.ProfileDefault)),
				huh.NewOption("Deep: adds enumeration", string(engine.ProfileDeep)),
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
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	args := []string{strings.TrimSpace(target), "--profile", profile}
	if output != "terminal" {
		args = append(args, "-o", "tuner-report."+output)
	}
	return scan(args, stdout, stderr)
}
