// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Pinned versions of the tools the benchmark compares Tuner with. WPScan
// runs from its official image (no API token: detection only). wpprobe
// and Nuclei run from a binary on PATH, installed at these versions by
// the nightly workflow.
const (
	wpscanImage    = "wpscanteam/wpscan:v3.8.28"
	wpprobeVersion = "v0.12.12"
	nucleiVersion  = "v3.11.1"
)

// Tool is one scanner in the benchmark.
type Tool struct {
	Key   string // short id, also the docs column slug
	Name  string // column name
	About string // one line for the scoreboard footer
	// Scan runs the tool against a site and returns its raw report. It
	// must make no request off the testbed hosts.
	Scan func(ctx context.Context, b *Bench, name string, site Site) *Report
}

// allTools is the benchmark's column order.
var allTools = []*Tool{
	{
		Key: "tuner", Name: "Tuner",
		About: "this project; a remote scan reads readme, REST and asset URLs and also reports exposed files",
		Scan:  scanTuner,
	},
	{
		Key: "wpscan", Name: "WPScan",
		About: "`" + wpscanImage + "` with no API token, so detection only (plugins it can see, no advisory lookups)",
		Scan:  scanWPScan,
	},
	{
		Key: "wpprobe", Name: "wpprobe",
		About: "`Chocapikk/wpprobe " + wpprobeVersion + "` in hybrid mode (REST plus brute force)",
		Scan:  scanWpprobe,
	},
	{
		Key: "nuclei", Name: "Nuclei",
		About: "`projectdiscovery/nuclei " + nucleiVersion + "` with the http/technologies WordPress templates",
		Scan:  scanNuclei,
	},
}

// run executes a command with a timeout and returns combined output.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // benchmark tools named by the harness
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// scanTuner runs this checkout's rhythm-tuner and reads its JSON report.
func scanTuner(ctx context.Context, b *Bench, name string, site Site) *Report {
	start := time.Now()
	out, err := run(ctx, b.Timeout, b.TunerBin, "scan", site.URL,
		"--json", "--plain", "-q", "--rate", "0", "--no-check-updates")
	rep := &Report{ScoresFiles: true, Requests: -1, Duration: time.Since(start)}
	doc, perr := parseTunerJSON(out)
	switch {
	case doc != nil:
		rep.Plugins, rep.Files, rep.Blocked, rep.Requests = doc.plugins, doc.files, doc.blocked, doc.requests
	case err != nil:
		rep.Err = toolError(out, err)
	default:
		rep.Err = perr.Error()
	}
	return rep
}

type tunerDoc struct {
	plugins, files []string
	blocked        bool
	requests       int64
}

// parseTunerJSON pulls plugins, exposed-file paths and the blocked flag
// out of a Tuner report (an object for one target).
func parseTunerJSON(out string) (*tunerDoc, error) {
	start := strings.IndexAny(out, "{[")
	if start < 0 {
		return nil, fmt.Errorf("no JSON in Tuner output")
	}
	var raw struct {
		BlockedBy   string `json:"blocked_by"`
		Requests    int64  `json:"requests"`
		Fingerprint struct {
			Components []struct {
				Type string `json:"type"`
				Slug string `json:"slug"`
			} `json:"components"`
		} `json:"fingerprint"`
		Findings []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out[start:]), &raw); err != nil {
		return nil, fmt.Errorf("Tuner JSON: %w", err)
	}
	doc := &tunerDoc{blocked: raw.BlockedBy != "", requests: raw.Requests}
	for _, c := range raw.Fingerprint.Components {
		if c.Type == "plugin" {
			doc.plugins = append(doc.plugins, c.Slug)
		}
	}
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.ID, "leak-") || f.ID == "wp-debug-log" {
			doc.files = append(doc.files, f.Path)
		}
	}
	return doc, nil
}

// scanWPScan runs the WPScan image against a site. No token, so it only
// enumerates; the network is the host's so the loopback testbed is
// reachable.
func scanWPScan(ctx context.Context, b *Bench, name string, site Site) *Report {
	start := time.Now()
	out, err := run(ctx, b.Timeout, "docker", "run", "--rm", "--network", b.DockerNet,
		wpscanImage, "--url", site.URL, "--no-banner", "--format", "json",
		"--enumerate", "p", "--plugins-detection", "mixed", "--random-user-agent")
	rep := &Report{Requests: -1, Duration: time.Since(start)}
	plugins, perr := parseWPScanJSON(out)
	switch {
	case perr == nil:
		rep.Plugins = plugins
	case err != nil:
		rep.Err = toolError(out, err)
	default:
		rep.Err = perr.Error()
	}
	return rep
}

func parseWPScanJSON(out string) ([]string, error) {
	start := strings.IndexByte(out, '{')
	if start < 0 {
		return nil, fmt.Errorf("no JSON in WPScan output")
	}
	var raw struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(out[start:]), &raw); err != nil {
		return nil, fmt.Errorf("WPScan JSON: %w", err)
	}
	var out2 []string
	for slug := range raw.Plugins {
		out2 = append(out2, slug)
	}
	return out2, nil
}

// scanWpprobe runs wpprobe in hybrid mode and reads its JSON.
func scanWpprobe(ctx context.Context, b *Bench, name string, site Site) *Report {
	start := time.Now()
	out, err := run(ctx, b.Timeout, "wpprobe", "scan", "-u", site.URL, "--mode", "hybrid", "--no-color")
	rep := &Report{Requests: -1, Duration: time.Since(start)}
	plugins, perr := parseWpprobeJSON(out)
	switch {
	case perr == nil:
		rep.Plugins = plugins
	case err != nil:
		rep.Err = toolError(out, err)
	default:
		rep.Err = perr.Error()
	}
	return rep
}

// parseWpprobeJSON reads wpprobe's array of targets, each with a plugins
// map keyed by slug.
func parseWpprobeJSON(out string) ([]string, error) {
	start := strings.IndexByte(out, '[')
	if start < 0 {
		return nil, fmt.Errorf("no JSON array in wpprobe output")
	}
	var raw []struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(out[start:]), &raw); err != nil {
		return nil, fmt.Errorf("wpprobe JSON: %w", err)
	}
	var out2 []string
	for _, t := range raw {
		for slug := range t.Plugins {
			out2 = append(out2, slug)
		}
	}
	return out2, nil
}

// scanNuclei runs Nuclei's WordPress technology templates and reads the
// plugin slugs from the JSONL output.
func scanNuclei(ctx context.Context, b *Bench, name string, site Site) *Report {
	start := time.Now()
	out, err := run(ctx, b.Timeout, "nuclei", "-u", site.URL, "-jsonl", "-silent", "-disable-update-check",
		"-tags", "wordpress,tech", "-rate-limit", "50")
	rep := &Report{Requests: -1, Duration: time.Since(start)}
	plugins := parseNucleiJSONL(out)
	if len(plugins) == 0 && err != nil {
		rep.Err = toolError(out, err)
		return rep
	}
	rep.Plugins = plugins
	return rep
}

// parseNucleiJSONL reads one JSON object per line and keeps the plugin
// slug from a wordpress-plugin-detect template's matched URL.
func parseNucleiJSONL(out string) []string {
	var slugs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var ev struct {
			TemplateID  string `json:"template-id"`
			MatchedAt   string `json:"matched-at"`
			ExtractedAt string `json:"extracted-results"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if s := slugFromPath(ev.MatchedAt); s != "" {
			slugs = append(slugs, s)
		}
	}
	return slugs
}

// slugFromPath returns the plugin slug in a wp-content/plugins/<slug>/ URL.
func slugFromPath(s string) string {
	const marker = "/wp-content/plugins/"
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if j := strings.IndexAny(rest, "/?"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// toolError trims a tool's output into a short error line.
func toolError(out string, err error) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return err.Error()
	}
	lines := strings.Split(out, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if last == "" && len(lines) > 1 {
		last = strings.TrimSpace(lines[len(lines)-2])
	}
	return fmt.Sprintf("%v: %s", err, last)
}
