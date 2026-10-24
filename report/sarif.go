// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// SARIF 2.1.0, the subset GitHub code scanning reads.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	Help             *sarifText     `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

// GitHub ranks alerts by security-severity (0–10).
var securitySeverity = map[engine.Severity]string{
	engine.Critical: "9.5", engine.High: "8.0", engine.Medium: "5.5", engine.Low: "3.0", engine.Info: "0.0",
}

func sarifLevel(s engine.Severity) string {
	switch s {
	case engine.Critical, engine.High:
		return "error"
	case engine.Medium:
		return "warning"
	}
	return "note"
}

// SARIF writes all reports as one SARIF log with a run per target.
func SARIF(w io.Writer, reports []Report, version string) error {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{},
	}
	for _, r := range reports {
		run := sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "rhythm-tuner",
				Version:        version,
				InformationURI: "https://rythm.sh/tuner",
				Rules:          []sarifRule{},
			}},
			Results: []sarifResult{},
		}
		for _, f := range r.Findings {
			if !slices.ContainsFunc(run.Tool.Driver.Rules, func(x sarifRule) bool { return x.ID == f.ID }) {
				rule := sarifRule{
					ID:               f.ID,
					Name:             f.ID,
					ShortDescription: sarifText{f.Title},
					Properties: map[string]any{
						"tags":              append([]string{"security"}, f.Tags...),
						"security-severity": securitySeverity[f.Severity],
					},
				}
				if f.Impact != "" {
					rule.FullDescription = &sarifText{f.Impact}
				}
				if f.Fix != "" {
					rule.Help = &sarifText{f.Fix}
				}
				if len(f.References) > 0 {
					rule.HelpURI = f.References[0]
				}
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			}
			msg := f.Title + " at " + f.URL
			if len(f.Evidence.Matched) > 0 {
				msg += " (" + strings.Join(f.Evidence.Matched, "; ") + ")"
			}
			res := sarifResult{RuleID: f.ID, Level: sarifLevel(f.Severity), Message: sarifText{msg}}
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = f.URL
			res.Locations = []sarifLocation{loc}
			if len(f.Advisories) > 0 {
				var cves []string
				for _, a := range f.Advisories {
					cves = append(cves, a.CVEs...)
				}
				res.Properties = map[string]any{"cves": cves, "advisories": len(f.Advisories), "source": f.Source}
			}
			if len(f.Evidence.Secrets) > 0 {
				var secrets []string
				for _, s := range f.Evidence.Secrets {
					secrets = append(secrets, s.String())
				}
				res.Properties = map[string]any{"secrets": secrets}
			}
			run.Results = append(run.Results, res)
		}
		log.Runs = append(log.Runs, run)
	}
	enc := encoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
