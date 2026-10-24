// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"cmp"
	"io"
	"net/url"
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
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	// OriginalURIBaseIDs says where SRCROOT is on disk for a local scan,
	// so code scanning can map the relative locations onto the repository.
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult                    `json:"results"`
}

// sarifInvocation says whether the run finished. A partial scan sets
// executionSuccessful to false and explains why in a notification, so a
// reader of the alerts knows some may be missing.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
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
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints lets code scanning follow an alert across runs.
	// Without it, a URL finding (no source file to hash) shows up as a
	// new alert after every upload.
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// srcRoot names the folder a local scan started from. GitHub's upload
// action resolves it to the checkout, so a repository scanned in CI gets
// alerts on its own files.
const srcRoot = "SRCROOT"

// fingerprintKey is the partialFingerprints entry Tuner writes. The
// version suffix changes if Fingerprint ever does.
const fingerprintKey = "tunerFinding/v1"

// Finding Reference on the wiki: every ID with its meaning and fix.
const findingReference = "https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Finding-Reference"

// helpURI links a rule to its entry in the Finding Reference. Checks link
// to their own ID; advisor and local findings, whose IDs carry a slug, to
// their section.
//
// Once advisors register rules with a help URL (engine.Rules), that URL
// wins for their IDs.
func helpURI(id string) string {
	switch {
	case strings.HasPrefix(id, "local-"):
		return findingReference + "#local-findings"
	case engine.IsAdvisorID(id):
		return findingReference + "#vulnerability-and-version-findings"
	}
	return findingReference + "#" + url.PathEscape(id)
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
	return Write("sarif", w, reports, WriteOptions{Version: version})
}

// writeSARIF writes a run per scanned target and one per target that
// could not be scanned. A failed target's run has no results and
// executionSuccessful false, so an upload for a site that was down says so
// instead of looking like a clean scan (an empty runs list would).
func writeSARIF(w io.Writer, reports []Report, o WriteOptions) error {
	version := SafeText(o.Version)
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{},
	}
	newRun := func() sarifRun {
		return sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "rhythm-tuner",
				Version:        version,
				InformationURI: "https://rythm.sh/tuner",
				Rules:          []sarifRule{},
			}},
			Results: []sarifResult{},
		}
	}
	for _, r := range reports {
		run := newRun()
		root := localRoot(r, o.Root)
		if root != "" {
			run.OriginalURIBaseIDs = map[string]sarifArtifactLocation{srcRoot: {URI: fileURI(root) + "/"}}
		}
		st := r.Status()
		inv := sarifInvocation{ExecutionSuccessful: !st.Partial()}
		for _, n := range st.Notes() {
			inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{"warning", sarifText{n}})
		}
		run.Invocations = []sarifInvocation{inv}
		for _, f := range r.Findings {
			if !slices.ContainsFunc(run.Tool.Driver.Rules, func(x sarifRule) bool { return x.ID == f.ID }) {
				rule := sarifRule{
					ID:               f.ID,
					Name:             f.ID,
					ShortDescription: sarifText{SafeText(f.Title)},
					Properties: map[string]any{
						"tags":              append([]string{"security"}, f.Tags...),
						"security-severity": securitySeverity[f.Severity],
					},
				}
				if f.Impact != "" {
					rule.FullDescription = &sarifText{safeBlock(f.Impact)}
				}
				if f.Fix != "" {
					rule.Help = &sarifText{safeBlock(f.Fix)}
				}
				rule.HelpURI = helpURI(f.ID)
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			}
			msg := f.Title + " at " + Place(f)
			if len(f.Evidence.Matched) > 0 {
				// The secrets themselves go in the result's properties, not below.
				var ev []string
				for _, m := range f.Evidence.Matched {
					ev = append(ev, strings.Replace(m, " (masked below)", "", 1))
				}
				msg += " (" + strings.Join(ev, "; ") + ")"
			}
			res := sarifResult{RuleID: f.ID, Level: sarifLevel(f.Severity), Message: sarifText{SafeText(msg)},
				PartialFingerprints: map[string]string{fingerprintKey: Fingerprint(f, root)}}
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation = artifactLocation(f, root)
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
					secrets = append(secrets, SafeText(s.String()))
				}
				res.Properties = map[string]any{"secrets": secrets}
			}
			run.Results = append(run.Results, res)
		}
		log.Runs = append(log.Runs, run)
	}
	for _, t := range o.Failed {
		run := newRun()
		run.Invocations = []sarifInvocation{{ToolExecutionNotifications: []sarifNotification{
			{"error", sarifText{"could not scan " + t.Target + ": " + t.Error}}}}}
		log.Runs = append(log.Runs, run)
	}
	if len(log.Runs) == 0 {
		run := newRun()
		run.Invocations = []sarifInvocation{{ToolExecutionNotifications: []sarifNotification{
			{"error", sarifText{"no target was scanned"}}}}}
		log.Runs = append(log.Runs, run)
	}
	enc := encoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// localRoot is the folder a local scan started from, or "" for a remote
// scan. The writer's option wins; a report read back from JSON has its
// findings' Target instead.
func localRoot(r Report, root string) string {
	if root = cmp.Or(root, r.root); root != "" {
		return root
	}
	for _, f := range r.Findings {
		if isFileURL(f.URL) {
			return f.Target
		}
	}
	return ""
}

func isFileURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "file"
}

// artifactLocation is where a result points: the URL of a remote finding,
// or a local file relative to SRCROOT.
func artifactLocation(f engine.Finding, root string) sarifArtifactLocation {
	if !isFileURL(f.URL) {
		return sarifArtifactLocation{URI: SafeText(f.URL)}
	}
	rel := strings.TrimPrefix(location(f, root), "/")
	if rel == "" {
		rel = "."
	}
	return sarifArtifactLocation{URI: SafeText((&url.URL{Path: rel}).String()), URIBaseID: srcRoot}
}

// fileURI turns a local folder into a file URI with three slashes on every
// system: file:///srv/www, and file:///C:/inetpub/wwwroot for a Windows
// path, where Go's url package would make "C:" the host.
func fileURI(dir string) string {
	p := strings.TrimSuffix(strings.ReplaceAll(dir, "\\", "/"), "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return SafeText((&url.URL{Scheme: "file", Path: p}).String())
}
