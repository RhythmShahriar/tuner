// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
)

func sarifOf(t *testing.T, reports []Report, o WriteOptions) []byte {
	t.Helper()
	o.Version = "0.4.0"
	var b bytes.Buffer
	if err := Write("sarif", &b, reports, o); err != nil {
		t.Fatal(err)
	}
	if errs := validate(loadSchema(t, "testdata/sarif-2.1.0-subset.json"), b.Bytes()); len(errs) > 0 {
		t.Errorf("not valid SARIF:\n%s\n%s", strings.Join(errs, "\n"), b.Bytes())
	}
	return b.Bytes()
}

// sarifView is the part of a SARIF log the tests look at.
type sarifView struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Message sarifText `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds"`
		Tool               sarifTool                        `json:"tool"`
		Results            []struct {
			RuleID              string            `json:"ruleId"`
			Message             sarifText         `json:"message"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Locations           []sarifLocation   `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func readSARIF(t *testing.T, doc []byte) sarifView {
	t.Helper()
	var v sarifView
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func localReport(root string) Report {
	sep := "/"
	if strings.Contains(root, "\\") {
		sep = "\\"
	}
	base := "file://" + strings.ReplaceAll(root, "\\", "/")
	if !strings.HasPrefix(root, "/") {
		base = "file:///" + strings.ReplaceAll(root, "\\", "/")
	}
	return New(&engine.Result{Target: root, Score: 60, Checks: 12, Findings: []engine.Finding{
		{ID: "local-wp-debug", Title: "WordPress debug mode is on", Severity: engine.Medium, Confidence: "high",
			Target: root, URL: base + "/wp-config.php", Path: "/wp-config.php", Fix: "Turn it off."},
		{ID: "local-env-file", Title: ".env file in the web root", Severity: engine.High, Confidence: "high",
			Target: root, URL: base + "/app%20one/.env", Path: sep + "app one" + sep + ".env",
			Evidence: engine.Evidence{Matched: []string{"2 secrets (masked below)"},
				Secrets: []matchers.Secret{{Kind: "env", Name: "DB_PASSWORD", Masked: "hu****42"}}}},
	}}, "0.4.0")
}

func TestSARIFLocalGolden(t *testing.T) {
	doc := sarifOf(t, []Report{localReport("/tmp/ci/wp")}, WriteOptions{Root: "/tmp/ci/wp"})
	golden(t, "sarif-local.golden", string(doc))
	v := readSARIF(t, doc)
	run := v.Runs[0]
	if got := run.OriginalURIBaseIDs[srcRoot].URI; got != "file:///tmp/ci/wp/" {
		t.Errorf("SRCROOT = %q", got)
	}
	for i, want := range []string{"wp-config.php", "app%20one/.env"} {
		loc := run.Results[i].Locations[0].PhysicalLocation.ArtifactLocation
		if loc.URI != want || loc.URIBaseID != srcRoot {
			t.Errorf("result %d location = %+v, want %q under %s", i, loc, want, srcRoot)
		}
	}
	if strings.Contains(string(doc), "masked below") {
		t.Errorf("the message promises secrets below that SARIF never shows:\n%s", doc)
	}
	if got := run.Tool.Driver.Rules[0].HelpURI; got != findingReference+"#local-findings" {
		t.Errorf("helpUri = %q", got)
	}
}

func TestSARIFRemoteGolden(t *testing.T) {
	r := New(viewResult(), "0.4.0")
	doc := sarifOf(t, []Report{r}, WriteOptions{})
	golden(t, "sarif-remote.golden", string(doc))
	v := readSARIF(t, doc)
	for _, res := range v.Runs[0].Results {
		if !strings.HasPrefix(res.PartialFingerprints[fingerprintKey], "v1:") {
			t.Errorf("%s: partialFingerprints = %v", res.RuleID, res.PartialFingerprints)
		}
	}
	rules := map[string]string{}
	for _, rule := range v.Runs[0].Tool.Driver.Rules {
		rules[rule.ID] = rule.HelpURI
	}
	if rules["xmlrpc"] != findingReference+"#xmlrpc" || rules["vuln-php"] != findingReference+"#vulnerability-and-version-findings" {
		t.Errorf("helpUri per rule = %v", rules)
	}
}

// The same finding gets the same partial fingerprint wherever the copy
// lives and whatever host served it, so code scanning keeps one alert.
func TestSARIFFingerprintsAreStable(t *testing.T) {
	a := readSARIF(t, sarifOf(t, []Report{localReport("/tmp/a/wp")}, WriteOptions{}))
	b := readSARIF(t, sarifOf(t, []Report{localReport("/home/runner/work/site")}, WriteOptions{}))
	for i := range a.Runs[0].Results {
		if fa, fb := a.Runs[0].Results[i].PartialFingerprints, b.Runs[0].Results[i].PartialFingerprints; fa[fingerprintKey] != fb[fingerprintKey] {
			t.Errorf("result %d: %v != %v", i, fa, fb)
		}
	}
}

func TestSARIFWindowsRoot(t *testing.T) {
	for _, root := range []string{"C:/inetpub/wwwroot", `C:\inetpub\wwwroot`} {
		v := readSARIF(t, sarifOf(t, []Report{localReport(root)}, WriteOptions{}))
		if got := v.Runs[0].OriginalURIBaseIDs[srcRoot].URI; got != "file:///C:/inetpub/wwwroot/" {
			t.Errorf("%s: SRCROOT = %q", root, got)
		}
		if got := v.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "wp-config.php" {
			t.Errorf("%s: uri = %q", root, got)
		}
	}
}

func TestSARIFFailedTargets(t *testing.T) {
	failed := []TargetError{{Target: "https://down.test", Error: "connection refused"}}
	v := readSARIF(t, sarifOf(t, nil, WriteOptions{Failed: failed}))
	if len(v.Runs) != 1 {
		t.Fatalf("an all-failed scan wrote %d runs, want 1", len(v.Runs))
	}
	inv := v.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || len(inv.ToolExecutionNotifications) != 1 ||
		inv.ToolExecutionNotifications[0].Message.Text != "could not scan https://down.test: connection refused" {
		t.Errorf("invocation = %+v", inv)
	}

	// One run per target, scanned or not.
	v = readSARIF(t, sarifOf(t, []Report{New(viewResult(), "0.4.0")}, WriteOptions{Failed: failed}))
	if len(v.Runs) != 2 || !v.Runs[0].Invocations[0].ExecutionSuccessful || v.Runs[1].Invocations[0].ExecutionSuccessful {
		t.Errorf("batch with one failure: %+v", v.Runs)
	}

	if v := readSARIF(t, sarifOf(t, nil, WriteOptions{})); len(v.Runs) != 1 || v.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Errorf("nothing scanned: %+v", v.Runs)
	}
}

func TestFileURI(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/www":            "file:///srv/www",
		"/srv/www/":           "file:///srv/www",
		"C:/inetpub/wwwroot":  "file:///C:/inetpub/wwwroot",
		`C:\inetpub\wwwroot\`: "file:///C:/inetpub/wwwroot",
		"/srv/my site":        "file:///srv/my%20site",
	} {
		if got := fileURI(in); got != want {
			t.Errorf("fileURI(%q) = %q, want %q", in, got, want)
		}
	}
}
