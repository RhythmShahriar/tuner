// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReadJSONRoundTrip(t *testing.T) {
	full := New(fullResult(), "0.4.0")
	full.Baselined = 2
	full.SetStatus(Status{Complete: false, StoppedBy: "max-time"})
	failed := []TargetError{{Target: "https://down.test", Error: "connection refused"}}

	for name, o := range map[string]WriteOptions{"object": {}, "array with failures": {Many: true, Failed: failed}} {
		reports, gotFailed, err := ReadJSON(bytes.NewReader(encodeJSON(t, []Report{full}, o)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(reports) != 1 || len(gotFailed) != len(o.Failed) {
			t.Fatalf("%s: %d reports, %d failed", name, len(reports), len(gotFailed))
		}
		r := reports[0]
		if r.Target != "https://a.test" || len(r.Findings) != 2 || r.Baselined != 2 || r.Complete ||
			r.StoppedBy != "max-time" || r.Duration != 1500*time.Millisecond || r.Findings[1].Advisories[0].ID != "A1" {
			t.Errorf("%s: read back %+v", name, r)
		}
		if Fingerprint(r.Findings[0], "") != Fingerprint(full.Findings[0], "") {
			t.Errorf("%s: fingerprint changed on the way back", name)
		}
	}
}

func TestReadJSONRejectsOtherJSON(t *testing.T) {
	for _, doc := range []string{`{"name": "x"}`, `[{"schema": "other/v1"}]`, `not json`} {
		if _, _, err := ReadJSON(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "not a Tuner JSON report") {
			t.Errorf("%s: err = %v", doc, err)
		}
	}
}

func TestReadJSONCleansText(t *testing.T) {
	doc := `{"schema": "rhythm-tuner/v0", "target": "https://a.test", "findings": [{"id": "x", "title": "bad\u001b]0;pwn\u0007"}]}`
	reports, _, err := ReadJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := reports[0].Findings[0].Title; strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("title kept control bytes: %q", got)
	}
}
