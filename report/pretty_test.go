package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// Plain output (logs, CI, screen readers) must not present a
// low-confidence finding as confirmed.
func TestPlainShowsLikely(t *testing.T) {
	var buf bytes.Buffer
	p := NewPretty(&buf, &buf, PrettyOptions{Plain: true})
	p.Finding(engine.Finding{Severity: engine.High, Title: "Apache 2.4.57: 3 known vulnerabilities", URL: "https://yoursite.com/",
		Confidence: "low", Caveat: "likely: a distro build may already include the fix"})
	p.Finding(engine.Finding{Severity: engine.Critical, Title: ".env file exposed", URL: "https://yoursite.com/.env", Confidence: "high"})
	out := buf.String()
	for _, want := range []string{"[HIGH, likely] Apache", "  likely: a distro build may already include the fix", "[CRITICAL] .env file exposed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
