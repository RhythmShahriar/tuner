package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/RhythmShahriar/tuner/engine"
)

// Baseline holds findings that were accepted earlier and should no longer
// be reported. Any previous JSON report works as a baseline file.
type Baseline map[string]bool

func baselineKey(f engine.Finding) string { return f.ID + " " + f.URL }

// LoadBaseline reads a JSON report (one object or an array of them).
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the user's --baseline flag
	if err != nil {
		return nil, err
	}
	var many []struct{ Findings []engine.Finding }
	if err := json.Unmarshal(data, &many); err != nil {
		var one struct{ Findings []engine.Finding }
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("%s is not a Tuner JSON report: %w", path, err)
		}
		many = append(many, one)
	}
	b := Baseline{}
	for _, r := range many {
		for _, f := range r.Findings {
			b[baselineKey(f)] = true
		}
	}
	return b, nil
}

// Has reports whether f was in the baseline. A nil Baseline has nothing.
func (b Baseline) Has(f engine.Finding) bool { return b[baselineKey(f)] }

// Filter removes baselined findings from res and recomputes its score.
// It returns how many were suppressed.
func (b Baseline) Filter(res *engine.Result) int {
	if len(b) == 0 {
		return 0
	}
	kept := res.Findings[:0]
	for _, f := range res.Findings {
		if !b.Has(f) {
			kept = append(kept, f)
		}
	}
	n := len(res.Findings) - len(kept)
	res.Findings = kept
	res.Score = engine.Score(kept)
	return n
}
