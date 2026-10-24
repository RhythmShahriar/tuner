// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package run scans a list of targets with a prepared plan. It is the
// part of rhythm tuner scan between reading the command line and printing
// the result: it scans targets in parallel, hides baselined and ignored
// findings, works out how much of each target a scan saw, builds the
// reports and picks the exit code. A program that embeds Tuner, or a
// server that runs scans in process, builds a Plan and calls Run.
package run

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/tunerconfig"
)

// Plan is everything a run needs. The zero value of each optional field
// turns that feature off.
type Plan struct {
	Targets []string        // URLs or folders, scanned in this order
	Checks  []*engine.Check // the selected HTTP checks
	// Engine configures every HTTP scan. Wrap its Advisor with TrackVulns
	// so each target's Status says how much vulnerability data it got.
	Engine engine.Options

	// Fast lists targets scanned at FastRate instead of Engine.Rate, such
	// as hosts on the user's own network.
	Fast     map[string]bool
	FastRate float64

	Parallel int           // targets scanned at once; below 1 means 1
	MaxTime  time.Duration // stop the whole run after this long; 0 never

	Baseline report.Baseline      // findings already known, hidden from the results
	Ignores  []tunerconfig.Ignore // accepted risks, hidden like baselined findings

	// FailOn makes Exit return ExitFindings for a finding at or above
	// this severity; "" never does. ConfirmedOnly counts only confirmed
	// findings for it. AllowMissingVulns and AllowPartial let it pass a
	// target whose vulnerability data was missing or whose scan was cut
	// short, which it otherwise can't call clean.
	FailOn                          engine.Severity
	ConfirmedOnly                   bool
	AllowMissingVulns, AllowPartial bool

	// Version, CheckSet and CheckPack go into each report.
	Version, CheckSet, CheckPack string
	// Selection, when set, goes into each report too, so a later
	// comparison knows which findings the scan looked for.
	Selection *report.Selection

	// Scan scans one target. Nil means s.Scan, which handles URLs only;
	// set it to scan folders too or to wrap each scan.
	Scan func(ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error)
}

// Hooks let the caller show a run as it happens. Both are called from the
// target's own goroutine, so with Parallel above 1 they run concurrently.
type Hooks struct {
	// Start is called before target i is scanned and returns the engine
	// hooks for its scan. Findings the baseline or an ignore entry hides
	// never reach Finding.
	Start func(i int, target string) engine.Hooks
	// Done is called once target i is finished, with its outcome.
	Done func(i int, t *Target)
}

// Target is how one target went.
type Target struct {
	Target string
	// Result is the scan's result without hidden findings, or nil when
	// the target could not be scanned.
	Result *engine.Result
	Status Status
	// Err is why the scan failed or stopped early; context.Canceled when
	// the run was canceled. A target with a Result may have one too.
	Err error
	// Suppressed counts the findings the baseline and ignores hid;
	// Baselined and Ignored count each one's share of them.
	Suppressed, Baselined, Ignored int
}

// Failed reports whether the target ran into an error of its own, rather
// than being stopped by a canceled run.
func (t *Target) Failed() bool { return t.Err != nil && !isCanceled(t.Err) }

// Outcome is a finished run.
type Outcome struct {
	Targets []Target        // one per plan target, in order
	Reports []report.Report // one per target with a Result, in order
	Status  []Status        // Reports[i]'s status
	// Canceled is set when the run's context was canceled, as Ctrl+C does.
	Canceled bool
}

// Run scans every target in the plan. It returns once all are done, also
// when ctx is canceled: targets then stop early and keep what they found.
func Run(ctx context.Context, p *Plan, hooks Hooks) *Outcome {
	if p.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.MaxTime)
		defer cancel()
	}
	scanner := engine.New(p.Checks, p.Engine)
	var fast *engine.Scanner // for the targets in p.Fast
	if len(p.Fast) > 0 {
		fo := p.Engine
		fo.Rate = p.FastRate
		fast = engine.New(p.Checks, fo)
	}

	out := &Outcome{Targets: make([]Target, len(p.Targets))}
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(p.Parallel, 1))
	for i, target := range p.Targets {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			var h engine.Hooks
			if hooks.Start != nil {
				h = hooks.Start(i, target)
			}
			show := h.Finding
			h.Finding = func(f engine.Finding) {
				if !p.Hidden(f) && show != nil {
					show(f)
				}
			}
			s := scanner
			if p.Fast[target] {
				s = fast
			}
			slot := &vulnSlot{}
			res, err := p.safeScan(context.WithValue(ctx, vulnSlotKey{}, slot), s, target, h)
			t := &out.Targets[i]
			*t = Target{Target: target, Err: err, Status: p.status(ctx, err, slot, res)}
			if res != nil {
				report.Stamp(res, "")
				// Ignored findings count with the baselined ones.
				t.Ignored = p.filterIgnored(res)
				t.Baselined = p.Baseline.Filter(res)
				t.Suppressed = t.Baselined + t.Ignored
				t.Result = res
			}
			if hooks.Done != nil {
				hooks.Done(i, t)
			}
		})
	}
	wg.Wait()

	for _, t := range out.Targets {
		if t.Result == nil {
			continue
		}
		r := report.New(t.Result, p.Version)
		r.CheckSet, r.CheckPack = p.CheckSet, p.CheckPack
		r.Selection = p.Selection
		r.Baselined = t.Baselined
		r.SetStatus(report.Status(t.Status))
		out.Reports = append(out.Reports, r)
		out.Status = append(out.Status, t.Status)
	}
	out.Canceled = isCanceled(ctx.Err())
	return out
}

// safeScan scans one target and turns a panic into an InternalError, so
// one target that trips a bug still lets every other target report.
// Panics in goroutines the scan starts itself can't be caught here.
func (p *Plan) safeScan(ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (res *engine.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, InternalError{r, debug.Stack()}
		}
	}()
	if p.Scan != nil {
		return p.Scan(ctx, s, target, h)
	}
	return s.Scan(ctx, target, h)
}

// InternalError is a panic caught while scanning one target.
type InternalError struct {
	Value any
	Stack []byte // where it happened, for a bug report
}

func (e InternalError) Error() string {
	return fmt.Sprintf("internal error (please report): %v", e.Value)
}

// Ignored reports whether an ignore entry hides f.
func (p *Plan) Ignored(f engine.Finding) bool {
	return slices.ContainsFunc(p.Ignores, func(ig tunerconfig.Ignore) bool { return ig.Matches(f.ID, f.Path) })
}

// Hidden reports whether f is left out of the results: it is in the
// baseline or an ignore entry covers it.
func (p *Plan) Hidden(f engine.Finding) bool { return p.Baseline.Has(f) || p.Ignored(f) }

// filterIgnored drops the findings ignore entries cover, recomputes the
// score and returns how many it dropped.
func (p *Plan) filterIgnored(res *engine.Result) int {
	if len(p.Ignores) == 0 {
		return 0
	}
	kept := res.Findings[:0]
	for _, f := range res.Findings {
		if !p.Ignored(f) {
			kept = append(kept, f)
		}
	}
	n := len(res.Findings) - len(kept)
	res.Findings = kept
	res.Score = engine.Score(kept)
	return n
}
