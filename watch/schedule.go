// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MinEvery is the shortest interval a schedule accepts. Anything faster
// is a load test of the sites, not a watch.
const MinEvery = time.Minute

// Schedule says when runs start: every Every from the first run, or each
// day at the times in At (local time of the clock). Exactly one is set.
type Schedule struct {
	Every time.Duration // between run starts; 0 when At is set
	At    []TimeOfDay   // times of day, sorted; nil when Every is set
}

// TimeOfDay is a wall-clock time, e.g. 02:00.
type TimeOfDay struct{ Hour, Minute int }

// String is the time as HH:MM.
func (t TimeOfDay) String() string { return fmt.Sprintf("%02d:%02d", t.Hour, t.Minute) }

// ParseAt reads "02:00" or "02:00,14:30" into sorted times of day.
func ParseAt(s string) ([]TimeOfDay, error) {
	var out []TimeOfDay
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		h, m, ok := strings.Cut(part, ":")
		hour, err1 := strconv.Atoi(h)
		minute, err2 := strconv.Atoi(m)
		if !ok || err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 || len(m) != 2 {
			return nil, fmt.Errorf("--at %q: want a 24-hour time like 02:00 (several separated by commas)", part)
		}
		t := TimeOfDay{hour, minute}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b TimeOfDay) int { return (a.Hour*60 + a.Minute) - (b.Hour*60 + b.Minute) })
	return out, nil
}

// Validate reports a schedule that sets neither or both of Every and At,
// or an interval below MinEvery.
func (s Schedule) Validate() error {
	switch {
	case s.Every == 0 && len(s.At) == 0:
		return fmt.Errorf("pick a schedule: --every <interval> or --at <HH:MM>")
	case s.Every != 0 && len(s.At) > 0:
		return fmt.Errorf("pick one of --every and --at")
	case s.Every != 0 && s.Every < MinEvery:
		return fmt.Errorf("--every %s is too often; the shortest interval is %s", s.Every, MinEvery)
	}
	return nil
}

// Next returns the first start time after prev for an interval schedule
// (prev is the previous start), or after now for a daily one. Starts an
// interval schedule missed while a run overran are skipped, so a slow
// run never causes a burst of catch-up runs.
func (s Schedule) Next(prev, now time.Time) time.Time {
	if s.Every > 0 {
		next := prev.Add(s.Every)
		for !next.After(now) {
			next = next.Add(s.Every)
		}
		return next
	}
	for day := 0; day <= 1; day++ {
		y, m, d := now.AddDate(0, 0, day).Date()
		for _, t := range s.At {
			at := time.Date(y, m, d, t.Hour, t.Minute, 0, 0, now.Location())
			if at.After(now) {
				return at
			}
		}
	}
	// Unreachable with a valid schedule: tomorrow always has a later time.
	return now.Add(24 * time.Hour)
}

// Clock tells the time and waits. Tests use a fake one.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done, returning ctx.Err() then.
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock is the system clock.
type RealClock struct{}

// Now returns the current local time.
func (RealClock) Now() time.Time { return time.Now() }

// Sleep waits for d or until ctx is done.
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sleepUntil waits until the clock reads at least until. It sleeps in
// steps of at most a minute and rereads the wall clock after each, since
// timers follow the monotonic clock: after a laptop wakes from sleep or
// the clock is set, a single long timer would fire late.
func sleepUntil(ctx context.Context, c Clock, until time.Time) error {
	for {
		d := until.Sub(c.Now())
		if d <= 0 {
			return nil
		}
		if err := c.Sleep(ctx, min(d, time.Minute)); err != nil {
			return err
		}
	}
}
