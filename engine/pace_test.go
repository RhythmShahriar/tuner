// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"math"
	"testing"
	"time"
)

// A pace with a rate keeps the kit limiter's own Slow: no extra slot is
// taken, so the next request waits one (doubled) step, not two.
func TestPaceWithRateSlowsWithoutExtraSlot(t *testing.T) {
	p := newPaces(20).For("example.com") // one request every 50ms
	if err := p.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.slow() // now every 100ms
	start := time.Now()
	if err := p.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 90*time.Millisecond {
		t.Errorf("wait after slow took %v, want at most the old 50ms step", d)
	}
}

// Hosts share one pace whatever their case. The unlimited start is
// taken once: a second slow is the kit's doubling.
func TestPaceUnlimitedSharedAndTakenOnce(t *testing.T) {
	ps := newPaces(0)
	a, b := ps.For("Example.com"), ps.For("example.com")
	if a != b {
		t.Fatal("same host in another case got another pace")
	}
	a.slow()
	if a.unlimited.Load() {
		t.Error("pace still unlimited after slow")
	}
	for _, rps := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if !newPaces(rps).unlimited {
			t.Errorf("rate %v: want an unlimited pace", rps)
		}
	}
	if newPaces(5).unlimited {
		t.Error("rate 5: want a limited pace")
	}
}
