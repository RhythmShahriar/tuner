// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	if New(0) != nil || New(-1) != nil {
		t.Error("rps <= 0 should mean no limiter")
	}
	var none *Limiter
	if err := none.Wait(context.Background()); err != nil {
		t.Error(err)
	}
	l := New(20) // every 50ms
	start := time.Now()
	for range 3 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 90*time.Millisecond {
		t.Errorf("3 requests at 20/s took %s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l = New(0.1)
	l.Wait(ctx) // the first is immediate
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait ignored a canceled context")
	}
}
