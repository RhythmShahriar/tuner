// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimit keeps Tuner polite and quick with the free data
// services it relies on: Limiter spaces requests, Breaker stops asking a
// host that can't be reached, and FastClient gives up on dead connections
// early. Limiter matches rhythm's kit/ratelimit.Limiter, so the two can be
// swapped once Tuner pins a kit release that has it.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces requests evenly to stay under a requests-per-second cap.
// A nil *Limiter never waits.
type Limiter struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
}

// New returns a limiter for rps requests per second, or nil (no limit)
// when rps <= 0.
func New(rps float64) *Limiter {
	if rps <= 0 {
		return nil
	}
	return &Limiter{every: time.Duration(float64(time.Second) / rps)}
}

// Wait blocks until the next request may be sent.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.every)
	l.mu.Unlock()
	return Sleep(ctx, time.Until(at))
}

// Sleep waits for d or until ctx is done.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
