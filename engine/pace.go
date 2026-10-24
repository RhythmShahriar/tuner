// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/ratelimit"
)

// Pace a scan without a rate limit (--rate 0) drops to on its first 429
// or 503: four requests a second, halved again on each one after. The kit
// limiter does the same; the constant is kept for the tests and the help.
const throttledPace = 250 * time.Millisecond

// pace is the request pace for one host, shared by every scan a Scanner
// runs against that host, so two targets on one server stay under --rate
// together. The kit limiter already slows an unlimited pace on Slow; pace
// adds one thing: the request right after the first throttle waits a full
// step instead of going out at once.
type pace struct {
	l *ratelimit.Limiter
	// unlimited is set while a pace made without --rate has not been
	// slowed yet.
	unlimited atomic.Bool
}

func (p *pace) wait(ctx context.Context) error {
	return p.l.Wait(ctx)
}

// slow halves the request rate, down to ratelimit.Slowest. An unlimited
// pace starts at throttledPace and the next request already waits for it.
func (p *pace) slow() {
	p.l.Slow()
	if p.unlimited.CompareAndSwap(true, false) {
		// An unlimited limiter's next slot is now; taking it here makes
		// the request after the 429 wait a full step.
		_ = p.l.Wait(context.Background())
	}
}

// paces hands out one pace per host name (any case, any port).
type paces struct {
	hosts     *ratelimit.Hosts
	unlimited bool
	mu        sync.Mutex
	m         map[string]*pace
}

// newPaces paces each host at rps requests a second. Like the kit, a rate
// of 0 or less (or NaN or +Inf) means no limit until a site throttles.
func newPaces(rps float64) *paces {
	unlimited := !(rps > 0) || math.IsInf(rps, 1)
	return &paces{hosts: ratelimit.NewHosts(rps), unlimited: unlimited, m: map[string]*pace{}}
}

func (ps *paces) For(host string) *pace {
	host = strings.ToLower(host)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.m[host]
	if !ok {
		p = &pace{l: ps.hosts.For(host)}
		p.unlimited.Store(ps.unlimited)
		ps.m[host] = p
	}
	return p
}
