// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/ratelimit"
)

// Pace a scan without a rate limit (--rate 0) drops to on its first 429
// or 503: four requests a second, halved again on each one after.
const throttledPace = 250 * time.Millisecond

// pace is the request pace for one host, shared by every scan a Scanner
// runs against that host, so two targets on one server stay under --rate
// together. It wraps a kit limiter and adds the one thing the kit lacks:
// without --rate there is no limiter until the site first throttles.
type pace struct {
	mu sync.Mutex
	l  *ratelimit.Limiter // nil lets everything through
}

func (p *pace) wait(ctx context.Context) error {
	p.mu.Lock()
	l := p.l
	p.mu.Unlock()
	return l.Wait(ctx)
}

// slow halves the request rate, down to ratelimit.Slowest. An unlimited
// pace starts at throttledPace and the next request already waits for it.
func (p *pace) slow() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.l != nil {
		p.l.Slow()
		return
	}
	p.l = ratelimit.New(float64(time.Second) / float64(throttledPace))
	// A new limiter lets its first request through at once; taking that
	// slot here makes the request after the 429 wait a full step.
	_ = p.l.Wait(context.Background())
}

// paces hands out one pace per host name (any case, any port).
type paces struct {
	hosts *ratelimit.Hosts
	mu    sync.Mutex
	m     map[string]*pace
}

func newPaces(rps float64) *paces {
	return &paces{hosts: ratelimit.NewHosts(rps), m: map[string]*pace{}}
}

func (ps *paces) For(host string) *pace {
	host = strings.ToLower(host)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.m[host]
	if !ok {
		p = &pace{l: ps.hosts.For(host)}
		ps.m[host] = p
	}
	return p
}
