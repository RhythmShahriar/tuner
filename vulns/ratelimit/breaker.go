// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
)

// DialTimeout bounds connecting to a data service. A firewall that drops
// packets would otherwise hold every lookup for the OS connect timeout.
const DialTimeout = 3 * time.Second

// ErrUnreachable means an earlier request to the host timed out or could
// not connect, so this one was not sent.
var ErrUnreachable = errors.New("unreachable (an earlier request timed out or could not connect)")

// Unreachable reports whether err means the service could not be reached
// at all (a timeout, a refused or dropped connection, a DNS failure), as
// opposed to answering badly. A canceled context is neither.
func Unreachable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, ErrUnreachable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var op *net.OpError
	var dns *net.DNSError
	return errors.As(err, &op) || errors.As(err, &dns)
}

// Breaker remembers which hosts are unreachable, so a run with a firewalled
// data service waits for one timeout instead of one per lookup. Until a
// host has answered once, only one request to it is in flight; the rest
// wait for its outcome. After a timeout or connection error the host is
// down: requests fail at once with ErrUnreachable until Cooldown passes,
// then one request probes it again. The zero value is ready to use.
type Breaker struct {
	Cooldown time.Duration // how long a host stays down; 0 means a minute

	mu    sync.Mutex
	hosts map[string]*hostState
}

type hostState struct {
	up     bool          // a request got an answer
	downAt time.Time     // when the host went down; zero if it isn't
	probe  chan struct{} // closed when the request in flight is done
}

// Do runs fn, a request to host, unless the host is down.
func (b *Breaker) Do(ctx context.Context, host string, fn func() error) error {
	for {
		b.mu.Lock()
		if b.hosts == nil {
			b.hosts = map[string]*hostState{}
		}
		st := b.hosts[host]
		if st == nil {
			st = &hostState{}
			b.hosts[host] = st
		}
		if !st.downAt.IsZero() {
			cool := b.Cooldown
			if cool <= 0 {
				cool = time.Minute
			}
			if time.Since(st.downAt) < cool {
				b.mu.Unlock()
				return fmt.Errorf("%s: %w", host, ErrUnreachable)
			}
			st.downAt = time.Time{} // probe it again
		}
		switch {
		case st.up:
			b.mu.Unlock()
			err := fn()
			b.record(st, err)
			return err
		case st.probe != nil:
			wait := st.probe
			b.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		done := make(chan struct{})
		st.probe = done
		b.mu.Unlock()
		err := fn()
		b.record(st, err)
		b.mu.Lock()
		st.probe = nil
		b.mu.Unlock()
		close(done)
		return err
	}
}

func (b *Breaker) record(st *hostState, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case Unreachable(err):
		st.up, st.downAt = false, time.Now()
	case err == nil || !errors.Is(err, context.Canceled):
		st.up = true // it answered, even if badly
	}
}

// Down lists the hosts that are down now, sorted.
func (b *Breaker) Down() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for h, st := range b.hosts {
		if !st.downAt.IsZero() {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out
}

// FastClient returns a copy of hc (or a new client when hc is nil) whose
// connections give up after DialTimeout. hc itself is not changed.
func FastClient(hc *http.Client) *http.Client {
	out := &http.Client{}
	if hc != nil {
		*out = *hc
	}
	tr, ok := out.Transport.(*http.Transport)
	switch {
	case out.Transport == nil:
		tr = http.DefaultTransport.(*http.Transport).Clone()
	case ok:
		tr = tr.Clone()
	default:
		return out // a custom RoundTripper dials its own way
	}
	tr.DialContext = (&net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}).DialContext
	out.Transport = tr
	return out
}
