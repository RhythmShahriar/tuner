// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errTimeout = fmt.Errorf("get: %w", context.DeadlineExceeded)

func TestBreaker(t *testing.T) {
	var b Breaker
	ctx := context.Background()
	var calls atomic.Int32
	slowFail := func() error { calls.Add(1); time.Sleep(50 * time.Millisecond); return errTimeout }

	// Five concurrent lookups to a host that times out: one request.
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Go(func() { errs[i] = b.Do(ctx, "api.example", slowFail) })
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("%d requests, want 1", calls.Load())
	}
	for _, err := range errs {
		if !Unreachable(err) {
			t.Errorf("err = %v", err)
		}
	}
	if got := b.Down(); len(got) != 1 || got[0] != "api.example" {
		t.Errorf("Down() = %v", got)
	}

	// Other hosts are unaffected; a bad answer means up.
	if err := b.Do(ctx, "other.example", func() error { return errors.New("HTTP 500") }); err == nil || Unreachable(err) {
		t.Errorf("HTTP error: %v", err)
	}
	if err := b.Do(ctx, "other.example", func() error { return nil }); err != nil {
		t.Error(err)
	}

	// After the cooldown, one request probes again and a success brings it back.
	b.Cooldown = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	if err := b.Do(ctx, "api.example", func() error { return nil }); err != nil {
		t.Errorf("probe after cooldown: %v", err)
	}
	if len(b.Down()) != 0 {
		t.Errorf("still down: %v", b.Down())
	}

	// A canceled request says nothing about the host.
	var c Breaker
	if err := c.Do(ctx, "h", func() error { return context.Canceled }); !errors.Is(err, context.Canceled) || len(c.Down()) != 0 {
		t.Errorf("canceled: %v, down %v", err, c.Down())
	}
}

func TestUnreachable(t *testing.T) {
	for err, want := range map[error]bool{
		nil:                    false,
		context.Canceled:       false,
		errors.New("HTTP 502"): false,
		errTimeout:             true,
		ErrUnreachable:         true,
		&net.OpError{Op: "dial", Err: errors.New("connection refused")}: true,
		&net.DNSError{Err: "no such host", Name: "x"}:                   true,
	} {
		if got := Unreachable(err); got != want {
			t.Errorf("Unreachable(%v) = %v", err, got)
		}
	}
}

func TestFastClient(t *testing.T) {
	orig := &http.Client{Timeout: time.Minute}
	fc := FastClient(orig)
	if fc == orig || orig.Transport != nil || fc.Timeout != time.Minute {
		t.Error("FastClient changed or lost the caller's client")
	}
	if tr, ok := fc.Transport.(*http.Transport); !ok || tr.DialContext == nil {
		t.Errorf("transport %T", fc.Transport)
	}
	if FastClient(nil).Transport == nil {
		t.Error("nil client got no transport")
	}
}
