// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a fake time source the test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestBackoffAfterFailure(t *testing.T) {
	rel := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	dir := t.TempDir()
	clk := &clock{time.Now()}
	c := rel.client(dir)
	c.Now = clk.now
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The TTL runs out while the host is down.
	clk.advance(DefaultTTL + time.Minute)
	rel.Close()
	p, err := c.Get(context.Background())
	if err != nil || !p.Stale || !errors.Is(p.Warning, ErrUnreachable) {
		t.Fatalf("host down: p=%+v err=%v", p, err)
	}
	before := rel.total()

	// Within the back-off: the cached pack, quietly, without a request.
	clk.advance(Backoff - time.Minute)
	p, err = c.Get(context.Background())
	if err != nil || p.Warning != nil || p.Version != "2026.10.01-120000" || rel.total() != before {
		t.Fatalf("in back-off: p=%+v err=%v, %d requests", p, err, rel.total()-before)
	}

	// After it, the release is consulted again.
	clk.advance(2 * time.Minute)
	if p, err = c.Get(context.Background()); err != nil || !errors.Is(p.Warning, ErrUnreachable) {
		t.Fatalf("after back-off: p=%+v err=%v", p, err)
	}
}

func TestBackoffWithoutCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close() // drop the connection, like a flaky network
	}))
	t.Cleanup(srv.Close)
	clk := &clock{time.Now()}
	c := &Client{BaseURL: srv.URL, CacheDir: t.TempDir(), Tuner: "0.3.0", Keys: testKeys(), Now: clk.now}

	if _, err := c.Get(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	n := hits.Load()
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrNotCached) || hits.Load() != n {
		t.Errorf("in back-off: err = %v, %d requests", err, hits.Load()-n)
	}
	// rhythm update asks anyway.
	c.Force = true
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrUnreachable) || hits.Load() == n {
		t.Errorf("forced: err = %v", err)
	}
	c.Force = false
	clk.advance(Backoff + time.Second)
	n = hits.Load()
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrUnreachable) || hits.Load() == n {
		t.Errorf("after back-off: err = %v, no request", err)
	}
	if c.Cached() {
		t.Error("a failure marker counts as a cached pack")
	}
}
