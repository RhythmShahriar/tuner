// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A host given without a scheme is tried over https first. On a plain
// http server that try fails its TLS handshake, which only means "use
// http": one try, no error counted.
func TestSchemeProbeIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	var mu sync.Mutex
	var https int
	h := Hooks{Request: func(l RequestLog) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(l.URL, "https://") {
			https++
		}
	}}
	s := New([]*Check{mustParse(t, envCheck)}, Options{Retries: 2, HTTPClient: srv.Client()})
	res, err := s.Scan(context.Background(), strings.TrimPrefix(srv.URL, "http://"), h)
	if err != nil {
		t.Fatal(err)
	}
	if res.Errors != 0 || https != 1 {
		t.Errorf("errors %d, https tries %d; want 0 and 1", res.Errors, https)
	}
	if !strings.HasPrefix(res.Target, "http://") {
		t.Errorf("target %q, want the http fallback", res.Target)
	}
}

func hangServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
}

func TestRequestTimeoutIsNotMaxTime(t *testing.T) {
	srv := hangServer()
	defer srv.Close()
	s := New([]*Check{mustParse(t, envCheck)}, Options{Timeout: 200 * time.Millisecond, Retries: 1, HTTPClient: srv.Client()})
	_, err := s.Scan(context.Background(), srv.URL, Hooks{})
	if !errors.Is(err, ErrRequestTimeout) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want ErrRequestTimeout and not DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "no response within 200ms (tried 2 times)") {
		t.Errorf("err = %q", err)
	}

	// The scan's own deadline (--max-time) stays DeadlineExceeded.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	s = New([]*Check{mustParse(t, envCheck)}, Options{Timeout: 10 * time.Second, HTTPClient: srv.Client()})
	_, err = s.Scan(ctx, srv.URL, Hooks{})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrRequestTimeout) {
		t.Errorf("max-time err = %v; want DeadlineExceeded only", err)
	}
}

func TestRequestTimeoutError(t *testing.T) {
	if got := (&RequestTimeoutError{Timeout: 10 * time.Second, Tries: 3}).Error(); got != "no response within 10s (tried 3 times)" {
		t.Errorf("3 tries: %q", got)
	}
	if got := (&RequestTimeoutError{Timeout: 10 * time.Second, Tries: 1}).Error(); got != "no response within 10s" {
		t.Errorf("1 try: %q", got)
	}
}

// Without --rate the first 429 still slows the scan down.
func TestThrottleAtRateZero(t *testing.T) {
	var mu sync.Mutex
	at := map[string]time.Time{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		at[r.URL.Path] = time.Now()
		mu.Unlock()
		if r.URL.Path == "/a" {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	c := mustParse(t, `
id: t-two
name: two
severity: low
request: {path: ["/a", "/b"]}
match: {all: [{status: 200}, {words: ["never"]}]}
`)
	res, err := New([]*Check{c}, Options{Concurrency: 1, HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Throttled != 1 {
		t.Fatalf("throttled %d, want 1", res.Throttled)
	}
	if gap := at["/b"].Sub(at["/a"]); gap < throttledPace-20*time.Millisecond {
		t.Errorf("request after the 429 came %v later, want about %v", gap, throttledPace)
	}
}

func TestLimiterUnlimitedUntilSlowed(t *testing.T) {
	l := newLimiter(0)
	start := time.Now()
	for range 100 {
		if err := l.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("unlimited limiter waited %v", d)
	}
	l.slow()
	start = time.Now()
	if err := l.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < throttledPace-20*time.Millisecond {
		t.Errorf("first wait after slow took %v, want about %v", d, throttledPace)
	}
	l.slow()
	if l.every != 2*throttledPace {
		t.Errorf("second slow: every %v", l.every)
	}
}

func TestNotHTTPS(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&url.Error{Op: "Get", Err: http.ErrSchemeMismatch}, true},
		{&url.Error{Op: "Get", Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}, true},
		{&url.Error{Op: "Get", Err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}, true},
		{&url.Error{Op: "Get", Err: context.DeadlineExceeded}, false},
		{errors.New("connection reset by peer"), false},
	} {
		if got := notHTTPS(tc.err); got != tc.want {
			t.Errorf("notHTTPS(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
