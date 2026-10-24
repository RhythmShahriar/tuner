// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// tlsBreaker stands in for an on-path attacker on a bare host: every TLS
// ClientHello gets a fatal handshake_failure alert, while plain http
// requests are answered and recorded.
type tlsBreaker struct {
	ln    net.Listener
	mu    sync.Mutex
	plain []*http.Request
}

func newTLSBreaker(t *testing.T) *tlsBreaker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &tlsBreaker{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *tlsBreaker) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	first, err := r.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x16 { // TLS handshake record
		_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
		return
	}
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.plain = append(b.plain, req)
		b.mu.Unlock()
		_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}
}

func (b *tlsBreaker) plainRequests() []*http.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.plain
}

// With a cookie set, a broken TLS handshake must not send the cookie over
// plain http. The scan stops and says how to scan over http on purpose.
func TestBrokenTLSKeepsHeadersOffHTTP(t *testing.T) {
	b := newTLSBreaker(t)
	h := http.Header{}
	h.Set("Cookie", "session=secret")
	s := New([]*Check{mustParse(t, envCheck)}, Options{Headers: h})
	_, err := s.Scan(context.Background(), b.ln.Addr().String(), Hooks{})
	if err == nil || !strings.Contains(err.Error(), "over https") || !strings.Contains(err.Error(), "give http://") {
		t.Fatalf("err = %v, want the over https error with the http:// hint", err)
	}
	for _, r := range b.plainRequests() {
		if r.Header.Get("Cookie") != "" {
			t.Errorf("cookie sent over plain http: %s %s", r.Method, r.URL)
		}
	}
	if n := len(b.plainRequests()); n != 0 {
		t.Errorf("%d plain http requests, want 0", n)
	}
}

// Without user headers there is nothing to leak, so the fallback stays.
func TestBrokenTLSFallsBackWithoutHeaders(t *testing.T) {
	b := newTLSBreaker(t)
	s := New([]*Check{mustParse(t, envCheck)}, Options{})
	res, err := s.Scan(context.Background(), b.ln.Addr().String(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Target, "http://") || len(b.plainRequests()) == 0 {
		t.Errorf("target %q, %d plain requests; want the http fallback", res.Target, len(b.plainRequests()))
	}
}

// A plain http server answering on the port is no attack, so headers go
// along with the fallback.
func TestSchemeMismatchFallsBackWithHeaders(t *testing.T) {
	var mu sync.Mutex
	var cookies []string
	srv := newPlainServer(t, func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		cookies = append(cookies, r.Header.Get("Cookie"))
	})
	h := http.Header{}
	h.Set("Cookie", "session=ok")
	res, err := New([]*Check{mustParse(t, envCheck)}, Options{Headers: h}).Scan(context.Background(), srv, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(res.Target, "http://") || len(cookies) == 0 || cookies[0] != "session=ok" {
		t.Errorf("target %q, cookies %q", res.Target, cookies)
	}
}

// newPlainServer starts a plain http server and returns its host:port.
func newPlainServer(t *testing.T, seen func(*http.Request)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen(r)
		http.NotFound(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// A real refused dial counts as "no https" on every platform, so a bare
// host with nothing on the port is tried once.
func TestRefusedDialIsNotHTTPS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	resp, err := (&http.Client{}).Get("https://" + addr + "/")
	if err == nil {
		resp.Body.Close()
		t.Skip("something listens on the closed port")
	}
	if !connRefused(err) || !notHTTPS(err) || !plainHTTPOnly(err) {
		t.Errorf("refused dial %v: connRefused %v, notHTTPS %v", err, connRefused(err), notHTTPS(err))
	}
}
