// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// seen is one request as a test server received it.
type seen struct{ host, path, auth, cookie, custom string }

// logServer is an httptest server that records every request it gets.
type logServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []seen
}

func newLogServer(t *testing.T, https bool, h http.HandlerFunc) *logServer {
	t.Helper()
	ls := &logServer{}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.reqs = append(ls.reqs, seen{r.Host, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Custom")})
		ls.mu.Unlock()
		if h != nil {
			h(w, r)
		}
	})
	if https {
		ls.Server = httptest.NewTLSServer(wrapped)
	} else {
		ls.Server = httptest.NewServer(wrapped)
	}
	t.Cleanup(ls.Close)
	return ls
}

func (ls *logServer) requests() []seen {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return append([]seen(nil), ls.reqs...)
}

func (ls *logServer) port() string {
	_, p, _ := net.SplitHostPort(ls.Listener.Addr().String())
	return p
}

// redirectTo answers every request with a 301 to base plus the path.
func redirectTo(base string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+r.URL.Path, http.StatusMovedPermanently)
	}
}

// fakeNet routes dials for made-up public addresses to local test
// servers and records every address dialed.
type fakeNet struct {
	mu     sync.Mutex
	routes map[string]string // "203.0.113.7:80" -> "127.0.0.1:port"
	dialed []string
}

func (n *fakeNet) client() *http.Client {
	d := &net.Dialer{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test servers
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			n.mu.Lock()
			n.dialed = append(n.dialed, addr)
			to, ok := n.routes[addr]
			n.mu.Unlock()
			if !ok {
				to = addr
			}
			return d.DialContext(ctx, network, to)
		},
	}
	return &http.Client{Transport: tr}
}

func (n *fakeNet) dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

// stubResolver answers from a map; anything else does not exist.
func stubResolver(names map[string]string) resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := names[host]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

// userHeaders are the -H and --cookie values every test sends.
func userHeaders() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic c3RhZ2luZzpodW50ZXIy")
	h.Set("Cookie", "wordpress_logged_in=SESSIONSECRET")
	h.Set("X-Custom", "custom-secret")
	return h
}

func redirectScanner(t *testing.T, n *fakeNet, names map[string]string, follow bool) *Scanner {
	t.Helper()
	s := New([]*Check{mustParse(t, envCheck)}, Options{Headers: userHeaders(), HTTPClient: n.client(), FollowHost: follow})
	s.resolve = stubResolver(names)
	return s
}

func assertNoUserHeaders(t *testing.T, name string, reqs []seen) {
	t.Helper()
	if len(reqs) == 0 {
		t.Errorf("%s: got no requests", name)
	}
	for _, r := range reqs {
		if r.auth != "" || r.cookie != "" || r.custom != "" {
			t.Errorf("%s: %s got user headers: %+v", name, r.path, r)
		}
	}
}

func assertUserHeaders(t *testing.T, name string, reqs []seen) {
	t.Helper()
	if len(reqs) < 3 {
		t.Errorf("%s: only %d requests", name, len(reqs))
	}
	for _, r := range reqs {
		if r.auth == "" || r.cookie == "" || r.custom == "" {
			t.Errorf("%s: %s lacks user headers: %+v", name, r.path, r)
		}
	}
}

func TestCrossHostRedirectStops(t *testing.T) {
	other := newLogServer(t, false, nil)
	first := newLogServer(t, false, redirectTo("http://localhost:"+other.port()))
	n := &fakeNet{}
	_, err := redirectScanner(t, n, map[string]string{"localhost": "127.0.0.1"}, false).Scan(context.Background(), first.URL, Hooks{})
	var re *RedirectError
	want := fmt.Sprintf("127.0.0.1:%s redirects to localhost:%s; scan that host directly if you own it, or pass --follow-host", first.port(), other.port())
	if !errors.As(err, &re) || err.Error() != want {
		t.Fatalf("err = %v\nwant %s", err, want)
	}
	if got := other.requests(); len(got) != 0 {
		t.Errorf("other host got %d requests: %+v", len(got), got)
	}
	if got := first.requests(); len(got) != 1 || got[0].auth == "" {
		t.Errorf("first host requests: %+v", got)
	}
}

// A refused redirect is the scan's own answer, so retrying it only sends
// the home request again and waits out the backoff.
func TestRefusedRedirectNotRetried(t *testing.T) {
	other := newLogServer(t, false, nil)
	internalSrv := newLogServer(t, false, nil)
	for _, tc := range []struct {
		name, to string
		names    map[string]string
	}{
		{"cross host", "http://localhost:" + other.port(), map[string]string{"public.test": "203.0.113.7", "localhost": "127.0.0.1"}},
		{"internal", "http://127.0.0.1:" + internalSrv.port(), map[string]string{"public.test": "203.0.113.7"}},
	} {
		origin := newLogServer(t, false, redirectTo(tc.to))
		n := &fakeNet{routes: map[string]string{"203.0.113.7:80": origin.Listener.Addr().String()}}
		s := New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: n.client(), Retries: 2})
		s.resolve = stubResolver(tc.names)
		start := time.Now()
		_, err := s.Scan(context.Background(), "http://public.test", Hooks{})
		if !errors.As(err, new(*RedirectError)) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if got := origin.requests(); len(got) != 1 {
			t.Errorf("%s: origin got %d home requests, want 1", tc.name, len(got))
		}
		if d := time.Since(start); d > 400*time.Millisecond {
			t.Errorf("%s: took %v, a retry backoff", tc.name, d)
		}
	}
	if len(other.requests())+len(internalSrv.requests()) != 0 {
		t.Error("a refused redirect target got requests")
	}
}

func TestFollowHostDropsUserHeaders(t *testing.T) {
	other := newLogServer(t, false, nil)
	first := newLogServer(t, false, redirectTo("http://localhost:"+other.port()))
	n := &fakeNet{}
	res, err := redirectScanner(t, n, map[string]string{"localhost": "127.0.0.1"}, true).Scan(context.Background(), first.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "http://localhost:"+other.port() {
		t.Errorf("target %s", res.Target)
	}
	assertNoUserHeaders(t, "followed host", other.requests())
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "redirects to localhost:"+other.port()+"; scanning localhost:"+other.port()+" because of --follow-host, without your headers and cookies") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestTwinAndUpgradeRedirectsFollowed(t *testing.T) {
	// site.test -> www.site.test on the same server.
	srv := newLogServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "site.test:") {
			http.Redirect(w, r, "http://www."+r.Host+r.URL.Path, http.StatusMovedPermanently)
		}
	})
	names := map[string]string{"site.test": "127.0.0.1", "www.site.test": "127.0.0.1"}
	res, err := redirectScanner(t, &fakeNet{}, names, false).Scan(context.Background(), "http://site.test:"+srv.port(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "http://www.site.test:"+srv.port() {
		t.Errorf("twin target %s", res.Target)
	}
	assertUserHeaders(t, "www twin", srv.requests())

	// http -> https on another port.
	secure := newLogServer(t, true, nil)
	plain := newLogServer(t, false, redirectTo(secure.URL))
	res, err = redirectScanner(t, &fakeNet{}, nil, false).Scan(context.Background(), plain.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != secure.URL {
		t.Errorf("upgrade target %s, want %s", res.Target, secure.URL)
	}
	assertUserHeaders(t, "https upgrade", secure.requests())
}

func TestHTTPSDowngrade(t *testing.T) {
	plain := newLogServer(t, false, nil)
	secure := newLogServer(t, true, redirectTo(plain.URL))
	_, err := redirectScanner(t, &fakeNet{}, nil, false).Scan(context.Background(), secure.URL, Hooks{})
	want := fmt.Sprintf("https://127.0.0.1:%s redirects to http://127.0.0.1:%s; scan that host directly", secure.port(), plain.port())
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("err = %v\nwant %s...", err, want)
	}
	if got := plain.requests(); len(got) != 0 {
		t.Errorf("http host got %d requests", len(got))
	}

	// Followed on request but the user's headers never go over http.
	if _, err := redirectScanner(t, &fakeNet{}, nil, true).Scan(context.Background(), secure.URL, Hooks{}); err != nil {
		t.Fatal(err)
	}
	assertNoUserHeaders(t, "http after https", plain.requests())
}

func TestRedirectToInternalAddressRefused(t *testing.T) {
	internalSrv := newLogServer(t, false, nil)
	for _, loc := range []string{
		"http://127.0.0.1:" + internalSrv.port(),
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.test",
		"http://[64:ff9b::a9fe:a9fe]",
	} {
		public := newLogServer(t, false, redirectTo(loc))
		n := &fakeNet{routes: map[string]string{"203.0.113.7:80": public.Listener.Addr().String()}}
		names := map[string]string{"public.test": "203.0.113.7", "metadata.test": "169.254.169.254"}
		_, err := redirectScanner(t, n, names, true).Scan(context.Background(), "http://public.test", Hooks{})
		var re *RedirectError
		if !errors.As(err, &re) || !re.Internal || !strings.Contains(err.Error(), "a local or private address") {
			t.Errorf("%s: err = %v", loc, err)
		}
		if dials := n.dials(); len(dials) != 1 || dials[0] != "203.0.113.7:80" {
			t.Errorf("%s: dialed %v", loc, dials)
		}
		if len(public.requests()) != 1 {
			t.Errorf("%s: public got %d requests", loc, len(public.requests()))
		}
	}
	if got := internalSrv.requests(); len(got) != 0 {
		t.Errorf("internal server got %d requests", len(got))
	}
}

func TestDNSRebindingRefused(t *testing.T) {
	srv := newLogServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close") // every request dials, so every one resolves
	})
	n := &fakeNet{routes: map[string]string{"203.0.113.8:80": srv.Listener.Addr().String()}}
	var rebound atomic.Bool
	s := New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: n.client()})
	s.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if rebound.Load() {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
	}
	var refused atomic.Int32
	res, err := s.Scan(context.Background(), "http://rebind.test", Hooks{
		Fingerprint: func(fingerprint.Result) { rebound.Store(true) },
		Request: func(l RequestLog) {
			if errors.As(l.Err, new(*AddressError)) {
				refused.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range n.dials() {
		if d != "203.0.113.8:80" {
			t.Errorf("dialed %s after the name rebound to loopback", d)
		}
	}
	if refused.Load() == 0 || res.Errors == 0 {
		t.Errorf("refused %d, errors %d; want the rebound requests refused", refused.Load(), res.Errors)
	}
}

func TestSameSite(t *testing.T) {
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{"https://example.com", "https://example.com/x", true},
		{"https://example.com", "https://WWW.example.com.", true},
		{"https://www.example.com", "https://example.com", true},
		{"http://example.com", "https://www.example.com", true},
		{"http://example.com:8080", "https://example.com:8443", true},
		{"https://example.com", "https://example.com:443", true},
		{"https://example.com", "http://example.com", false},
		{"https://example.com", "https://example.com:8443", false},
		{"https://example.com", "https://other.net", false},
		{"https://example.com", "https://api.example.com", false},
		{"https://example.com", "https://www.www.example.com", false},
	} {
		if got := sameSite(u(tc.from), u(tc.to)); got != tc.want {
			t.Errorf("sameSite(%s, %s) = %v", tc.from, tc.to, got)
		}
	}
}

func TestInternal(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "172.16.0.1": true, "169.254.169.254": true,
		"::1": true, "fe80::1": true, "fd00::1": true, "0.0.0.0": true, "::ffff:127.0.0.1": true, "64:ff9b::a9fe:a9fe": true,
		"100.100.100.200": true, "100.64.0.1": true, "0.1.2.3": true, "192.0.0.192": true, "198.18.0.1": true,
		"::127.0.0.1": true, "2002:7f00:1::": true, "2002:a9fe:a9fe::1": true, "2002:6464:64c8::": true,
		// Teredo with client 127.0.0.1, then local-use NAT64.
		"2001:0:4136:e378:8000:63bf:80ff:fffe": true, "64:ff9b:1::a9fe:a9fe": true,
		"203.0.113.7": false, "8.8.8.8": false, "2606:4700::1111": false, "100.128.0.1": false,
		"::8.8.8.8": false, "2002:808:808::": false, "2001:0:4136:e378:8000:63bf:f7f7:f7f7": false,
	} {
		if got := internal(netip.MustParseAddr(addr)); got != want {
			t.Errorf("internal(%s) = %v", addr, got)
		}
	}
}
