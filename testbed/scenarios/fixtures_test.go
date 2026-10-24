// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// serverSpec is one fixture server in expect.yaml.
type serverSpec struct {
	Name string `yaml:"name"`
	// Kind is "routes" (the default) or "data", the fake vulnerability,
	// wordpress.org, php.net, OSV, check pack and GitHub services.
	Kind string `yaml:"kind"`
	// Listen is the loopback address: 127.0.0.1 (default) or ::1.
	Listen string `yaml:"listen"`
	// TLS is "" for plain HTTP, "self-signed" or "h2-only" (TLS that
	// refuses HTTP/1.1). Both use a certificate no client trusts.
	TLS string `yaml:"tls"`
	// Routes maps a path to its response. "/blog/*" matches a prefix and
	// "*" everything else; without "*" other paths get a plain 404.
	Routes map[string]route `yaml:"routes"`
	// State is a data server's starting state (see dataHandler).
	State string `yaml:"state"`
}

// route is one canned response.
type route struct {
	Status  int               `yaml:"status"` // default 200
	Body    string            `yaml:"body"`
	File    string            `yaml:"file"`   // body from this file, relative to the scenario folder
	Repeat  int               `yaml:"repeat"` // send the body this many times
	Type    string            `yaml:"type"`   // Content-Type; default text/html
	Headers map[string]string `yaml:"headers"`
	Delay   duration          `yaml:"delay"` // wait this long before answering
	Hang    bool              `yaml:"hang"`  // never answer
	// Reset sends the headers and half the body, then resets the
	// connection.
	Reset bool `yaml:"reset"`
}

// duration reads "2s" or "150ms" from YAML.
type duration time.Duration

func (d *duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = duration(v)
	return err
}

// hit is one request a fixture server saw.
type hit struct {
	Method string
	Path   string // with the query, as sent
	Host   string
	Proto  string
	Header http.Header
}

// server is a running fixture.
type server struct {
	spec   serverSpec
	ln     net.Listener
	url    string
	srv    *http.Server
	closed chan struct{}

	mu    sync.Mutex
	hits  []hit
	state string
}

func (s *server) log(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, hit{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Proto: r.Proto, Header: r.Header.Clone()})
}

// requests returns the requests seen so far and forgets them, so each
// step's assertions see only that step's traffic.
func (s *server) requests() []hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.hits
	s.hits = nil
	return out
}

func (s *server) setState(st string) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

func (s *server) getState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// start serves s on its listener. dir is the scenario folder and expand
// fills in {{...}} placeholders in bodies and headers.
func (s *server) start(dir string, expand func(string) string) error {
	var h http.Handler
	switch s.spec.Kind {
	case "", "routes":
		rt, err := loadRoutes(s.spec.Routes, dir, expand)
		if err != nil {
			return fmt.Errorf("server %s: %w", s.spec.Name, err)
		}
		h = s.routesHandler(rt)
	case "data":
		states, err := os.ReadFile(filepath.Join(dir, "..", "..", "..", "vulns", "testdata", "phpnet-states.json"))
		if err != nil {
			return fmt.Errorf("server %s: %w", s.spec.Name, err)
		}
		s.state = s.spec.State
		h = s.dataHandler(states)
	default:
		return fmt.Errorf("server %s: unknown kind %q", s.spec.Name, s.spec.Kind)
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log(r)
		h.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 10 * time.Second, ErrorLog: quietLog}

	ln := s.ln
	switch s.spec.TLS {
	case "":
	case "self-signed", "h2-only":
		cert, err := selfSigned()
		if err != nil {
			return err
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if s.spec.TLS == "h2-only" {
			var p http.Protocols
			p.SetHTTP2(true)
			s.srv.Protocols = &p
			cfg.NextProtos = []string{"h2"}
			inner := s.srv.Handler
			s.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor < 2 {
					http.Error(w, "HTTP/2 only", http.StatusHTTPVersionNotSupported)
					return
				}
				inner.ServeHTTP(w, r)
			})
		}
		s.srv.TLSConfig = cfg
		ln = tls.NewListener(ln, cfg)
	default:
		return fmt.Errorf("server %s: unknown tls %q", s.spec.Name, s.spec.TLS)
	}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

func (s *server) stop() {
	close(s.closed) // wakes hanging handlers so Close doesn't wait on them
	_ = s.srv.Close()
	_ = s.ln.Close()
}

// wait blocks like a server that never answers, until the client gives
// up or the scenario ends.
func (s *server) wait(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-s.closed:
	}
}

type compiled struct {
	route
	body []byte
}

func loadRoutes(in map[string]route, dir string, expand func(string) string) (map[string]compiled, error) {
	out := map[string]compiled{}
	for path, r := range in {
		body := []byte(expand(r.Body))
		if r.File != "" {
			b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(r.File)))
			if err != nil {
				return nil, err
			}
			body = b
		}
		if r.Repeat > 1 {
			body = []byte(strings.Repeat(string(body), r.Repeat))
		}
		hdr := map[string]string{}
		for k, v := range r.Headers {
			hdr[k] = expand(v)
		}
		r.Headers = hdr
		out[path] = compiled{route: r, body: body}
	}
	return out, nil
}

func match(routes map[string]compiled, path string) (compiled, bool) {
	if r, ok := routes[path]; ok {
		return r, true
	}
	// Longest prefix first, so /blog/wp-*/ beats /blog/*.
	var prefixes []string
	for p := range routes {
		if strings.HasSuffix(p, "*") && p != "*" {
			prefixes = append(prefixes, p)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	for _, p := range prefixes {
		if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
			return routes[p], true
		}
	}
	r, ok := routes["*"]
	return r, ok
}

func (s *server) routesHandler(routes map[string]compiled) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, ok := match(routes, r.URL.Path)
		if !ok {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		if rt.Hang {
			s.wait(r)
			return
		}
		if rt.Delay > 0 {
			select {
			case <-time.After(time.Duration(rt.Delay)):
			case <-r.Context().Done():
				return
			case <-s.closed:
				return
			}
		}
		typ := rt.Type
		if typ == "" {
			typ = "text/html; charset=utf-8"
		}
		status := rt.Status
		if status == 0 {
			status = http.StatusOK
		}
		if rt.Reset {
			reset(w, status, typ, rt.body)
			return
		}
		for k, v := range rt.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", typ)
		w.Header().Set("Content-Length", strconv.Itoa(len(rt.body)))
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write(rt.body)
		}
	})
}

// reset promises the whole body, sends half of it and then resets the
// connection, like a proxy or PHP worker dying mid-response.
func reset(w http.ResponseWriter, status int, typ string, body []byte) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("reset needs HTTP/1.1")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", status, http.StatusText(status), typ, len(body))
	_, _ = buf.Write(body[:len(body)/2])
	_ = buf.Flush()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0) // RST instead of FIN
	}
	_ = conn.Close()
}

// The fake advisories for the plugin "gallery": state v1 has one low
// advisory, v2 adds a critical one on CISA's known exploited list.
var (
	galleryLow = map[string]any{
		"uuid": "scenario-low", "name": "Gallery < 2.0 - Reflected XSS",
		"operator": map[string]any{"max_version": "2.0", "max_operator": "lt", "unfixed": "0"},
		"source":   []any{map[string]any{"id": "CVE-2024-0001", "name": "Gallery < 2.0 - Reflected XSS", "link": "https://example.invalid/1"}},
		"impact":   map[string]any{"cvss3": map[string]any{"score": "3.1", "severity": "low"}, "kev": false},
	}
	galleryCritical = map[string]any{
		"uuid": "scenario-critical", "name": "Gallery < 3.0 - Unauthenticated RCE",
		"operator": map[string]any{"max_version": "3.0", "max_operator": "lt", "unfixed": "0"},
		"source":   []any{map[string]any{"id": "CVE-2026-0002", "name": "Gallery < 3.0 - Unauthenticated RCE", "link": "https://example.invalid/2"}},
		"impact":   map[string]any{"cvss3": map[string]any{"score": "9.8", "severity": "critical"}, "kev": true},
	}
)

// dataHandler fakes every data service Tuner calls. Its state, set in
// expect.yaml and changed per step, decides how it behaves:
//
//	v1 (default)  answers normally, gallery has one low advisory
//	v2            gallery also has a critical, actively exploited one
//	down          500 for everything
//	hang          never answers
//	slow          answers like v1 after 3 seconds
//	html          200 with an HTML page instead of JSON
//
// The check pack, OSV and GitHub release endpoints always answer 404 or
// empty, so a scan falls back to built-in checks and no update notice.
func (s *server) dataHandler(phpStates []byte) http.Handler {
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.getState()
		p := r.URL.Path
		switch st {
		case "hang":
			s.wait(r)
			return
		case "down":
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		case "html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<!doctype html><html><body><h1>Service temporarily unavailable</h1></body></html>")
			return
		case "slow":
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
				return
			case <-s.closed:
				return
			}
		}
		switch {
		case strings.HasPrefix(p, "/plugin/gallery/"):
			vulns := []any{galleryLow}
			if st == "v2" {
				vulns = append(vulns, galleryCritical)
			}
			j(w, map[string]any{"error": 0, "data": map[string]any{"name": "Gallery", "closed": 0, "vulnerability": vulns}})
		case strings.HasPrefix(p, "/plugin/"), strings.HasPrefix(p, "/theme/"):
			j(w, map[string]any{"error": 0, "data": map[string]any{"name": "x", "closed": 0, "vulnerability": []any{}}})
		case strings.HasPrefix(p, "/core/version-check"):
			j(w, map[string]any{"offers": []any{map[string]any{"current": "6.9.3"}}})
		case strings.HasPrefix(p, "/core/"):
			j(w, map[string]any{"error": 0, "data": map[string]any{"vulnerability": []any{}}})
		case strings.HasPrefix(p, "/plugins/info"), strings.HasPrefix(p, "/themes/info"):
			j(w, map[string]any{"version": "3.1", "last_updated": "2026-09-01 1:00pm GMT"})
		case strings.HasPrefix(p, "/php/"):
			j(w, map[string]any{"error": 0, "data": map[string]any{"name": "PHP", "date_end": "2099-01-01", "vulnerability": []any{}}})
		case strings.HasPrefix(p, "/releases/states.php"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(phpStates)
		case r.Method == http.MethodPost && strings.HasPrefix(p, "/v1/query"):
			j(w, map[string]any{})
		default:
			http.Error(w, `{"error":1,"message":"not found"}`, http.StatusNotFound)
		}
	})
}

// selfSigned makes a throwaway certificate for the loopback names.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tuner scenario fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// hostsOf lists the listen addresses the specs need, in order.
func hostsOf(specs []serverSpec) []string {
	var out []string
	for _, s := range specs {
		h := s.Listen
		if h == "" {
			h = "127.0.0.1"
		}
		out = append(out, h)
	}
	return out
}

// urlOf is the base URL of a listener for a spec.
func urlOf(spec serverSpec, ln net.Listener) string {
	scheme := "http"
	if spec.TLS != "" {
		scheme = "https"
	}
	return scheme + "://" + ln.Addr().String()
}

// hostOnly reports whether all requests went to these Host values.
func hostsSeen(hits []hit) []string {
	var out []string
	for _, h := range hits {
		if !slices.Contains(out, h.Host) {
			out = append(out, h.Host)
		}
	}
	return out
}
