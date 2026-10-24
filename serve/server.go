// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package serve is Tuner's HTTP API for agencies and hosts: register a
// site, prove you own it, queue scans and follow them as they run.
//
// A site must pass an ownership check (a DNS TXT record or a file under
// /.well-known) before it can be scanned, so the API can't be pointed at
// someone else's site. Each scan runs the Tuner binary as a child
// process, which keeps a scan's memory out of the long-running server
// and lets one scan crash without taking the others down.
//
// Endpoints (all JSON, all behind the bearer token when one is set; a
// POST body needs Content-Type: application/json):
//
//	GET    /v0/health
//	POST   /v0/targets                 {"url": "https://example.com"}
//	GET    /v0/targets, /v0/targets/{id}
//	DELETE /v0/targets/{id}
//	POST   /v0/targets/{id}/verify     {"method": "dns" | "file"} (both when empty)
//	POST   /v0/scans                   {"target_id": "...", "profile": "quick", ...}
//	GET    /v0/scans/{id}
//	GET    /v0/scans/{id}/events       Server-Sent Events
package serve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Defaults for the Config fields left zero.
const (
	DefaultWorkers     = 2
	DefaultMaxScanTime = 30 * time.Minute
	DefaultMaxQueue    = 100
	// MinTokenLength keeps the bearer token out of guessing range.
	MinTokenLength = 16
	// maxBody caps request bodies; every request is a small JSON object.
	maxBody = 64 << 10
)

// Runner runs the Tuner binary with args, writing its standard output
// and error to stdout and stderr; it returns the exit code. Canceling
// ctx stops it. Tests swap in a fake.
type Runner func(ctx context.Context, args []string, stdout, stderr io.Writer) (exit int, err error)

// Resolver looks up DNS TXT records; *net.Resolver is one.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Config sets up a Server.
type Config struct {
	DataDir string // targets.json and scans/<id>.json
	// Token is the bearer token every request must carry. Empty turns
	// authentication off, which CheckListen allows on loopback only.
	Token   string
	Workers int // scans at once across all sites (default 2)
	// MaxScanTime is passed to each scan as --max-time (default 30m).
	MaxScanTime time.Duration
	MaxQueue    int // queued scans before POST /v0/scans answers 429 (default 100)
	Runner      Runner
	Resolver    Resolver // default net.DefaultResolver
	// HTTP fetches verification files and delivers webhooks. Its
	// redirect policy is replaced: verification follows same-host
	// redirects only and webhooks follow none.
	HTTP *http.Client
	// WebhookURL receives every scan's completion; a scan request can
	// name its own too. WebhookSecret signs them (HMAC-SHA256).
	WebhookURL    string
	WebhookSecret string
	// WebhookRetry is the wait before each retry of a failed delivery
	// (default 5s, 30s, 2m).
	WebhookRetry []time.Duration
	UserAgent    string
	Version      string
	Log          io.Writer // one line per notable event; default io.Discard
	Now          func() time.Time
}

// Server is the API. Create it with New, serve Handler and Close it to
// stop the workers.
type Server struct {
	cfg     Config
	store   *store
	queue   *queue
	mux     *http.ServeMux
	ctx     context.Context // canceled by Close: stops running scans
	cancel  context.CancelFunc
	workers sync.WaitGroup
	hooks   sync.WaitGroup // webhook deliveries in flight
	logMu   sync.Mutex
}

// New loads the data folder and starts the workers.
func New(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("serve: no data folder")
	}
	if cfg.Runner == nil {
		return nil, errors.New("serve: no runner")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.MaxScanTime <= 0 {
		cfg.MaxScanTime = DefaultMaxScanTime
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = DefaultMaxQueue
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{}
	}
	if cfg.WebhookRetry == nil {
		cfg.WebhookRetry = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "rhythm-tuner-serve"
	}
	if cfg.WebhookURL != "" && cfg.WebhookSecret == "" {
		return nil, errors.New("a webhook needs a signing secret (--webhook-secret or TUNER_WEBHOOK_SECRET)")
	}
	st, interrupted, err := openStore(cfg.DataDir, cfg.Now)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st, queue: newQueue(cfg.MaxQueue)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	for _, id := range interrupted {
		s.logf("scan %s was queued or running when the server stopped; marked interrupted", id)
	}
	s.routes()
	for range cfg.Workers {
		s.workers.Go(s.work)
	}
	return s, nil
}

// Close stops taking scans, cancels the ones running (they are saved as
// canceled) and waits for the workers and for webhook deliveries until
// ctx is done.
func (s *Server) Close(ctx context.Context) error {
	for _, sc := range s.queue.close() {
		s.finish(sc, statusCanceled, -1, "the server stopped before the scan started")
	}
	s.cancel()
	done := make(chan struct{})
	go func() {
		s.workers.Wait()
		s.hooks.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Handler is the API's HTTP handler, authentication included.
func (s *Server) Handler() http.Handler { return s.auth(s.mux) }

// ListenAndServe serves the API on addr until ctx is done, then shuts
// down: no new requests, running scans canceled, webhooks given up to
// 10 seconds to go out.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if err := CheckListen(addr, s.cfg.Token); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve is ListenAndServe on an open listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	s.logf("listening on %s", ln.Addr())
	select {
	case err := <-errc:
		_ = s.Close(context.Background())
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Close first: canceling s.ctx ends the event streams, which would
	// otherwise hold Shutdown for its whole timeout.
	cerr := s.Close(sctx)
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return cerr
}

// CheckListen refuses to serve without a token anywhere but loopback,
// and refuses a short token anywhere.
func CheckListen(addr, token string) error {
	if token != "" && len(token) < MinTokenLength {
		return fmt.Errorf("TUNER_SERVE_TOKEN is too short; use at least %d random characters, e.g. from: openssl rand -hex 32", MinTokenLength)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--listen %q: want host:port, e.g. 127.0.0.1:8080", addr)
	}
	if token == "" && !isLoopback(host) {
		return fmt.Errorf("refusing to listen on %s without TUNER_SERVE_TOKEN: anyone who can reach it could queue scans; set the token, or listen on 127.0.0.1", addr)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// auth checks the bearer token in constant time and caps the body and
// write time of everything but event streams.
//
// Without a token it also guards against the operator's own browser. A
// page served from a rebinding domain reaches 127.0.0.1 with its own
// name in Host, so only loopback names are let in. A page on any origin
// can still send a "simple" cross-site POST, which a browser sends
// without asking first only for form and text/plain bodies, so a POST
// body must be application/json: that forces a CORS preflight, which
// this API never answers.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="tuner"`)
				writeError(w, http.StatusUnauthorized, "missing or wrong bearer token (Authorization: Bearer $TUNER_SERVE_TOKEN)")
				return
			}
		} else if !loopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("Host %q is not a loopback name; without TUNER_SERVE_TOKEN the API answers only localhost, 127.0.0.1 and [::1]", r.Host))
			return
		}
		if r.Method == http.MethodPost && r.ContentLength != 0 && !isJSON(r.Header.Get("Content-Type")) {
			writeError(w, http.StatusUnsupportedMediaType, "a request body must be JSON with Content-Type: application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		if !strings.HasSuffix(r.URL.Path, "/events") {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		next.ServeHTTP(w, r)
	})
}

// loopbackHost reports whether a request's Host names this machine:
// localhost, 127.0.0.0/8 or ::1, with or without a port.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return isLoopback(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

// isJSON reports whether a Content-Type is application/json, parameters
// such as charset allowed.
func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /v0/health", s.health)
	m.HandleFunc("POST /v0/targets", s.createTarget)
	m.HandleFunc("GET /v0/targets", s.listTargets)
	m.HandleFunc("GET /v0/targets/{id}", s.getTarget)
	m.HandleFunc("DELETE /v0/targets/{id}", s.deleteTarget)
	m.HandleFunc("POST /v0/targets/{id}/verify", s.verifyTarget)
	m.HandleFunc("POST /v0/scans", s.createScan)
	m.HandleFunc("GET /v0/scans/{id}", s.getScan)
	m.HandleFunc("GET /v0/scans/{id}/events", s.scanEvents)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint: "+r.Method+" "+r.URL.Path)
	})
	s.mux = m
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	queued, running := s.queue.counts()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "version": s.cfg.Version, "workers": s.cfg.Workers,
		"queued": queued, "running": running,
	})
}

func (s *Server) logf(format string, a ...any) {
	if s.cfg.Log == nil {
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Fprintf(s.cfg.Log, "%s "+format+"\n", append([]any{s.cfg.Now().UTC().Format(time.RFC3339)}, a...)...)
}

// apiError is every error response: {"error": "..."} plus details.
type apiError struct {
	Error  string        `json:"error"`
	Checks []verifyCheck `json:"checks,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apiError{Error: msg})
}

// readJSON decodes a request body strictly: unknown fields are typos.
// An empty body leaves v as it is.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	var tooBig *http.MaxBytesError
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return true
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body over %d bytes", tooBig.Limit))
	default:
		writeError(w, http.StatusBadRequest, "bad JSON body: "+err.Error())
	}
	return false
}

// newID returns prefix plus n random bytes in hex.
func newID(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return prefix + hex.EncodeToString(b)
}
