// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123"

// TestMain doubles as a fake Tuner binary for ExecRunner: with
// FAKE_SCAN set, it prints its environment's secrets and exits 3.
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_SCAN") != "" {
		fmt.Printf(`{"id":"fake","severity":"low","title":"%s|%s"}`+"\n", os.Getenv("TUNER_SERVE_TOKEN"), os.Getenv("TUNER_WEBHOOK_SECRET"))
		fmt.Fprintln(os.Stderr, "rhythm tuner: can't reach the site")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// fakeRunner records each scan's arguments and prints lines as --jsonl
// would. With gate set, each scan waits for a value on it first.
type fakeRunner struct {
	mu    sync.Mutex
	args  [][]string
	lines []string
	exit  int
	gate  chan struct{}
	// running counts scans in flight per host (the URL in args[1]).
	running map[string]int
	peak    map[string]int
	total   atomic.Int32
	peakAll atomic.Int32
}

func (f *fakeRunner) run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.args = append(f.args, args)
	if f.running == nil {
		f.running, f.peak = map[string]int{}, map[string]int{}
	}
	f.running[args[1]]++
	f.peak[args[1]] = max(f.peak[args[1]], f.running[args[1]])
	f.mu.Unlock()
	n := f.total.Add(1)
	for {
		p := f.peakAll.Load()
		if n <= p || f.peakAll.CompareAndSwap(p, n) {
			break
		}
	}
	defer func() {
		f.total.Add(-1)
		f.mu.Lock()
		f.running[args[1]]--
		f.mu.Unlock()
	}()
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return 130, nil
		}
	}
	for _, l := range f.lines {
		fmt.Fprintln(stdout, l)
	}
	fmt.Fprintln(stderr, "rhythm tuner: example.com: vulnerability data not cached")
	return f.exit, nil
}

func (f *fakeRunner) calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.args)
}

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	runner *fakeRunner
	dns    fakeResolver
	now    atomic.Pointer[time.Time]
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, runner: &fakeRunner{}, dns: fakeResolver{}}
	start := time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC)
	h.now.Store(&start)
	cfg := Config{
		DataDir: t.TempDir(), Token: testToken, Runner: h.runner.run, Resolver: h.dns,
		Now: func() time.Time { return *h.now.Load() }, WebhookRetry: []time.Duration{time.Millisecond, time.Millisecond},
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	h.http = httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		h.http.Close()
		_ = srv.Close(context.Background())
	})
	return h
}

// do sends a request with the test token and decodes a JSON reply.
func (h *harness) do(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	return h.doToken(method, path, body, testToken)
}

func (h *harness) doToken(method, path string, body any, token string) (int, map[string]any) {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.http.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &out); err != nil {
			h.t.Fatalf("%s %s: %v\n%s", method, path, err, b)
		}
	}
	return resp.StatusCode, out
}

// verified registers u and proves it by DNS.
func (h *harness) verified(u string) map[string]any {
	h.t.Helper()
	code, tg := h.do("POST", "/v0/targets", map[string]string{"url": u})
	if code != http.StatusCreated {
		h.t.Fatalf("create target: %d %v", code, tg)
	}
	dns := tg["verify"].(map[string]any)["dns"].(map[string]any)
	h.dns[dns["name"].(string)] = []string{"v=other", dns["value"].(string)}
	if code, body := h.do("POST", "/v0/targets/"+tg["id"].(string)+"/verify", map[string]string{"method": "dns"}); code != http.StatusOK {
		h.t.Fatalf("verify: %d %v", code, body)
	}
	return tg
}

// wait polls the scan until it is final.
func (h *harness) wait(id string) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, sc := h.do("GET", "/v0/scans/"+id, nil)
		if s := sc["status"]; s != statusQueued && s != statusRunning {
			return sc
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("scan %s never finished", id)
	return nil
}

func TestUnverifiedTargetForbidden(t *testing.T) {
	h := newHarness(t, nil)
	code, tg := h.do("POST", "/v0/targets", map[string]string{"url": "Example.com/"})
	if code != http.StatusCreated || tg["url"] != "https://example.com" || tg["host"] != "example.com" || tg["is_verified"] != false {
		t.Fatalf("%d %v", code, tg)
	}
	token := tg["token"].(string)
	if !strings.HasPrefix(token, "tuner-verify=") || len(token) != len("tuner-verify=")+32 {
		t.Errorf("token %q", token)
	}
	v := tg["verify"].(map[string]any)
	if v["dns"].(map[string]any)["name"] != "_tuner-verify.example.com" || v["file"].(map[string]any)["url"] != "https://example.com/.well-known/tuner-verify.txt" {
		t.Errorf("verify instructions %v", v)
	}
	// The same URL again returns the same target and token.
	if code, again := h.do("POST", "/v0/targets", map[string]string{"url": "https://example.com"}); code != http.StatusOK || again["token"] != token {
		t.Errorf("re-register: %d %v", code, again)
	}

	code, body := h.do("POST", "/v0/scans", map[string]string{"target_id": tg["id"].(string)})
	if code != http.StatusForbidden || !strings.Contains(body["error"].(string), "isn't verified") {
		t.Errorf("unverified scan: %d %v", code, body)
	}
	// A failed check says why, per method.
	code, body = h.do("POST", "/v0/targets/"+tg["id"].(string)+"/verify", nil)
	checks, _ := body["checks"].([]any)
	if code != http.StatusUnprocessableEntity || len(checks) != 2 ||
		checks[0].(map[string]any)["error"] != "no TXT record at _tuner-verify.example.com" {
		t.Errorf("failed verify: %d %v", code, body)
	}
	if len(h.runner.calls()) != 0 {
		t.Error("an unverified target was scanned")
	}
	if code, body := h.do("POST", "/v0/scans", map[string]string{"target_id": "t_000000000000"}); code != http.StatusNotFound {
		t.Errorf("unknown target: %d %v", code, body)
	}
	for _, bad := range []string{"", "ftp://example.com", "https://user:pw@example.com", "https://example.com/?q=1"} {
		if code, body := h.do("POST", "/v0/targets", map[string]string{"url": bad}); code != http.StatusBadRequest {
			t.Errorf("url %q: %d %v", bad, code, body)
		}
	}
}

func TestTXTVerificationAndScan(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.lines = []string{
		`{"id":"leak-dotenv","title":"Exposed .env","severity":"critical","url":"https://example.com/.env"}`,
		`{"id":"wp-version","title":"WordPress version","severity":"info","url":"https://example.com/"}`,
	}
	tg := h.verified("https://example.com")
	_, got := h.do("GET", "/v0/targets/"+tg["id"].(string), nil)
	if got["is_verified"] != true || got["verified_by"] != "dns" || got["verification_expires"] != "2026-11-23T02:00:00Z" {
		t.Errorf("target after verify: %v", got)
	}
	code, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"], "profile": "quick", "tags": []string{"leak", "wordpress"}})
	if code != http.StatusAccepted || sc["status"] != statusQueued {
		t.Fatalf("%d %v", code, sc)
	}
	done := h.wait(sc["id"].(string))
	if done["status"] != statusDone || done["exit_code"] != 0.0 {
		t.Errorf("scan %v", done)
	}
	if s := done["summary"].(map[string]any); s["critical"] != 1.0 || s["info"] != 1.0 || len(done["findings"].([]any)) != 2 {
		t.Errorf("summary %v findings %v", s, done["findings"])
	}
	if log := done["log"].([]any); len(log) != 1 || !strings.Contains(log[0].(string), "not cached") {
		t.Errorf("log %v", log)
	}
	want := []string{"scan", "https://example.com", "--jsonl", "--no-color", "--max-time", "30m0s", "--profile", "quick", "--tags", "leak,wordpress"}
	if got := h.runner.calls(); !slices.Equal(got[0], want) {
		t.Errorf("args %q, want %q", got[0], want)
	}

	// Verification lapses after 30 days.
	later := h.now.Load().Add(VerifyTTL + time.Hour)
	h.now.Store(&later)
	code, body := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
	if code != http.StatusForbidden || !strings.Contains(body["error"].(string), "over 30 days old") {
		t.Errorf("expired: %d %v", code, body)
	}
}

func TestFileVerification(t *testing.T) {
	var token atomic.Value
	token.Store("")
	site := httptest.NewUnstartedServer(nil)
	port := site.Listener.Addr().(*net.TCPAddr).Port
	var mode atomic.Value
	mode.Store("serve")
	site.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/tuner-verify.txt" && mode.Load() == "serve":
			fmt.Fprintln(w, token.Load())
		case r.URL.Path == "/.well-known/tuner-verify.txt" && mode.Load() == "same-host":
			http.Redirect(w, r, "/proof.txt", http.StatusFound)
		case r.URL.Path == "/.well-known/tuner-verify.txt" && mode.Load() == "off-host":
			// localhost reaches this same server; it's another host
			// name: an attacker's redirect looks just like this.
			http.Redirect(w, r, fmt.Sprintf("https://localhost:%d/proof.txt", port), http.StatusFound)
		case r.URL.Path == "/.well-known/tuner-verify.txt" && mode.Load() == "downgrade":
			http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%d/proof.txt", port), http.StatusFound)
		case r.URL.Path == "/.well-known/tuner-verify.txt" && mode.Load() == "wrong":
			fmt.Fprintln(w, "tuner-verify=someone-else")
		case r.URL.Path == "/proof.txt":
			fmt.Fprintln(w, token.Load())
		default:
			http.NotFound(w, r)
		}
	})
	site.StartTLS()
	defer site.Close()
	h := newHarness(t, func(c *Config) { c.HTTP = site.Client() })
	code, tg := h.do("POST", "/v0/targets", map[string]string{"url": site.URL})
	if code != http.StatusCreated {
		t.Fatal(code, tg)
	}
	token.Store(tg["token"])
	id := tg["id"].(string)

	for _, c := range []struct{ mode, want string }{
		{"off-host", fmt.Sprintf("redirected off the host, to localhost:%d", port)},
		{"downgrade", "redirected to plain HTTP"},
		{"wrong", "the file doesn't hold this target's token"},
		{"missing", "HTTP 404"},
	} {
		mode.Store(c.mode)
		code, body := h.do("POST", "/v0/targets/"+id+"/verify", map[string]string{"method": "file"})
		checks, _ := body["checks"].([]any)
		if code != http.StatusUnprocessableEntity || len(checks) != 1 || !strings.Contains(checks[0].(map[string]any)["error"].(string), c.want) {
			t.Errorf("%s: %d %v", c.mode, code, body)
		}
	}
	if _, got := h.do("GET", "/v0/targets/"+id, nil); got["is_verified"] != false {
		t.Fatal("verified by a failed check")
	}
	for _, m := range []string{"same-host", "serve"} {
		mode.Store(m)
		code, body := h.do("POST", "/v0/targets/"+id+"/verify", nil)
		if code != http.StatusOK || body["verified_by"] != "file" {
			t.Errorf("%s: %d %v", m, code, body)
		}
	}
	if code, body := h.do("POST", "/v0/targets/"+id+"/verify", map[string]string{"method": "smtp"}); code != http.StatusBadRequest {
		t.Errorf("bad method: %d %v", code, body)
	}
}

func TestEventsInOrder(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.gate = make(chan struct{})
	h.runner.lines = []string{
		`{"id":"a","severity":"high"}`,
		`not json, kept as a log line`,
		`{"id":"b","severity":"low"}`,
	}
	tg := h.verified("example.com")
	_, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
	id := sc["id"].(string)

	req, _ := http.NewRequest("GET", h.http.URL+"/v0/scans/"+id+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content type %q", ct)
	}
	// The stream is open before the scan prints anything.
	close(h.runner.gate)
	events := readEvents(t, resp.Body)
	var types []string
	for _, e := range events {
		types = append(types, e.Type)
	}
	want := []string{"queued", "started", "finding", "log", "finding", "log", "done"}
	if !slices.Equal(types, want) {
		t.Fatalf("events %v, want %v", types, want)
	}
	for i, e := range events {
		if e.Seq != i+1 {
			t.Errorf("event %d has id %d", i, e.Seq)
		}
	}
	if !strings.Contains(string(events[2].Data), `"id":"a"`) || !strings.Contains(string(events[6].Data), `"status":"done"`) {
		t.Errorf("data: %s / %s", events[2].Data, events[6].Data)
	}

	// Reconnecting with Last-Event-ID replays the rest, from disk now.
	req.Header.Set("Last-Event-ID", "5")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	rest := readEvents(t, resp2.Body)
	if len(rest) != 2 || rest[0].Seq != 6 || rest[1].Type != "done" {
		t.Errorf("resumed: %+v", rest)
	}
}

// readEvents reads an SSE stream to its end.
func readEvents(t *testing.T, r io.Reader) []Event {
	t.Helper()
	var out []Event
	var cur Event
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.Type != "" {
				out = append(out, cur)
			}
			cur = Event{}
		case strings.HasPrefix(line, "id: "):
			fmt.Sscan(line[4:], &cur.Seq)
		case strings.HasPrefix(line, "event: "):
			cur.Type = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.Data = json.RawMessage(line[6:])
		}
	}
	return out
}

func TestWebhookSignature(t *testing.T) {
	const secret = "s3cret-for-hooks"
	type delivery struct {
		body   []byte
		header http.Header
	}
	got := make(chan delivery, 4)
	var fails atomic.Int32
	fails.Store(1) // the first try gets a 503 and is retried
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if fails.Add(-1) >= 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got <- delivery{b, r.Header.Clone()}
	}))
	defer recv.Close()
	h := newHarness(t, func(c *Config) { c.WebhookSecret = secret })
	h.runner.lines = []string{`{"id":"leak-dotenv","title":"Exposed .env","severity":"critical","url":"https://example.com/.env","evidence":{"matched":["APP_KEY=****"]}}`}
	tg := h.verified("example.com")
	_, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"], "webhook_url": recv.URL + "/hook?key=abc"})
	if _, ok := sc["webhook_url"]; ok {
		t.Error("the webhook URL is shown")
	}
	var d delivery
	select {
	case d = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no webhook")
	}
	sig := d.header.Get(SignatureHeader)
	if !VerifySignature(secret, d.body, sig) || VerifySignature("wrong", d.body, sig) || VerifySignature(secret, append(d.body, ' '), sig) {
		t.Errorf("signature %q doesn't verify the body", sig)
	}
	if d.header.Get(EventHeader) != EventCompleted || d.header.Get(DeliveryHeader) != sc["id"] {
		t.Errorf("headers %v", d.header)
	}
	var p WebhookPayload
	if err := json.Unmarshal(d.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Scan.Status != statusDone || p.Scan.Summary["critical"] != 1 || len(p.Scan.Findings) != 1 || p.Scan.Findings[0].Title != "Exposed .env" {
		t.Errorf("payload %s", d.body)
	}
	if bytes.Contains(d.body, []byte("APP_KEY")) {
		t.Error("evidence in the webhook payload")
	}

	// A webhook without a secret is refused up front.
	h2 := newHarness(t, nil)
	tg2 := h2.verified("example.org")
	if code, body := h2.do("POST", "/v0/scans", map[string]any{"target_id": tg2["id"], "webhook_url": recv.URL}); code != http.StatusBadRequest {
		t.Errorf("unsigned webhook: %d %v", code, body)
	}
	if _, err := New(Config{DataDir: t.TempDir(), Runner: h.runner.run, WebhookURL: recv.URL}); err == nil {
		t.Error("server webhook without a secret accepted")
	}
}

func TestMissingToken(t *testing.T) {
	h := newHarness(t, nil)
	for _, tok := range []string{"", "wrong-token-wrong-token"} {
		code, body := h.doToken("GET", "/v0/health", nil, tok)
		if code != http.StatusUnauthorized || !strings.Contains(body["error"].(string), "bearer token") {
			t.Errorf("token %q: %d %v", tok, code, body)
		}
		if code, _ := h.doToken("POST", "/v0/targets", map[string]string{"url": "example.com"}, tok); code != http.StatusUnauthorized {
			t.Errorf("token %q create: %d", tok, code)
		}
	}
	if code, body := h.do("GET", "/v0/health", nil); code != http.StatusOK || body["status"] != "ok" || body["workers"] != 2.0 {
		t.Errorf("health: %d %v", code, body)
	}
	if code, body := h.do("GET", "/v0/nope", nil); code != http.StatusNotFound || body["error"] == nil {
		t.Errorf("unknown endpoint: %d %v", code, body)
	}
}

func TestCheckListen(t *testing.T) {
	for _, c := range []struct {
		addr, token, want string
	}{
		{"127.0.0.1:8080", "", ""},
		{"[::1]:8080", "", ""},
		{"localhost:8080", "", ""},
		{"0.0.0.0:8080", "", "refusing to listen on 0.0.0.0:8080 without TUNER_SERVE_TOKEN"},
		{":8080", "", "refusing to listen on :8080"},
		{"192.168.1.5:8080", "", "refusing"},
		{"0.0.0.0:8080", testToken, ""},
		{"0.0.0.0:8080", "short", "TUNER_SERVE_TOKEN is too short"},
		{"8080", "", "want host:port"},
	} {
		err := CheckListen(c.addr, c.token)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s %q: %v, want %q", c.addr, c.token, err, c.want)
		}
	}
	srv, err := New(Config{DataDir: t.TempDir(), Runner: (&fakeRunner{}).run})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	if err := srv.ListenAndServe(context.Background(), "0.0.0.0:0"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("ListenAndServe without a token: %v", err)
	}
}

func TestServeShutsDown(t *testing.T) {
	r := &fakeRunner{gate: make(chan struct{})}
	srv, err := New(Config{DataDir: t.TempDir(), Runner: r.run, Resolver: fakeResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx, ln) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/v0/health") // no token on loopback
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health without token on loopback: %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve didn't stop")
	}
}

func TestPerHostQueue(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Workers = 3 })
	h.runner.gate = make(chan struct{})
	a := h.verified("a.example")
	b := h.verified("b.example")
	var ids []string
	for _, tg := range []map[string]any{a, a, b} {
		_, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
		ids = append(ids, sc["id"].(string))
	}
	// a's first scan and b's run; a's second waits for its host.
	deadline := time.Now().Add(5 * time.Second)
	for h.runner.total.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := h.runner.total.Load(); n != 2 {
		t.Errorf("%d scans running, want 2", n)
	}
	if code, health := h.do("GET", "/v0/health", nil); code != 200 || health["queued"] != 1.0 || health["running"] != 2.0 {
		t.Errorf("health %v", health)
	}
	close(h.runner.gate)
	for _, id := range ids {
		h.wait(id)
	}
	h.runner.mu.Lock()
	peak := h.runner.peak["https://a.example"]
	h.runner.mu.Unlock()
	if peak != 1 {
		t.Errorf("a.example ran %d scans at once", peak)
	}
}

func TestRequestLimits(t *testing.T) {
	h := newHarness(t, nil)
	big := map[string]string{"url": "example.com", "pad": strings.Repeat("x", maxBody)}
	if code, body := h.do("POST", "/v0/targets", big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("big body: %d %v", code, body)
	}
	if code, body := h.do("POST", "/v0/targets", map[string]string{"site": "example.com"}); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "unknown field") {
		t.Errorf("unknown field: %d %v", code, body)
	}
	tg := h.verified("example.com")
	for _, opts := range []map[string]any{
		{"profile": "insane"},
		{"severity": "severe"},
		{"tags": []string{"--checks=/etc"}},
		{"ids": []string{"leak dotenv"}},
		{"checks": "/etc"},
	} {
		opts["target_id"] = tg["id"]
		if code, body := h.do("POST", "/v0/scans", opts); code != http.StatusBadRequest {
			t.Errorf("%v: %d %v", opts, code, body)
		}
	}
}

func TestQueueFull(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Workers = 1; c.MaxQueue = 1 })
	h.runner.gate = make(chan struct{})
	defer close(h.runner.gate)
	tg := h.verified("example.com")
	codes := []int{}
	for range 4 {
		code, _ := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
		codes = append(codes, code)
		time.Sleep(20 * time.Millisecond) // let the worker take the first
	}
	if codes[0] != http.StatusAccepted || codes[3] != http.StatusTooManyRequests {
		t.Errorf("codes %v", codes)
	}
}

func TestRestartAndClose(t *testing.T) {
	dir := t.TempDir()
	r := &fakeRunner{gate: make(chan struct{})}
	dns := fakeResolver{}
	cfg := Config{DataDir: dir, Token: testToken, Runner: r.run, Resolver: dns}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, http: httptest.NewServer(srv.Handler()), dns: dns}
	defer h.http.Close()
	tg := h.verified("example.com")
	_, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
	id := sc["id"].(string)
	for r.total.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if err := srv.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, got := h.do("GET", "/v0/scans/"+id, nil); got["status"] != statusCanceled {
		t.Errorf("after Close: %v", got)
	}

	// A record left running by a crash reads as interrupted after a
	// restart; the targets survive it.
	crashed := filepath.Join(dir, "scans", "s_0123456789abcdef.json")
	os.WriteFile(crashed, []byte(`{"id":"s_0123456789abcdef","status":"running","summary":{},"findings":[]}`), 0o600)
	srv2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close(context.Background())
	h2 := &harness{t: t, srv: srv2, http: httptest.NewServer(srv2.Handler())}
	defer h2.http.Close()
	if _, got := h2.do("GET", "/v0/scans/s_0123456789abcdef", nil); got["status"] != statusInterrupted || !strings.Contains(got["error"].(string), "while the scan was running") {
		t.Errorf("crashed scan: %v", got)
	}
	if _, got := h2.do("GET", "/v0/targets/"+tg["id"].(string), nil); got["is_verified"] != true {
		t.Errorf("target after restart: %v", got)
	}
	if code, _ := h2.do("GET", "/v0/scans/..%2F..%2Ftargets", nil); code != http.StatusNotFound {
		t.Error("path in scan id")
	}
	if code, _ := h2.do("DELETE", "/v0/targets/"+tg["id"].(string), nil); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
	if code, _ := h2.do("GET", "/v0/targets/"+tg["id"].(string), nil); code != http.StatusNotFound {
		t.Errorf("deleted target: %d", code)
	}
}

func TestExecRunner(t *testing.T) {
	exe, _ := os.Executable()
	t.Setenv("FAKE_SCAN", "1")
	// A -race build otherwise pauses a second at exit (atexit_sleep_ms).
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	t.Setenv("TUNER_SERVE_TOKEN", "server-token")
	t.Setenv("TUNER_WEBHOOK_SECRET", "hook-secret")
	var out, errb bytes.Buffer
	code, err := ExecRunner(exe, t.TempDir())(context.Background(), []string{"scan", "https://example.com"}, &out, &errb)
	if err != nil || code != 3 {
		t.Fatalf("exit %d, %v", code, err)
	}
	if strings.Contains(out.String(), "server-token") || strings.Contains(out.String(), "hook-secret") || !strings.Contains(errb.String(), "can't reach") {
		t.Errorf("stdout %q stderr %q", out.String(), errb.String())
	}
	if _, err := ExecRunner(filepath.Join(t.TempDir(), "missing"), "")(context.Background(), nil, &out, &errb); err == nil {
		t.Error("missing binary ran")
	}
}

func TestFailedScanStatus(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.exit = 3
	tg := h.verified("example.com")
	_, sc := h.do("POST", "/v0/scans", map[string]any{"target_id": tg["id"]})
	done := h.wait(sc["id"].(string))
	if done["status"] != statusFailed || done["exit_code"] != 3.0 || done["error"] != "the scan exited 3; see log" {
		t.Errorf("%v", done)
	}
}

func TestLineWriter(t *testing.T) {
	var got []string
	lw := &lineWriter{fn: func(b []byte) { got = append(got, string(b)) }}
	lw.Write([]byte("one\ntw"))
	lw.Write([]byte("o\n"))
	lw.Write(bytes.Repeat([]byte("x"), maxLine+1))
	lw.Write([]byte("still long\nthree"))
	lw.flush()
	if !slices.Equal(got, []string{"one", "two", "three"}) {
		t.Errorf("%q", got)
	}
}

// TestTokenlessRefusesBrowserAttacks covers the two ways a web page in
// the operator's browser could drive a tokenless server: DNS rebinding
// (a foreign Host) and a simple cross-site POST (a text/plain body).
func TestTokenlessRefusesBrowserAttacks(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Token = "" })
	send := func(host, contentType string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("POST", h.http.URL+"/v0/targets", strings.NewReader(`{"url":"example.com"}`))
		if host != "" {
			req.Host = host
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Origin", "http://rebind.attacker.example:8080")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	for _, c := range []struct {
		host, contentType string
		want              int
		msg               string
	}{
		{"rebind.attacker.example:8080", "application/json", http.StatusForbidden, `Host "rebind.attacker.example:8080" is not a loopback name`},
		{"rebind.attacker.example", "text/plain", http.StatusForbidden, "not a loopback name"},
		{"10.0.0.5:8080", "application/json", http.StatusForbidden, "not a loopback name"},
		{"", "text/plain", http.StatusUnsupportedMediaType, "Content-Type: application/json"},
		{"", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType, "Content-Type: application/json"},
		{"", "", http.StatusUnsupportedMediaType, "Content-Type: application/json"},
		{"", "application/json; charset=utf-8", http.StatusCreated, ""},
		{"localhost:8080", "application/json", http.StatusCreated, ""},
		{"[::1]:8080", "application/json", http.StatusCreated, ""},
		{"127.1.2.3", "application/json", http.StatusCreated, ""},
	} {
		code, body := send(c.host, c.contentType)
		if code == http.StatusOK && c.want == http.StatusCreated {
			code = http.StatusCreated // the same site again returns the first target
		}
		if code != c.want {
			t.Errorf("Host %q, %q: %d %v, want %d", c.host, c.contentType, code, body, c.want)
			continue
		}
		if c.msg != "" && !strings.Contains(fmt.Sprint(body["error"]), c.msg) {
			t.Errorf("Host %q, %q: error %v, want %q", c.host, c.contentType, body["error"], c.msg)
		}
		if c.want != http.StatusCreated && body["token"] != nil {
			t.Errorf("Host %q, %q: refused reply leaked a token", c.host, c.contentType)
		}
	}
	// A GET from a rebinding page is refused as well, so it can't read
	// targets or findings.
	req, _ := http.NewRequest("GET", h.http.URL+"/v0/targets", nil)
	req.Host = "rebind.attacker.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("rebinding GET: %d", resp.StatusCode)
	}
}

// TestTokenAllowsAnyHost checks that the Host guard applies only
// without a token: behind a token the API may sit behind a proxy or a
// public name.
func TestTokenAllowsAnyHost(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest("GET", h.http.URL+"/v0/health", nil)
	req.Host = "tuner.example.com"
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("token with a public Host: %d", resp.StatusCode)
	}
	if code, _ := h.doRaw("POST", "/v0/targets", `{"url":"example.com"}`, "text/plain"); code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST with a token: %d", code)
	}
	if code, _ := h.doRaw("POST", "/v0/targets/t_missing/verify", "", ""); code != http.StatusNotFound {
		t.Errorf("empty POST without Content-Type: %d, want it to reach the handler", code)
	}
}

// doRaw sends body as is with the given Content-Type and the test token.
func (h *harness) doRaw(method, path, body, contentType string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.http.URL+path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestFileVerificationPlainHTTP checks that a site served only over
// http on its own port proves itself at that same address.
func TestFileVerificationPlainHTTP(t *testing.T) {
	var token atomic.Value
	token.Store("")
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/tuner-verify.txt" {
			fmt.Fprintln(w, token.Load())
			return
		}
		http.NotFound(w, r)
	}))
	defer site.Close()
	h := newHarness(t, nil)
	code, tg := h.do("POST", "/v0/targets", map[string]string{"url": site.URL})
	if code != http.StatusCreated {
		t.Fatal(code, tg)
	}
	want := site.URL + "/.well-known/tuner-verify.txt"
	if got := tg["verify"].(map[string]any)["file"].(map[string]any)["url"]; got != want {
		t.Errorf("proof URL %v, want %s", got, want)
	}
	token.Store(tg["token"])
	code, body := h.do("POST", "/v0/targets/"+tg["id"].(string)+"/verify", map[string]string{"method": "file"})
	if code != http.StatusOK || body["verified_by"] != "file" {
		t.Errorf("http file proof: %d %v", code, body)
	}
}
