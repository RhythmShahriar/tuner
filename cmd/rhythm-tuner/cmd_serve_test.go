// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/serve"
)

// With fakeServeEnv set, the test binary is a fake scan for the server:
// it prints its arguments as a finding's title, as --jsonl would, and
// exits 0. This runs in init, before the testing package reads flags.
const fakeServeEnv = "TUNER_TEST_FAKE_SERVE_SCAN"

func init() {
	if os.Getenv(fakeServeEnv) == "" {
		return
	}
	b, _ := json.Marshal(map[string]string{"id": "leak-dotenv", "severity": "critical", "title": strings.Join(os.Args[1:], " ")})
	fmt.Println(string(b))
	os.Exit(0)
}

type txtRecords map[string][]string

func (r txtRecords) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestServeEndToEnd(t *testing.T) {
	const token = "test-token-0123456789"
	t.Setenv("TUNER_SERVE_TOKEN", token)
	t.Setenv("TUNER_WEBHOOK_SECRET", "")
	t.Setenv(fakeServeEnv, "1")
	exe, _ := os.Executable()
	cfg, listen, err := planServe([]string{"--data", t.TempDir(), "--exec", exe, "--workers", "1", "--max-scan-time", "5m"})
	if err != nil || listen != "127.0.0.1:8080" || cfg.Token != token || cfg.Workers != 1 {
		t.Fatalf("%+v %s %v", cfg, listen, err)
	}
	dns := txtRecords{}
	cfg.Resolver = dns
	srv, err := serve.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	call := func(method, path, body string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(method, hs.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	tg := call("POST", "/v0/targets", `{"url":"example.com"}`)
	dns["_tuner-verify.example.com"] = []string{tg["token"].(string)}
	if v := call("POST", "/v0/targets/"+tg["id"].(string)+"/verify", ""); v["is_verified"] != true {
		t.Fatalf("verify: %v", v)
	}
	sc := call("POST", "/v0/scans", fmt.Sprintf(`{"target_id":%q,"profile":"quick"}`, tg["id"]))
	var done map[string]any
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if done = call("GET", "/v0/scans/"+sc["id"].(string), ""); done["status"] == "done" {
			break
		}
	}
	findings, _ := done["findings"].([]any)
	if done["status"] != "done" || len(findings) != 1 {
		t.Fatalf("scan: %v", done)
	}
	title := findings[0].(map[string]any)["title"]
	if title != "scan https://example.com --jsonl --no-color --max-time 5m0s --profile quick" {
		t.Errorf("scan args %q", title)
	}
}

func TestServeFlags(t *testing.T) {
	t.Setenv("TUNER_SERVE_TOKEN", "")
	t.Setenv("TUNER_WEBHOOK_SECRET", "")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--listen", "0.0.0.0:8080"}, "refusing to listen on 0.0.0.0:8080 without TUNER_SERVE_TOKEN"},
		{[]string{"--workers", "0"}, "--workers 0: want 1 or more"},
		{[]string{"--max-queue", "0"}, "--max-queue 0: want 1 or more"},
		{[]string{"--max-scan-time", "10s"}, "--max-scan-time 10s: want at least 1m"},
		{[]string{"--webhook", "https://hooks.example/x"}, "--webhook needs a signing secret"},
		{[]string{"example.com"}, "serve takes no targets"},
		{[]string{"--listne", "x"}, "unknown flag --listne; did you mean --listen?"},
	} {
		if _, _, err := planServe(c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
	var out, errb bytes.Buffer
	if code := cmdServe([]string{"--listen", "0.0.0.0:8080"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "refusing") {
		t.Errorf("non-loopback without token: exit %d\n%s", code, errb.String())
	}
	if code := cmdServe([]string{"--help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "POST   /v0/targets/{id}/verify") {
		t.Errorf("help: %d", code)
	}

	t.Setenv("TUNER_SERVE_TOKEN", "test-token-0123456789")
	t.Setenv("TUNER_WEBHOOK_SECRET", "hook-secret")
	cfg, _, err := planServe([]string{"--listen", "0.0.0.0:9000", "--webhook", "https://hooks.example/x", "--data", t.TempDir()})
	if err != nil || cfg.WebhookSecret != "hook-secret" || cfg.WebhookURL != "https://hooks.example/x" {
		t.Errorf("%+v %v", cfg, err)
	}
	if cache, _ := os.UserCacheDir(); cache != "" {
		cfg, _, _ := planServe(nil)
		if !slices.Contains(strings.Split(cfg.DataDir, string(os.PathSeparator)), "serve") {
			t.Errorf("default data folder %s", cfg.DataDir)
		}
	}
}
