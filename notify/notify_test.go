// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/diff"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
	"github.com/RhythmShahriar/tuner/report"
)

const (
	fixtureSecret = "AKIAIOSFODNN7EXAMPLE" // an AWS key ID the secret rules mask
	bodyMarker    = "BODY-ONLY-IN-EVIDENCE"
	token         = "SECRETTOKEN123"
)

// newFindings compares a scan with an earlier one that only knew site b's
// plugin, with one advisory fewer. New: a critical with a secret and an
// escape sequence in its title, the plugin's new advisory (high), a medium
// on site b and a low that --notify-min high drops.
func newFindings() diff.Result {
	f := func(target, id, title, path string, sev engine.Severity) engine.Finding {
		return engine.Finding{ID: id, Title: title, Severity: sev, Confidence: "high", Target: target,
			URL: target + path, Path: path, Fix: "Remove the file.\n\x1b[2Kthen rotate keys",
			Evidence: engine.Evidence{Request: "GET " + path, Status: 200, Matched: []string{bodyMarker + " " + fixtureSecret}}}
	}
	a := report.New(&engine.Result{Target: "https://user:pw@a.test", Findings: []engine.Finding{
		f("https://user:pw@a.test", "leak-dotenv", ".env with "+fixtureSecret+"\x1b]0;PWNED\x07", "/.env", engine.Critical),
		f("https://user:pw@a.test", "xmlrpc", "XML-RPC is on", "/xmlrpc.php", engine.Low),
	}}, "test")
	vuln := f("https://b.test", "vuln-plugin-gallery", "gallery 1.5: 1 known vulnerability", "/wp-content/plugins/gallery/", engine.High)
	known := engine.Advisory{ID: "WPV-0", CVEs: []string{"CVE-2025-9"}, Severity: engine.Medium}
	vuln.Advisories = []engine.Advisory{known}
	before := report.New(&engine.Result{Target: "https://b.test", Findings: []engine.Finding{vuln}}, "test")
	vuln.Advisories = []engine.Advisory{known, {ID: "WPV-1", CVEs: []string{"CVE-2026-1"}, Severity: engine.High}}
	b := report.New(&engine.Result{Target: "https://b.test", Findings: []engine.Finding{
		vuln, f("https://b.test", "debug", "Debug log <@everyone> **bold**", "/wp-content/debug.log", engine.Medium),
	}}, "test")
	return diff.Compare([]report.Report{before}, []report.Report{a, b})
}

func TestBuild(t *testing.T) {
	m := Build(newFindings(), "/var/reports/last-week.json", engine.Medium, "1.2.3")
	if m.Schema != Schema || m.Since != "last-week.json" || m.MinSeverity != engine.Medium {
		t.Errorf("header: %+v", m)
	}
	if len(m.Findings) != 3 {
		t.Fatalf("want critical, high and medium, got %d: %+v", len(m.Findings), m.Findings)
	}
	if m.Counts[engine.Low] != 0 || m.Counts[engine.Critical] != 1 || len(m.Counts) != 5 {
		t.Errorf("counts: %v", m.Counts)
	}
	if want := "Tuner: 3 new findings (1 critical, 1 high, 1 medium) on 2 sites"; m.Summary != want {
		t.Errorf("summary %q, want %q", m.Summary, want)
	}
	crit := m.Findings[0]
	if crit.Title != ".env with "+matchers.Redact(fixtureSecret)+"�]0;PWNED�" {
		t.Errorf("title not cleaned: %q", crit.Title)
	}
	if crit.Target != "https://a.test" || crit.Location != "https://a.test/.env" {
		t.Errorf("user info kept: %q %q", crit.Target, crit.Location)
	}
	if crit.Fix != "Remove the file.\n�[2Kthen rotate keys" {
		t.Errorf("fix: %q", crit.Fix)
	}
	if got := m.Findings[1].NewAdvisories; len(got) != 1 || got[0] != "CVE-2026-1" {
		t.Errorf("new advisories: %v", got)
	}

	// A first run has no since and says findings, not new findings.
	one := Build(newFindings(), "", engine.Critical, "1.2.3")
	if one.Since != "" || one.Summary != "Tuner: 1 finding (1 critical) on a.test" {
		t.Errorf("first run: %q %q", one.Since, one.Summary)
	}
	if none := Build(diff.Result{}, "x.json", engine.High, ""); none.Summary != "Tuner: no new findings" || len(none.Findings) != 0 {
		t.Errorf("empty: %+v", none)
	}
}

func TestText(t *testing.T) {
	m := Build(newFindings(), "last-week.json", engine.High, "1.2.3")
	want := "Tuner: 2 new findings (1 critical, 1 high) on 2 sites\n" +
		"Compared with last-week.json. Showing high and above.\n" +
		"\nhttps://a.test\n" +
		"[CRITICAL] .env with AKIA•••••�]0;PWNED� - https://a.test/.env\n" +
		"\nhttps://b.test\n" +
		"[HIGH] gallery 1.5: 1 known vulnerability (1 new: CVE-2026-1) - https://b.test/wp-content/plugins/gallery/\n"
	if got := m.Text(func(s string) string { return s }); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	// Long lists end with a count instead of every line.
	var res diff.Result
	for i := range MaxListed + 3 {
		res.New = append(res.New, diff.Entry{Target: "https://a.test", Finding: engine.Finding{ID: "x", Title: fmt.Sprint(i), Severity: engine.High}})
	}
	if got := Build(res, "", engine.High, "").Text(func(s string) string { return s }); !strings.HasSuffix(got, "…and 3 more\n") {
		t.Errorf("no cap:\n%s", got)
	}
}

// listen opens a loopback listener on the ports these tests may use.
func listen(t *testing.T) net.Listener {
	t.Helper()
	for port := 20140; port < 20160; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in 20140-20159")
	return nil
}

// receiver is an https server that records one request body.
func receiver(t *testing.T, status int) (*httptest.Server, chan []byte, chan string) {
	t.Helper()
	bodies, paths := make(chan []byte, 1), make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		paths <- r.URL.Path
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s", r.Method, r.Header.Get("Content-Type"))
		}
		w.WriteHeader(status)
	}))
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, bodies, paths
}

func send(t *testing.T, scheme string, srv *httptest.Server) error {
	t.Helper()
	n, err := Parse(scheme+"://"+srv.Listener.Addr().String()+"/hooks/"+token, Options{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(n.String(), token) || n.String() != scheme+"://"+srv.Listener.Addr().String() {
		t.Errorf("String() = %q", n.String())
	}
	return n.Send(context.Background(), Build(newFindings(), "last-week.json", engine.High, "1.2.3"))
}

// clean checks a payload never carries what a chat channel must not see.
func clean(t *testing.T, body []byte) {
	t.Helper()
	for _, bad := range []string{fixtureSecret, bodyMarker, "\x1b", `\u001b`, "user:pw", "xmlrpc"} {
		if strings.Contains(string(body), bad) {
			t.Errorf("payload holds %q:\n%s", bad, body)
		}
	}
}

func TestSlack(t *testing.T) {
	srv, bodies, paths := receiver(t, http.StatusOK)
	if err := send(t, "slack", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)
	if p := <-paths; p != "/hooks/"+token {
		t.Errorf("path %q", p)
	}
	var got struct {
		Text        string `json:"text"`
		UnfurlLinks *bool  `json:"unfurl_links"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.UnfurlLinks == nil || *got.UnfurlLinks {
		t.Fatalf("%v: %s", err, body)
	}
	if !strings.HasPrefix(got.Text, "Tuner: 2 new findings (1 critical, 1 high) on 2 sites\n") || !strings.Contains(got.Text, "[CRITICAL] .env with AKIA•••••") {
		t.Errorf("text:\n%s", got.Text)
	}
}

func TestSlackEscapesMarkup(t *testing.T) {
	m := Build(newFindings(), "", engine.Medium, "")
	text := slackBody(m).(map[string]any)["text"].(string)
	if !strings.Contains(text, "Debug log &lt;@everyone&gt; **bold**") {
		t.Errorf("slack text:\n%s", text)
	}
	content := discordBody(m).(map[string]any)["content"].(string)
	if !strings.Contains(content, `Debug log \<\@everyone\> \*\*bold\*\* - https://b.test/wp-content/debug.log`) {
		t.Errorf("discord content:\n%s", content)
	}
}

func TestDiscord(t *testing.T) {
	srv, bodies, _ := receiver(t, http.StatusNoContent)
	if err := send(t, "discord", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)
	var got struct {
		Content  string `json:"content"`
		Mentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
		Flags int `json:"flags"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Mentions.Parse == nil || len(got.Mentions.Parse) != 0 || got.Flags != 4 {
		t.Fatalf("%v: %s", err, body)
	}
	if !strings.Contains(got.Content, `\[CRITICAL\] .env with AKIA•••••`) {
		t.Errorf("content:\n%s", got.Content)
	}

	// Discord refuses content over 2000 characters.
	var res diff.Result
	for range 40 {
		res.New = append(res.New, diff.Entry{Target: "https://a.test", Finding: engine.Finding{Title: strings.Repeat("x", 120), Severity: engine.High}})
	}
	if c := discordBody(Build(res, "", engine.High, "")).(map[string]any)["content"].(string); len([]rune(c)) > discordLimit {
		t.Errorf("content is %d characters", len([]rune(c)))
	}
}

func TestWebhookMatchesSchema(t *testing.T) {
	srv, bodies, _ := receiver(t, http.StatusAccepted)
	if err := send(t, "webhook+https", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)

	raw, err := os.ReadFile("../schema/notify-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema   string                     `json:"schema"`
		Findings []map[string]any           `json:"findings"`
		All      map[string]json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &doc.All); err != nil {
		t.Fatal(err)
	}
	fits := func(where string, obj map[string]json.RawMessage, required []string, props map[string]json.RawMessage) {
		for _, k := range required {
			if _, ok := obj[k]; !ok {
				t.Errorf("%s: missing %q", where, k)
			}
		}
		for k := range obj {
			if _, ok := props[k]; !ok {
				t.Errorf("%s: %q is not in schema/notify-v0.json", where, k)
			}
		}
	}
	fits("message", doc.All, schema.Required, schema.Properties)
	if doc.Schema != Schema || len(doc.Findings) != 2 {
		t.Fatalf("payload: %s", body)
	}
	var items []map[string]json.RawMessage
	_ = json.Unmarshal(doc.All["findings"], &items)
	for i, it := range items {
		fits(fmt.Sprintf("findings[%d]", i), it, schema.Defs["Item"].Required, schema.Defs["Item"].Properties)
	}
	if doc.Findings[1]["new_advisories"].([]any)[0] != "CVE-2026-1" {
		t.Errorf("advisories: %v", doc.Findings[1])
	}
}

func TestReceiverErrorsKeepTheURLSecret(t *testing.T) {
	srv, _, _ := receiver(t, http.StatusInternalServerError)
	err := send(t, "slack", srv)
	if err == nil || err.Error() != "receiver answered 500 Internal Server Error" {
		t.Errorf("err = %v", err)
	}

	// A receiver that redirects is an error, not a second POST elsewhere.
	redirect := httptest.NewUnstartedServer(http.RedirectHandler("https://elsewhere.test/", http.StatusFound))
	_ = redirect.Listener.Close()
	redirect.Listener = listen(t)
	redirect.StartTLS()
	defer redirect.Close()
	if err := send(t, "webhook+https", redirect); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect: %v", err)
	}

	// A receiver that is down: net/http's error names the URL, ours doesn't.
	l := listen(t)
	addr := l.Addr().String()
	_ = l.Close()
	n, _ := Parse("discord://"+addr+"/api/webhooks/1/"+token, Options{})
	if err := n.Send(context.Background(), Message{}); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("down: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for raw, want := range map[string]string{
		"hooks.slack.com/services/" + token:                            "not a notification URL",
		"ftp://example.com/" + token:                                   `unsupported notification scheme "ftp"`,
		"slack://hooks.slack.com":                                      "slack://hooks.slack.com: the URL has no path",
		"slack:///services/" + token:                                   "no host",
		"webhook+http://hooks.example.com/" + token:                    "plain http is only for a receiver on this machine",
		"smtp://me:" + token + "@mail.example.com?to=a@b.c&from=t@b.c": "put the SMTP password in TUNER_SMTP_PASSWORD",
		"smtp://me@mail.example.com?to=a@b.c&from=t@b.c":               "set TUNER_SMTP_PASSWORD",
		"smtp://mail.example.com?from=t@b.c":                           "no to= address",
		"smtp://mail.example.com?to=a@b.c":                             "from=",
		"smtp://mail.example.com?to=nobody&from=t@b.c":                 "to=",
		"slack://hooks.slack.com/%zz" + token:                          "not a notification URL",
	} {
		_, err := Parse(raw, Options{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Errorf("%s: error shows the token: %v", raw, err)
		}
	}
	if n, err := Parse("webhook+http://127.0.0.1:20150/hook", Options{}); err != nil || n.String() != "webhook+http://127.0.0.1:20150" {
		t.Errorf("loopback http: %v %v", n, err)
	}
	if got := Redacted("smtp://me@mail.example.com:587?to=a@b.c"); got != "smtp://mail.example.com:587" {
		t.Errorf("Redacted = %q", got)
	}
}

// review: a title word that looks like a URL must not carry a masked link.
func TestDiscordEscapesURLLookalikes(t *testing.T) {
	for in, want := range map[string]string{
		"[HIGH] https://x[click](https://evil.test) - https://a.test/p": `\[HIGH\] https://x%5Bclick%5D%28https://evil.test%29 - https://a.test/p`,
		"see https://a.test/a_b?q=1 **now**":                            `see https://a.test/a_b?q=1 \*\*now\*\*`,
		"https://a.test/<@everyone>":                                    "https://a.test/%3C@everyone%3E",
	} {
		if got := discordEscape(in); got != want {
			t.Errorf("discordEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// review: an incomplete scan says so in every message, even with nothing
// new to list and the field is in the published schema.
func TestIncompleteScan(t *testing.T) {
	res := diff.Result{Incomplete: []string{"Incomplete: blocked by Cloudflare challenge"}}
	m := Build(res, "last-week.json", engine.High, "1.2.3")
	want := "Tuner: no new findings\n" +
		"Compared with last-week.json. Showing high and above.\n" +
		"Incomplete: blocked by Cloudflare challenge\n"
	if got := m.Text(func(s string) string { return s }); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	raw, err := os.ReadFile("../schema/notify-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	_ = json.Unmarshal(raw, &schema)
	body, _ := json.Marshal(m)
	var doc map[string]json.RawMessage
	_ = json.Unmarshal(body, &doc)
	if _, ok := doc["incomplete"]; !ok {
		t.Errorf("no incomplete field: %s", body)
	}
	for k := range doc {
		if _, ok := schema.Properties[k]; !ok {
			t.Errorf("%q is not in schema/notify-v0.json", k)
		}
	}
}

// A cut never leaves half an escape before the ellipsis.
func TestDiscordCutKeepsEscapes(t *testing.T) {
	for in, want := range map[string]string{`aa\`: `aa`, `aa\\`: `aa\\`, `aa\\\`: `aa\\`, `aa`: `aa`, ``: ``} {
		if got := cutEscape(in); got != want {
			t.Errorf("cutEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
