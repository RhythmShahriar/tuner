// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/notify"
	"github.com/RhythmShahriar/tuner/report"
)

// planned parses scan flags into a fresh extension and runs its Plan.
func planned(t *testing.T, args ...string) (*reportExtension, error) {
	t.Helper()
	return notifyPlanned(t, nil, args...)
}

func thisWeek() []report.Report {
	return []report.Report{report.New(&engine.Result{Target: "https://a.test", Findings: []engine.Finding{
		finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High),
	}}, "test")}
}

func TestReportExtensionSince(t *testing.T) {
	old, _ := diffFixtures(t)
	e, err := planned(t, "--since", old)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	code, err := e.Finished(&scanPlan{}, thisWeek(), &errs)
	if err != nil || code != exitOK {
		t.Fatalf("exit %d, %v", code, err)
	}
	want := "1 new, 1 fixed since " + old + "\n" +
		"  new: [HIGH] leak-git-config - https://a.test/.git/config\n" +
		"  fixed: [CRITICAL] leak-dotenv - https://a.test/.env\n"
	if errs.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", errs.String(), want)
	}

	// -q keeps only the summary line.
	errs.Reset()
	p := &scanPlan{}
	p.o.quiet = true
	if _, err := e.Finished(p, thisWeek(), &errs); err != nil || errs.String() != "1 new, 1 fixed since "+old+"\n" {
		t.Errorf("quiet: %q, %v", errs.String(), err)
	}
}

func TestReportExtensionFailOnNew(t *testing.T) {
	old, _ := diffFixtures(t)
	for level, want := range map[string]int{"high": exitFindings, "low": exitFindings, "critical": exitOK} {
		e, err := planned(t, "--since", old, "--fail-on-new", level)
		if err != nil {
			t.Fatal(err)
		}
		if code, err := e.Finished(&scanPlan{}, thisWeek(), io.Discard); err != nil || code != want {
			t.Errorf("--fail-on-new %s: exit %d, want %d (%v)", level, code, want, err)
		}
	}
	// Nothing new: a finding that was already there doesn't fail the build.
	cur := saveReport(t, "same.json", finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High))
	e, err := planned(t, "--since", cur, "--fail-on-new", "info")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := e.Finished(&scanPlan{}, thisWeek(), io.Discard); code != exitOK {
		t.Errorf("nothing new: exit %d", code)
	}
}

func TestReportExtensionPlanErrors(t *testing.T) {
	var ue usageError
	if _, err := planned(t, "--fail-on-new", "high"); !errors.As(err, &ue) || !strings.Contains(err.Error(), "needs --since") {
		t.Errorf("--fail-on-new alone: %v", err)
	}
	if _, err := planned(t, "--since", "x.json", "--fail-on-new", "severe"); !errors.As(err, &ue) {
		t.Errorf("bad level: %v", err)
	}
	if _, err := planned(t, "--since", "/nonexistent/last-week.json"); err == nil || errors.As(err, &ue) {
		t.Errorf("missing file should be a plain error (exit 3): %v", err)
	}
	e, err := planned(t)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	if code, err := e.Finished(&scanPlan{}, thisWeek(), &errs); code != exitOK || err != nil || errs.Len() != 0 {
		t.Errorf("without --since: exit %d, %v, %q", code, err, errs.String())
	}
	if !strings.Contains(e.Help(), "--since <file>") || !strings.Contains(e.Help(), "--fail-on-new <level>") {
		t.Errorf("help:\n%s", e.Help())
	}
}

// hookReceiver is a local https webhook that answers status and hands
// each body it gets to the test.
func hookReceiver(t *testing.T, status int) (*httptest.Server, chan []byte) {
	t.Helper()
	bodies := make(chan []byte, 4)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(status)
	}))
	_ = srv.Listener.Close()
	for port := 20140; port < 20160; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			srv.Listener = l
			break
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, bodies
}

// notifyPlanned is planned with the notifiers pointed at srv.
func notifyPlanned(t *testing.T, srv *httptest.Server, args ...string) (*reportExtension, error) {
	t.Helper()
	e := &reportExtension{}
	if srv != nil {
		e.notifyOptions.HTTPClient = srv.Client()
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	e.Flags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return e, e.Plan(&scanPlan{})
}

func hookURL(srv *httptest.Server) string {
	return "webhook+https://" + srv.Listener.Addr().String() + "/hook/SECRETTOKEN"
}

func TestReportExtensionNotify(t *testing.T) {
	old, _ := diffFixtures(t)
	srv, bodies := hookReceiver(t, http.StatusOK)
	e, err := notifyPlanned(t, srv, "--since", old, "--notify", hookURL(srv))
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	if code, err := e.Finished(&scanPlan{}, thisWeek(), &errs); code != exitOK || err != nil {
		t.Fatalf("exit %d, %v", code, err)
	}
	var msg notify.Message
	if err := json.Unmarshal(<-bodies, &msg); err != nil {
		t.Fatal(err)
	}
	// Only the new high: xmlrpc was there before and is low anyway.
	if len(msg.Findings) != 1 || msg.Findings[0].ID != "leak-git-config" || msg.Since != "last-week.json" || msg.MinSeverity != engine.High {
		t.Errorf("message: %+v", msg)
	}
	want := "notified webhook+https://" + srv.Listener.Addr().String() + ": 1 finding\n"
	if !strings.HasSuffix(errs.String(), want) || strings.Contains(errs.String(), "SECRETTOKEN") {
		t.Errorf("stderr:\n%s", errs.String())
	}

	// Nothing new at the level: no request at all.
	e, _ = notifyPlanned(t, srv, "--since", old, "--notify", hookURL(srv), "--notify-min", "critical")
	errs.Reset()
	if code, _ := e.Finished(&scanPlan{}, thisWeek(), &errs); code != exitOK || !strings.Contains(errs.String(), "nothing new at critical or above, so no notification\n") {
		t.Errorf("exit %d:\n%s", code, errs.String())
	}
	select {
	case b := <-bodies:
		t.Errorf("sent %s", b)
	default:
	}
}

func TestReportExtensionNotifyFirstRun(t *testing.T) {
	srv, bodies := hookReceiver(t, http.StatusOK)
	missing := filepath.Join(t.TempDir(), "previous.json")
	for _, args := range [][]string{
		{"--since", missing, "--notify-all-first", "--notify-min", "low", "--notify", hookURL(srv)},
		{"--notify-all-first", "--notify-min", "low", "--notify", hookURL(srv)},
	} {
		e, err := notifyPlanned(t, srv, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var errs bytes.Buffer
		if code, _ := e.Finished(&scanPlan{}, thisWeek(), &errs); code != exitOK || !strings.HasPrefix(errs.String(), "no previous report; sending all findings\n") {
			t.Errorf("%v: exit %d:\n%s", args, code, errs.String())
		}
		var msg notify.Message
		if err := json.Unmarshal(<-bodies, &msg); err != nil || len(msg.Findings) != 2 || msg.Since != "" {
			t.Errorf("%v: %v %+v", args, err, msg)
		}
	}
	// -q drops the first-run line, and --fail-on-new doesn't fail a first
	// run: with nothing to compare, every finding would count as new.
	e, err := notifyPlanned(t, srv, "--since", missing, "--notify-all-first", "--fail-on-new", "low", "--notify", hookURL(srv))
	if err != nil {
		t.Fatal(err)
	}
	p := &scanPlan{}
	p.o.quiet = true
	var errs bytes.Buffer
	if code, _ := e.Finished(p, thisWeek(), &errs); code != exitOK || errs.String() != "" {
		t.Errorf("quiet first run: exit %d:\n%s", code, errs.String())
	}
	<-bodies

	// Without --notify-all-first a missing report is still an error (exit 3).
	var ue usageError
	if _, err := notifyPlanned(t, srv, "--since", missing, "--notify", hookURL(srv)); err == nil || errors.As(err, &ue) {
		t.Errorf("missing --since file: %v", err)
	}
}

func TestReportExtensionNotifyFailure(t *testing.T) {
	old, _ := diffFixtures(t)
	srv, _ := hookReceiver(t, http.StatusInternalServerError)
	for strict, want := range map[bool]int{false: exitOK, true: exitError} {
		args := []string{"--since", old, "--notify", hookURL(srv)}
		if strict {
			args = append(args, "--notify-strict")
		}
		e, err := notifyPlanned(t, srv, args...)
		if err != nil {
			t.Fatal(err)
		}
		var errs bytes.Buffer
		code, err := e.Finished(&scanPlan{}, thisWeek(), &errs)
		warn := "rhythm tuner: warning: could not notify webhook+https://" + srv.Listener.Addr().String() + ": receiver answered 500 Internal Server Error\n"
		if err != nil || code != want || !strings.HasSuffix(errs.String(), warn) || strings.Contains(errs.String(), "SECRETTOKEN") {
			t.Errorf("strict=%v: exit %d (%v):\n%s", strict, code, err, errs.String())
		}
	}
}

func TestReportExtensionNotifyPlanErrors(t *testing.T) {
	old, _ := diffFixtures(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--notify", "slack://hooks.slack.com/services/SECRETTOKEN"}, "--notify needs --since <file>"},
		{[]string{"--since", old, "--notify-min", "high"}, "--notify-min needs --notify <url>"},
		{[]string{"--since", old, "--notify-all-first"}, "--notify-all-first needs --notify <url>"},
		{[]string{"--since", old, "--notify-strict"}, "--notify-strict needs --notify <url>"},
		{[]string{"--since", old, "--notify", "slack://x.test/a", "--notify-min", "loud"}, `--notify-min "loud"`},
		{[]string{"--since", old, "--notify", "ftp://x.test/SECRETTOKEN"}, `--notify: unsupported notification scheme "ftp"`},
		{[]string{"--since", old, "--notify", "webhook+http://x.test/SECRETTOKEN"}, "--notify: webhook+http://x.test: plain http"},
	} {
		var ue usageError
		_, err := notifyPlanned(t, nil, c.args...)
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	t.Setenv("TUNER_SMTP_PASSWORD", "")
	if _, err := notifyPlanned(t, nil, "--since", old, "--notify", "smtp://me@mail.test?to=a@b.test&from=t@b.test"); err == nil || !strings.Contains(err.Error(), "TUNER_SMTP_PASSWORD") {
		t.Errorf("smtp without password: %v", err)
	}
	t.Setenv("TUNER_SMTP_PASSWORD", "hunter2")
	if _, err := notifyPlanned(t, nil, "--since", old, "--notify", "smtp://me@mail.test?to=a@b.test&from=t@b.test"); err != nil {
		t.Errorf("smtp with password: %v", err)
	}
}

// review: a scan that stopped early says so next to the diff, even with
// -q, and lists what it didn't reach as not seen rather than fixed.
func TestReportExtensionIncompleteScan(t *testing.T) {
	old, _ := diffFixtures(t)
	e, err := planned(t, "--since", old)
	if err != nil {
		t.Fatal(err)
	}
	now := thisWeek()
	now[0].SetStatus(report.Status{StoppedBy: "max-time"})
	var errs bytes.Buffer
	if code, err := e.Finished(&scanPlan{}, now, &errs); err != nil || code != exitOK {
		t.Fatalf("exit %d, %v", code, err)
	}
	want := "1 new, 0 fixed since " + old + "; 1 not seen (scan incomplete)\n" +
		"  Incomplete: stopped by --max-time\n" +
		"  new: [HIGH] leak-git-config - https://a.test/.git/config\n" +
		"  not seen: [CRITICAL] leak-dotenv - https://a.test/.env\n"
	if errs.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", errs.String(), want)
	}
	errs.Reset()
	p := &scanPlan{}
	p.o.quiet = true
	if _, _ = e.Finished(p, now, &errs); !strings.Contains(errs.String(), "Incomplete: stopped by --max-time") {
		t.Errorf("quiet dropped the note:\n%s", errs.String())
	}
}

// A blocked scan with nothing new still notifies, so a schedule doesn't
// go quiet while the firewall keeps it out.
func TestReportExtensionNotifyIncomplete(t *testing.T) {
	srv, bodies := hookReceiver(t, http.StatusOK)
	cur := saveReport(t, "same.json", finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High))
	e, err := notifyPlanned(t, srv, "--since", cur, "--notify", hookURL(srv))
	if err != nil {
		t.Fatal(err)
	}
	now := thisWeek()
	now[0].SetStatus(report.Status{StoppedBy: "waf", BlockedBy: "sucuri"})
	if code, err := e.Finished(&scanPlan{}, now, io.Discard); err != nil || code != exitOK {
		t.Fatalf("exit %d, %v", code, err)
	}
	var msg notify.Message
	if err := json.Unmarshal(<-bodies, &msg); err != nil || len(msg.Findings) != 0 ||
		len(msg.Incomplete) != 1 || msg.Incomplete[0] != "Incomplete: blocked by Sucuri challenge" {
		t.Errorf("%v: %+v", err, msg)
	}
}
