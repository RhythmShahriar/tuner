// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain doubles as a fake Tuner binary: with FAKE_TUNER_ARGV set, the
// test binary records its arguments there and acts like a scan.
func TestMain(m *testing.M) {
	if argv := os.Getenv("FAKE_TUNER_ARGV"); argv != "" {
		os.Exit(fakeTuner(argv, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeTuner appends args as one JSON line to argvFile and writes the
// report named by -o, with the findings in FAKE_TUNER_FINDINGS (a comma
// list of IDs). FAKE_TUNER_SLEEP holds it before exiting with
// FAKE_TUNER_EXIT. The report command prints a stub HTML page.
func fakeTuner(argvFile string, args []string) int {
	f, err := os.OpenFile(argvFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 99
	}
	b, _ := json.Marshal(args)
	f.Write(append(b, '\n'))
	f.Close()
	if d, err := time.ParseDuration(os.Getenv("FAKE_TUNER_SLEEP")); err == nil {
		time.Sleep(d)
	}
	if len(args) > 0 && args[0] == "report" {
		os.Stdout.WriteString("<!doctype html><title>report</title>\n")
		return 0
	}
	if i := slices.Index(args, "-o"); i >= 0 && os.Getenv("FAKE_TUNER_NO_REPORT") == "" {
		var findings []map[string]string
		for id := range strings.SplitSeq(os.Getenv("FAKE_TUNER_FINDINGS"), ",") {
			if id != "" {
				findings = append(findings, map[string]string{"id": id, "severity": "high", "path": "/" + id})
			}
		}
		rep := []map[string]any{{"target": "https://example.com", "findings": findings}}
		b, _ := json.Marshal(rep)
		os.WriteFile(args[i+1], b, 0o600)
	}
	os.Stdout.WriteString("scan output\n")
	code, _ := strconv.Atoi(os.Getenv("FAKE_TUNER_EXIT"))
	return code
}

// fakeClock jumps straight to the end of every sleep and stops the
// watch after a number of sleeps that reached their run.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
	// stopAfter cancels when the clock has slept this many times.
	stopAfter int
	sleeps    int
	cancel    context.CancelFunc
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.sleeps++
	stop := c.stopAfter > 0 && c.sleeps >= c.stopAfter
	c.mu.Unlock()
	if stop {
		c.cancel()
		return ctx.Err()
	}
	return nil
}

func fake(t *testing.T) (w *Watcher, argv string) {
	t.Helper()
	dir := t.TempDir()
	argv = filepath.Join(dir, "argv.jsonl")
	t.Setenv("FAKE_TUNER_ARGV", argv)
	t.Setenv("FAKE_TUNER_EXIT", "0")
	t.Setenv("FAKE_TUNER_FINDINGS", "")
	t.Setenv("FAKE_TUNER_SLEEP", "")
	t.Setenv("FAKE_TUNER_NO_REPORT", "")
	noRaceExitSleep(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Watcher{Exe: exe, List: filepath.Join(dir, "sites.txt"), Dir: filepath.Join(dir, "state")}, argv
}

// noRaceExitSleep stops a -race build of the fake binary from pausing a
// second at exit (the race runtime's atexit_sleep_ms), which every run
// would otherwise wait for.
func noRaceExitSleep(t *testing.T) {
	t.Helper()
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
}

func calls(t *testing.T, argv string) [][]string {
	t.Helper()
	f, err := os.Open(argv)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var a []string
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func TestRunTwoTicksCompareWithFirst(t *testing.T) {
	w, argv := fake(t)
	w.Extra = []string{"--notify", "slack://hooks.example/x", "--fail-on-new", "high", "--profile=quick"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Two runs: the first at once, then a 24h sleep (in minute steps)
	// before the second; the clock stops the watch on the next sleep.
	clock := &fakeClock{now: time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC), cancel: cancel, stopAfter: 24*60 + 1}
	w.Clock = clock
	w.Schedule = Schedule{Every: 24 * time.Hour}
	var log strings.Builder
	w.Log = &log
	t.Setenv("FAKE_TUNER_FINDINGS", "a,b")
	first := true
	// Change the findings between runs: the first run's log line is
	// written before the clock sleeps.
	w.Log = writerFunc(func(p []byte) (int, error) {
		if first && strings.Contains(string(p), "report") {
			first = false
			os.Setenv("FAKE_TUNER_FINDINGS", "b,c,d")
		}
		return log.Write(p)
	})
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	got := calls(t, argv)
	if len(got) != 2 {
		t.Fatalf("%d runs, want 2: %v\n%s", len(got), got, log.String())
	}
	r1 := filepath.Join(w.Dir, "20261024T010000Z.json")
	r2 := filepath.Join(w.Dir, "20261025T010000Z.json")
	want1 := []string{"scan", "-l", w.List, "--json", "-o", r1, "--notify", "slack://hooks.example/x", "--fail-on-new", "high", "--profile=quick"}
	want2 := []string{"scan", "-l", w.List, "--json", "-o", r2, "--since", r1, "--notify", "slack://hooks.example/x", "--fail-on-new", "high", "--profile=quick"}
	if !slices.Equal(got[0], want1) || !slices.Equal(got[1], want2) {
		t.Errorf("argv:\n%q\n%q\nwant:\n%q\n%q", got[0], got[1], want1, want2)
	}
	out := log.String()
	for _, want := range []string{
		"2026-10-24 01:00 UTC: 1 site, 2 findings (2 high); report " + r1,
		"2026-10-25 01:00 UTC: 1 site, 3 findings (3 high); 2 new, 1 fixed since the last run; report " + r2,
		"Next run 2026-10-25 01:00 UTC",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	var st state
	b, _ := os.ReadFile(filepath.Join(w.Dir, StateName))
	if json.Unmarshal(b, &st); st.Report != "20261025T010000Z.json" {
		t.Errorf("last.json: %s", b)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestLockPreventsOverlap(t *testing.T) {
	w, argv := fake(t)
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := Lock(w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunOnce(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: err %v", err)
	}
	if _, err := os.Stat(argv); err == nil {
		t.Error("a scan ran while the lock was held")
	}
	unlock()
	if run, err := w.RunOnce(context.Background()); err != nil || run.Exit != 0 || run.Report == "" {
		t.Fatalf("after unlock: %+v, %v", run, err)
	}

	// Two runs at once from separate goroutines: one gets the lock, the
	// other is turned away.
	t.Setenv("FAKE_TUNER_SLEEP", "300ms")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() { _, errs[i] = w.RunOnce(context.Background()) })
	}
	wg.Wait()
	if n := len(calls(t, argv)); n != 2 || errors.Is(errs[0], ErrLocked) == errors.Is(errs[1], ErrLocked) {
		t.Errorf("%d scans, errors %v", n, errs)
	}
}

func TestRunSkipsLockedTick(t *testing.T) {
	w, argv := fake(t)
	os.MkdirAll(w.Dir, 0o700)
	unlock, err := Lock(w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Clock = &fakeClock{now: time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC), cancel: cancel, stopAfter: 1}
	w.Schedule = Schedule{Every: time.Hour}
	var log strings.Builder
	w.Log = &log
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "skipped: another run of this watch is still going") {
		t.Errorf("log:\n%s", log.String())
	}
	if _, err := os.Stat(argv); err == nil {
		t.Error("scan ran under someone else's lock")
	}
}

func TestStopFinishesCurrentRun(t *testing.T) {
	w, argv := fake(t)
	t.Setenv("FAKE_TUNER_SLEEP", "400ms")
	w.Schedule = Schedule{Every: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitChild(t, w)
		cancel() // SIGTERM during the scan
	}()
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(calls(t, argv)); n != 1 {
		t.Errorf("%d scans", n)
	}
	if _, err := os.Stat(filepath.Join(w.Dir, StateName)); err != nil {
		t.Errorf("finished run not recorded: %v", err)
	}
}

// waitChild returns once w has a scan running, or after 10 seconds.
func waitChild(t *testing.T, w *Watcher) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		started := w.child != nil
		w.mu.Unlock()
		if started {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAbortStopsScan(t *testing.T) {
	w, _ := fake(t)
	t.Setenv("FAKE_TUNER_SLEEP", "10s")
	done := make(chan Run)
	go func() {
		run, _ := w.RunOnce(context.Background())
		done <- run
	}()
	waitChild(t, w)
	w.Abort()
	select {
	case run := <-done:
		if run.Exit == 0 {
			t.Errorf("aborted scan exit %d", run.Exit)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Abort didn't stop the scan")
	}
}

func TestFailedRunKeepsBaseline(t *testing.T) {
	w, argv := fake(t)
	ctx := context.Background()
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	first := calls(t, argv)[0][5]
	// A scan that couldn't reach a site (exit 3) still writes a report,
	// but the next run compares with the last complete one.
	t.Setenv("FAKE_TUNER_EXIT", "3")
	run, err := w.RunOnce(ctx)
	if err != nil || run.Exit != 3 || !strings.Contains(run.Line(), "(scan exit 3)") {
		t.Fatalf("%+v %v", run, err)
	}
	t.Setenv("FAKE_TUNER_EXIT", "0")
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	third := calls(t, argv)[2]
	if i := slices.Index(third, "--since"); i < 0 || third[i+1] != first {
		t.Errorf("third run: %q, want --since %s", third, first)
	}

	t.Setenv("FAKE_TUNER_NO_REPORT", "1")
	t.Setenv("FAKE_TUNER_EXIT", "130")
	run, err = w.RunOnce(ctx)
	if err != nil || run.Report != "" || !strings.Contains(run.Line(), "scan exited 130 without a report; see ") {
		t.Errorf("%+v %v %q", run, err, run.Line())
	}
}

func TestUsageErrorStopsWatch(t *testing.T) {
	w, argv := fake(t)
	t.Setenv("FAKE_TUNER_EXIT", "2")
	w.Schedule = Schedule{Every: time.Hour}
	w.Clock = &fakeClock{now: time.Now(), cancel: func() {}}
	err := w.Run(context.Background())
	if !errors.Is(err, ErrScanUsage) {
		t.Fatalf("err %v", err)
	}
	if n := len(calls(t, argv)); n != 1 {
		t.Errorf("%d scans after a usage error", n)
	}
}

func TestHTMLAndPrune(t *testing.T) {
	w, argv := fake(t)
	w.HTML = true
	w.Keep = 2
	clock := &fakeClock{now: time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)}
	w.Clock = clock
	var last Run
	for range 4 {
		var err error
		if last, err = w.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock.now = clock.now.Add(time.Hour)
	}
	if last.HTML == "" {
		t.Fatalf("no HTML: %+v", last)
	}
	if b, _ := os.ReadFile(last.HTML); !strings.Contains(string(b), "<!doctype html>") {
		t.Errorf("html: %q", b)
	}
	got := calls(t, argv)
	report := got[len(got)-1]
	want := []string{"report", last.Report, "--since", last.Since, "--html"}
	if !slices.Equal(report, want) {
		t.Errorf("report argv %q, want %q", report, want)
	}
	entries, _ := os.ReadDir(w.Dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want = []string{
		"20261024T030000Z.html", "20261024T030000Z.json", "20261024T030000Z.log",
		"20261024T040000Z.html", "20261024T040000Z.json", "20261024T040000Z.log",
		StateName, LockName,
	}
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("state folder %v, want %v", names, want)
	}
}

func TestSameSecondNames(t *testing.T) {
	w, _ := fake(t)
	w.Clock = &fakeClock{now: time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)}
	a, _ := w.RunOnce(context.Background())
	b, _ := w.RunOnce(context.Background())
	if filepath.Base(a.Report) != "20261024T010000Z.json" || filepath.Base(b.Report) != "20261024T010000Z-2.json" {
		t.Errorf("%s, %s", a.Report, b.Report)
	}
}

func TestSchedule(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	at, err := ParseAt("14:30, 02:00,02:00")
	if err != nil || len(at) != 2 || at[0].String() != "02:00" {
		t.Fatalf("%v %v", at, err)
	}
	s := Schedule{At: at}
	for _, c := range []struct{ now, want time.Time }{
		{time.Date(2026, 10, 24, 1, 0, 0, 0, loc), time.Date(2026, 10, 24, 2, 0, 0, 0, loc)},
		{time.Date(2026, 10, 24, 2, 0, 0, 0, loc), time.Date(2026, 10, 24, 14, 30, 0, 0, loc)},
		{time.Date(2026, 10, 24, 23, 0, 0, 0, loc), time.Date(2026, 10, 25, 2, 0, 0, 0, loc)},
	} {
		if got := s.Next(time.Time{}, c.now); !got.Equal(c.want) {
			t.Errorf("Next(%s) = %s, want %s", c.now, got, c.want)
		}
	}
	// An overrun skips missed starts instead of catching up.
	every := Schedule{Every: time.Hour}
	start := time.Date(2026, 10, 24, 1, 0, 0, 0, loc)
	if got := every.Next(start, start.Add(150*time.Minute)); !got.Equal(start.Add(3 * time.Hour)) {
		t.Errorf("overrun next %s", got)
	}
	for _, bad := range []string{"2am", "24:00", "02:60", "2:5", ""} {
		if _, err := ParseAt(bad); err == nil {
			t.Errorf("ParseAt(%q) accepted", bad)
		}
	}
	for _, c := range []struct {
		s    Schedule
		want string
	}{
		{Schedule{}, "pick a schedule"},
		{Schedule{Every: time.Hour, At: at}, "pick one of --every and --at"},
		{Schedule{Every: time.Second}, "too often"},
	} {
		if err := c.s.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.s, err)
		}
	}
}

func TestDigestIgnoresSitesNotScanned(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	cur := filepath.Join(dir, "new.json")
	os.WriteFile(old, []byte(`[{"target":"a","findings":[{"id":"x","severity":"low"}]},{"target":"b","findings":[{"id":"y","severity":"low"}]}]`), 0o600)
	os.WriteFile(cur, []byte(`{"target":"a","findings":[{"id":"x","severity":"low"},{"id":"vuln-plugin-z","severity":"critical","advisories":[{"id":"W-1"}]}]}`), 0o600)
	d, err := digest(cur, old)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.String(); got != "1 site, 2 findings (1 critical, 1 low); 1 new, 0 fixed since the last run" {
		t.Errorf("digest %q", got)
	}
	if _, err := digest(filepath.Join(dir, "missing.json"), ""); err == nil {
		t.Error("missing report read")
	}
	os.WriteFile(cur, []byte("not json"), 0o600)
	if _, err := digest(cur, ""); err == nil || !strings.Contains(err.Error(), "not a Tuner JSON report") {
		t.Errorf("bad report: %v", err)
	}
}
