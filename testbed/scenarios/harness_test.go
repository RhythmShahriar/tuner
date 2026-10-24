// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// scenario is one expect.yaml.
type scenario struct {
	// QA lists the gaps in the QA review's "Test coverage gaps" this covers.
	QA    []int  `yaml:"qa"`
	Title string `yaml:"title"`
	// Xfail names the roadmap item (e.g. E1) whose fix this scenario
	// waits for. Until it merges a failing scenario is skipped as an
	// expected failure; one that passes is reported as XPASS so the xfail
	// can be cleared.
	Xfail string `yaml:"xfail"`
	// SkipOn lists GOOS values the scenario can't run on, e.g. FIFOs on
	// windows.
	SkipOn  []string     `yaml:"skip_on"`
	Servers []serverSpec `yaml:"servers"`
	// Data adjusts the fake data services every scan points at.
	Data  serverSpec `yaml:"data"`
	Tree  []treeOp   `yaml:"tree"`
	Steps []step     `yaml:"steps"`
}

// step is one run of rhythm-tuner.
type step struct {
	Name      string            `yaml:"name"`
	DataState string            `yaml:"data_state"` // switch the data services first
	Tree      []treeOp          `yaml:"tree"`       // change the work folder first
	Args      []string          `yaml:"args"`
	Env       map[string]string `yaml:"env"`
	Stdin     string            `yaml:"stdin"`
	// Signals are sent this long after the start, in order.
	Signals []signalAt `yaml:"signals"`
	// Timeout kills the run; default 60s. A killed run fails the step.
	Timeout duration    `yaml:"timeout"`
	Expect  expectation `yaml:"expect"`
}

type signalAt struct {
	After  duration `yaml:"after"`
	Signal string   `yaml:"signal"` // INT, TERM or KILL
}

type expectation struct {
	// Exit is the exit code, or a list of allowed ones; -1 means killed by
	// a signal.
	Exit    any                  `yaml:"exit"`
	MaxTime duration             `yaml:"max_time"`
	Stdout  textCheck            `yaml:"stdout"`
	Stderr  textCheck            `yaml:"stderr"`
	Output  textCheck            `yaml:"output"` // stdout and stderr together
	Files   map[string]fileCheck `yaml:"files"`  // paths in the work folder
	// Requests checks what each named server saw during the step. The
	// data server is "data".
	Requests map[string]reqCheck `yaml:"requests"`
}

type textCheck struct {
	Contains    []string `yaml:"contains"`
	NotContains []string `yaml:"not_contains"`
	Matches     []string `yaml:"matches"` // Go regular expressions
	NotMatches  []string `yaml:"not_matches"`
}

type fileCheck struct {
	Exists    *bool `yaml:"exists"`
	MinSize   int   `yaml:"min_size"`
	textCheck `yaml:",inline"`
	// JSON compares values at dotted paths: "score", "findings.0.id",
	// "findings.#" (a length). A list path such as "[].target" checks
	// every element of a top-level array.
	JSON map[string]any `yaml:"json"`
	// FindingIDs and NoFindingIDs look across every report in the file.
	FindingIDs   []string `yaml:"finding_ids"`
	NoFindingIDs []string `yaml:"no_finding_ids"`
}

type reqCheck struct {
	Min      *int     `yaml:"min"`
	Max      *int     `yaml:"max"`
	Paths    []string `yaml:"paths"`     // each was requested
	NotPaths []string `yaml:"not_paths"` // none was requested
	Hosts    []string `yaml:"hosts"`     // every request's Host is one of these
	// NoHeaders lists request headers that must never have been sent,
	// e.g. Authorization after a redirect.
	NoHeaders []string `yaml:"no_headers"`
	Protos    []string `yaml:"protos"` // every request used one of these, e.g. HTTP/2.0
	// PathMax caps how often each path was requested.
	PathMax map[string]int `yaml:"path_max"`
}

var (
	bin      string
	ports    *portPool
	quietLog = log.New(io.Discard, "", 0)

	resultsMu sync.Mutex
	results   []result
)

// result is one scenario's outcome for the summary.
type result struct {
	name, status, xfail, detail string
}

func record(r result) {
	resultsMu.Lock()
	results = append(results, r)
	resultsMu.Unlock()
}

func TestMain(m *testing.M) {
	flag.Parse()
	var err error
	if ports, err = portsFromEnv(); err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		os.Exit(2)
	}
	dir, err := os.MkdirTemp("", "tuner-scenarios-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		os.Exit(2)
	}
	switch {
	case os.Getenv("TUNER_SCENARIO_BIN") != "": // test a release build instead
		bin = os.Getenv("TUNER_SCENARIO_BIN")
	case !testing.Short():
		bin, err = build(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scenarios: building rhythm-tuner:", err)
			_ = os.RemoveAll(dir)
			os.Exit(2)
		}
	}
	code := m.Run()
	writeSummary()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// build compiles this checkout's rhythm-tuner into dir.
func build(dir string) (string, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // fallback when go isn't on PATH
	}
	out := filepath.Join(dir, "rhythm-tuner")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command(goBin, "build", "-o", out, "./cmd/rhythm-tuner")
	cmd.Dir = filepath.Join("..", "..")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w\n%s", err, b)
	}
	return out, nil
}

// statSources stats every source file the binary is built from. go test
// caches a passing run until the files the test touched change, and the
// build happens in a child process it can't see; stat'ing the sources
// makes an edit anywhere in Tuner rerun the suite. It has to run inside a
// test: go test only records file access once TestMain calls m.Run.
func statSources(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == ".git" || d.Name() == "testbed" || d.Name() == "bin" || d.Name() == "dist"):
			return filepath.SkipDir
		case d.IsDir():
			return nil
		}
		switch filepath.Ext(p) {
		case ".go", ".yaml", ".json", ".mod", ".sum":
			_, err = os.Stat(p)
		}
		return err
	})
}

func TestScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("scenarios run rhythm-tuner end to end; skipped with -short")
	}
	if os.Getenv("TUNER_SCENARIO_BIN") == "" {
		if err := statSources(filepath.Join("..", "..")); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join("*", "expect.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scenarios found (%v)", err)
	}
	sort.Strings(files)
	for _, f := range files {
		name := filepath.Dir(f)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc, err := load(f)
			if err != nil {
				t.Fatal(err)
			}
			runScenario(t, name, sc)
		})
	}
}

func load(path string) (*scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var sc scenario
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sc.Title == "" || len(sc.Steps) == 0 {
		return nil, fmt.Errorf("%s: needs a title and at least one step", path)
	}
	for _, s := range sc.Servers {
		if s.Name == "" || s.Name == "data" {
			return nil, fmt.Errorf("%s: every server needs a name other than data", path)
		}
	}
	return &sc, nil
}

func runScenario(t *testing.T, name string, sc *scenario) {
	if slices.Contains(sc.SkipOn, runtime.GOOS) {
		record(result{name: name, status: "skip", xfail: sc.Xfail, detail: "not on " + runtime.GOOS})
		t.Skipf("not on %s", runtime.GOOS)
	}
	dir, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}

	// Listeners first, so every server's URL is known before any handler
	// or argument is filled in.
	data := sc.Data
	data.Name, data.Kind = "data", "data"
	if data.State == "" {
		data.State = "v1"
	}
	specs := append([]serverSpec{data}, sc.Servers...)
	lns, err := ports.listen(hostsOf(specs))
	var he *hostError
	if errors.As(err, &he) {
		record(result{name: name, status: "skip", xfail: sc.Xfail, detail: he.Error()})
		t.Skip(he)
	}
	if err != nil {
		t.Fatal(err)
	}
	servers := map[string]*server{}
	for i, spec := range specs {
		servers[spec.Name] = &server{spec: spec, ln: lns[i], url: urlOf(spec, lns[i]), closed: make(chan struct{})}
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	home := filepath.Join(root, "home")
	for _, d := range []string{work, home, filepath.Join(home, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	expand := expander(servers, work, home)

	for _, s := range servers {
		if err := s.start(dir, expand); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.stop)
	}
	tr := &treeRunner{dir: dir, work: work, expand: expand}
	t.Cleanup(tr.close)
	if err := tr.apply(sc.Tree); err != nil {
		t.Fatal(err)
	}

	var problems []string
	for i, st := range sc.Steps {
		label := st.Name
		if label == "" {
			label = "step " + strconv.Itoa(i+1)
		}
		if err := tr.apply(st.Tree); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if st.DataState != "" {
			servers["data"].setState(st.DataState)
		}
		run := execStep(t, st, work, home, servers["data"].url, expand)
		t.Logf("%s: %s\nexit %d in %s\n--- stdout\n%s\n--- stderr\n%s", label, strings.Join(run.args, " "), run.exit, run.took.Round(time.Millisecond), run.stdout, run.stderr)
		for _, p := range check(st.Expect, run, servers, work, expand) {
			problems = append(problems, label+": "+p)
		}
	}

	switch {
	case len(problems) == 0 && sc.Xfail != "":
		record(result{name: name, status: "XPASS", xfail: sc.Xfail, detail: "passes now; remove xfail: " + sc.Xfail})
		t.Logf("XPASS: passes now; remove xfail: %s from %s/expect.yaml", sc.Xfail, name)
	case len(problems) == 0:
		record(result{name: name, status: "pass"})
	case sc.Xfail != "":
		record(result{name: name, status: "xfail", xfail: sc.Xfail, detail: problems[0]})
		t.Skipf("xfail %s (expected until it merges):\n  %s", sc.Xfail, strings.Join(problems, "\n  "))
	default:
		record(result{name: name, status: "FAIL", detail: problems[0]})
		t.Errorf("%s:\n  %s", sc.Title, strings.Join(problems, "\n  "))
	}
}

// expander fills in {{url:name}}, {{host:name}}, {{port:name}}, {{work}}
// (the run's folder), {{home}} (its home folder) and {{cache}} (where
// rhythm-tuner caches on this OS) and {{x:N}} (N x's, for long lines).
func expander(servers map[string]*server, work, home string) func(string) string {
	var pairs []string
	for name, s := range servers {
		addr := s.ln.Addr().String()
		_, port, _ := strings.Cut(addr[strings.LastIndex(addr, ":"):], ":")
		pairs = append(pairs,
			"{{url:"+name+"}}", s.url,
			"{{host:"+name+"}}", addr,
			"{{port:"+name+"}}", port)
	}
	pairs = append(pairs, "{{work}}", work, "{{home}}", home, "{{cache}}", cacheDir(home), "{{sep}}", string(filepath.Separator))
	r := strings.NewReplacer(pairs...)
	return func(s string) string {
		s = r.Replace(s)
		return repeatX.ReplaceAllStringFunc(s, func(m string) string {
			n, _ := strconv.Atoi(repeatX.FindStringSubmatch(m)[1])
			return strings.Repeat("x", n)
		})
	}
}

var repeatX = regexp.MustCompile(`\{\{x:(\d{1,7})\}\}`)

// runResult is what one rhythm-tuner run did.
type runResult struct {
	args           []string
	exit           int
	took           time.Duration
	stdout, stderr string
	timedOut       bool
}

// cacheDir is os.UserCacheDir()/rhythm under the environment environ sets.
func cacheDir(home string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Local", "rhythm")
	case "darwin", "ios":
		return filepath.Join(home, "Library", "Caches", "rhythm")
	}
	return filepath.Join(home, ".cache", "rhythm")
}

func execStep(t *testing.T, st step, work, home, data string, expand func(string) string) runResult {
	t.Helper()
	args := make([]string, len(st.Args))
	for i, a := range st.Args {
		args[i] = expand(a)
	}
	cmd := exec.Command(bin, args...) //nolint:gosec // the binary this suite built, with the scenario's arguments
	cmd.Dir = work
	cmd.Env = environ(home, data)
	for k, v := range st.Env {
		cmd.Env = append(cmd.Env, k+"="+expand(v))
	}
	cmd.Stdin = strings.NewReader(expand(st.Stdin))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	timeout := time.Duration(st.Timeout)
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for _, s := range st.Signals {
			select {
			case <-time.After(time.Until(start.Add(time.Duration(s.After)))):
				if err := sendSignal(cmd.Process, s.Signal); err != nil {
					t.Errorf("signal %s: %v", s.Signal, err)
				}
			case <-done:
				return
			}
		}
	}()
	timer := time.AfterFunc(timeout, func() { _ = cmd.Process.Kill() })
	err := cmd.Wait()
	close(done)
	timedOut := !timer.Stop()
	took := time.Since(start)

	exit := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		exit = ee.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return runResult{args: args, exit: exit, took: took, stdout: stdout.String(), stderr: stderr.String(), timedOut: timedOut}
}

// environ isolates a run: its own home, cache and config folders, every
// data service on the loopback fake, and a proxy on the same fake for
// anything else, so a request that would leave the machine lands there
// instead (Go never proxies loopback addresses).
func environ(home, data string) []string {
	drop := []string{"HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NO_COLOR", "TERM"}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		u := strings.ToUpper(k)
		if slices.Contains(drop, u) || strings.HasPrefix(u, "XDG_") || strings.HasPrefix(u, "TUNER_") || strings.HasPrefix(u, "RHYTHM_") {
			continue
		}
		if u == "PATH" && runtime.GOOS != "windows" {
			continue // no php or other tools from the machine
		}
		env = append(env, kv)
	}
	env = append(env,
		"HOME="+home, "USERPROFILE="+home,
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"XDG_STATE_HOME="+filepath.Join(home, ".local", "state"),
		"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"NO_COLOR=1", "TERM=dumb",
		"TUNER_VULN_API="+data, "TUNER_WPORG_API="+data, "TUNER_PHPNET_API="+data,
		"TUNER_OSV_API="+data, "TUNER_CHECKS_URL="+data+"/checks-latest", "RHYTHM_GITHUB_API="+data,
		"HTTP_PROXY="+data, "HTTPS_PROXY="+data,
	)
	if runtime.GOOS != "windows" {
		env = append(env, "PATH="+filepath.Join(home, "bin"))
	}
	return env
}

func check(e expectation, run runResult, servers map[string]*server, work string, expand func(string) string) []string {
	var out []string
	if run.timedOut {
		out = append(out, fmt.Sprintf("still running after the step timeout; killed after %s", run.took.Round(time.Millisecond)))
	}
	if want := exits(e.Exit); len(want) > 0 && !slices.Contains(want, run.exit) {
		out = append(out, fmt.Sprintf("exit %d, want %v", run.exit, e.Exit))
	}
	if e.MaxTime > 0 && run.took > time.Duration(e.MaxTime) {
		out = append(out, fmt.Sprintf("took %s, want at most %s", run.took.Round(time.Millisecond), time.Duration(e.MaxTime)))
	}
	out = append(out, e.Stdout.check("stdout", run.stdout, expand)...)
	out = append(out, e.Stderr.check("stderr", run.stderr, expand)...)
	out = append(out, e.Output.check("output", run.stdout+run.stderr, expand)...)

	for path, fc := range e.Files {
		out = append(out, fc.check(filepath.Join(work, filepath.FromSlash(expand(path))), path, expand)...)
	}

	hits := map[string][]hit{}
	for name, s := range servers {
		hits[name] = s.requests()
	}
	// Anything addressed to another host reached the data server through
	// the proxy variables: the run tried to leave the machine.
	dataHost := servers["data"].ln.Addr().String()
	for _, h := range hits["data"] {
		if h.Host != dataHost {
			out = append(out, fmt.Sprintf("tried to leave the machine: %s %s (host %s)", h.Method, h.Path, h.Host))
		}
	}
	names := make([]string, 0, len(e.Requests))
	for n := range e.Requests {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := servers[name]; !ok {
			out = append(out, fmt.Sprintf("requests: no server named %q", name))
			continue
		}
		out = append(out, e.Requests[name].check(name, hits[name], expand)...)
	}
	return out
}

func exits(v any) []int {
	switch x := v.(type) {
	case nil:
		return nil
	case int:
		return []int{x}
	case []any:
		var out []int
		for _, e := range x {
			if n, ok := e.(int); ok {
				out = append(out, n)
			}
		}
		return out
	}
	return []int{-999} // a typo never passes
}

func (c textCheck) check(what, text string, expand func(string) string) []string {
	var out []string
	for _, s := range c.Contains {
		if s = expand(s); !strings.Contains(text, s) {
			out = append(out, fmt.Sprintf("%s lacks %q", what, s))
		}
	}
	for _, s := range c.NotContains {
		if s = expand(s); strings.Contains(text, s) {
			out = append(out, fmt.Sprintf("%s has %q", what, s))
		}
	}
	for _, s := range c.Matches {
		if re, err := regexp.Compile(expand(s)); err != nil {
			out = append(out, fmt.Sprintf("%s: bad regexp %q: %v", what, s, err))
		} else if !re.MatchString(text) {
			out = append(out, fmt.Sprintf("%s doesn't match %s", what, s))
		}
	}
	for _, s := range c.NotMatches {
		if re, err := regexp.Compile(expand(s)); err != nil {
			out = append(out, fmt.Sprintf("%s: bad regexp %q: %v", what, s, err))
		} else if m := re.FindString(text); m != "" {
			out = append(out, fmt.Sprintf("%s matches %s (%q)", what, s, m))
		}
	}
	return out
}

func (c fileCheck) check(path, label string, expand func(string) string) []string {
	b, err := os.ReadFile(path) //nolint:gosec // a file in the scenario's work folder
	if c.Exists != nil && !*c.Exists {
		if err == nil {
			return []string{label + " exists, want none"}
		}
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", label, err)}
	}
	var out []string
	if len(b) < c.MinSize {
		out = append(out, fmt.Sprintf("%s has %d bytes, want at least %d", label, len(b), c.MinSize))
	}
	out = append(out, c.textCheck.check(label, string(b), expand)...)
	if len(c.JSON) == 0 && len(c.FindingIDs) == 0 && len(c.NoFindingIDs) == 0 {
		return out
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return append(out, fmt.Sprintf("%s is not JSON: %v", label, err))
	}
	keys := make([]string, 0, len(c.JSON))
	for k := range c.JSON {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, ok := lookup(doc, k)
		if !ok {
			out = append(out, fmt.Sprintf("%s: no %s", label, k))
		} else if want := expandAny(c.JSON[k], expand); !sameJSON(got, want) {
			out = append(out, fmt.Sprintf("%s: %s is %v, want %v", label, k, got, want))
		}
	}
	ids := findingIDs(doc)
	for _, id := range c.FindingIDs {
		if !slices.Contains(ids, id) {
			out = append(out, fmt.Sprintf("%s has no %s finding (has %v)", label, id, ids))
		}
	}
	for _, id := range c.NoFindingIDs {
		if slices.Contains(ids, id) {
			out = append(out, fmt.Sprintf("%s has a %s finding", label, id))
		}
	}
	return out
}

// lookup walks a dotted path through decoded JSON. "#" is a length.
func lookup(v any, path string) (any, bool) {
	for _, part := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			if part == "#" {
				v = float64(len(x))
				continue
			}
			var ok bool
			if v, ok = x[part]; !ok {
				return nil, false
			}
		case []any:
			if part == "#" {
				v = float64(len(x))
				continue
			}
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// expandAny fills in placeholders in every string of a YAML value.
func expandAny(v any, expand func(string) string) any {
	switch x := v.(type) {
	case string:
		return expand(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = expandAny(e, expand)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = expandAny(e, expand)
		}
		return out
	}
	return v
}

// sameJSON compares a decoded JSON value with one from YAML.
func sameJSON(got, want any) bool {
	wb, err := json.Marshal(want)
	if err != nil {
		return false
	}
	var w any
	if json.Unmarshal(wb, &w) != nil {
		return false
	}
	return reflect.DeepEqual(got, w)
}

// findingIDs collects finding IDs from a report object or array.
func findingIDs(doc any) []string {
	var reports []any
	switch x := doc.(type) {
	case []any:
		reports = x
	default:
		reports = []any{x}
	}
	var ids []string
	for _, r := range reports {
		fs, _ := lookup(r, "findings")
		list, _ := fs.([]any)
		for _, f := range list {
			if id, ok := lookup(f, "id"); ok {
				ids = append(ids, fmt.Sprint(id))
			}
		}
	}
	return ids
}

func (c reqCheck) check(name string, hits []hit, expand func(string) string) []string {
	var out []string
	if c.Min != nil && len(hits) < *c.Min {
		out = append(out, fmt.Sprintf("%s got %d requests, want at least %d", name, len(hits), *c.Min))
	}
	if c.Max != nil && len(hits) > *c.Max {
		out = append(out, fmt.Sprintf("%s got %d requests, want at most %d (first: %s)", name, len(hits), *c.Max, hits[0].Path))
	}
	path := func(h hit) string { p, _, _ := strings.Cut(h.Path, "?"); return p }
	for _, p := range c.Paths {
		if !slices.ContainsFunc(hits, func(h hit) bool { return path(h) == p }) {
			out = append(out, fmt.Sprintf("%s never got %s", name, p))
		}
	}
	for _, p := range c.NotPaths {
		if slices.ContainsFunc(hits, func(h hit) bool { return path(h) == p }) {
			out = append(out, fmt.Sprintf("%s got %s", name, p))
		}
	}
	if len(c.Hosts) > 0 {
		var want []string
		for _, h := range c.Hosts {
			want = append(want, expand(h))
		}
		for _, h := range hostsSeen(hits) {
			if !slices.Contains(want, h) {
				out = append(out, fmt.Sprintf("%s got requests for host %s, want only %v", name, h, want))
			}
		}
	}
	for _, hdr := range c.NoHeaders {
		for _, h := range hits {
			if h.Header.Get(hdr) != "" {
				out = append(out, fmt.Sprintf("%s got %s on %s", name, hdr, h.Path))
				break
			}
		}
	}
	for p, most := range c.PathMax {
		if n := len(slices.DeleteFunc(slices.Clone(hits), func(h hit) bool { return path(h) != p })); n > most {
			out = append(out, fmt.Sprintf("%s got %s %d times, want at most %d", name, p, n, most))
		}
	}
	if len(c.Protos) > 0 {
		for _, h := range hits {
			if !slices.Contains(c.Protos, h.Proto) {
				out = append(out, fmt.Sprintf("%s got %s over %s, want %v", name, h.Path, h.Proto, c.Protos))
				break
			}
		}
	}
	return out
}

// writeSummary writes a Markdown table of every scenario to the file in
// TUNER_SCENARIO_SUMMARY, e.g. $GITHUB_STEP_SUMMARY in CI.
func writeSummary() {
	path := os.Getenv("TUNER_SCENARIO_SUMMARY")
	if path == "" || len(results) == 0 {
		return
	}
	sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })
	var b strings.Builder
	counts := map[string]int{}
	for _, r := range results {
		counts[r.status]++
	}
	fmt.Fprintf(&b, "### Tuner scenarios\n\n%d pass, %d xfail, %d XPASS, %d FAIL, %d skipped\n\n",
		counts["pass"], counts["xfail"], counts["XPASS"], counts["FAIL"], counts["skip"])
	b.WriteString("| Scenario | Result | Waits for | Detail |\n|---|---|---|---|\n")
	for _, r := range results {
		d := strings.NewReplacer("|", "\\|", "\n", " ").Replace(r.detail)
		if len(d) > 160 {
			d = d[:160] + "..."
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.name, r.status, r.xfail, d)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // the summary file CI names
	if err != nil {
		fmt.Fprintln(os.Stderr, "scenarios: summary:", err)
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(b.String())
}
