// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

func scanWithStatus(t *testing.T, root string, opts Options) (*engine.Result, status) {
	t.Helper()
	if opts.Exec == nil {
		opts.Exec = fakePHP("8.3.6", nil)
	}
	res, st, err := scanStatus(context.Background(), root, opts, engine.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return res, st
}

func hasWarning(res *engine.Result, sub string) bool {
	return slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, sub) })
}

func TestSessionEntryCap(t *testing.T) {
	files := map[string]string{}
	for i := range 50 {
		files[fmt.Sprintf("lib/f%02d.php", i)] = "<?php echo 1;"
	}
	res, st := scanWithStatus(t, tree(t, files), Options{MaxEntries: 10})
	if !hasWarning(res, "stopped after 10 entries; the session check may be incomplete") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if st.complete || st.stoppedBy != "budget" {
		t.Errorf("status %+v", st)
	}

	// Negative: a tree under the cap is complete.
	res, st = scanWithStatus(t, tree(t, map[string]string{"index.php": "<?php"}), Options{MaxEntries: 10})
	if !st.complete || st.stoppedBy != "" || hasWarning(res, "stopped") {
		t.Errorf("status %+v, warnings %q", st, res.Warnings)
	}
}

func TestSessionSkipsDependencies(t *testing.T) {
	for _, dir := range []string{"vendor/acme/lib", "node_modules/pkg"} {
		res := scanTree(t, tree(t, map[string]string{"index.php": "<?php", dir + "/s.php": switchPlugin}), Options{Exec: fakeSessionPHP("8.3.6", unsafeCLI("1"))})
		if f := find(res, sessionCheckID); f != nil {
			t.Errorf("%s visited: %q", dir, f.Title)
		}
	}
	// Positive: the same file in the app is found.
	res := scanTree(t, tree(t, map[string]string{"lib/s.php": switchPlugin}), Options{Exec: fakeSessionPHP("8.3.6", unsafeCLI("1"))})
	if find(res, sessionCheckID) == nil {
		t.Errorf("app code not checked: %v", ids(res))
	}
}

func TestSessionUnreadableFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := tree(t, map[string]string{"index.php": "<?php", "private/a.php": "<?php"})
	locked := filepath.Join(root, "private")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) }) //nolint:gosec // restore so TempDir can clean up
	res := scanTree(t, root, Options{})
	if !hasWarning(res, "the session check couldn't read 1 entry, so it may be incomplete (first: /private: permission denied)") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

// statusFunc is an advisor that reports a fixed vulnData status.
type statusFunc string

func (s statusFunc) Advise(context.Context, *url.URL, fingerprint.Result) ([]engine.Finding, []string) {
	panic("AdviseStatus should be used")
}

func (s statusFunc) AdviseStatus(context.Context, *url.URL, fingerprint.Result) ([]engine.Finding, []string, string) {
	var warnings []string
	if s != vulnOK {
		warnings = []string{"vulnerability data unavailable"}
	}
	return nil, warnings, string(s)
}

// warnAdvisor is an advisor without a status that warns.
type warnAdvisor []string

func (w warnAdvisor) Advise(context.Context, *url.URL, fingerprint.Result) ([]engine.Finding, []string) {
	return nil, w
}

func TestVulnData(t *testing.T) {
	root := tree(t, map[string]string{"index.php": "<?php"})
	lock := tree(t, map[string]string{"index.php": "<?php", "composer.lock": `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.1"}]}`})
	offline := func() *OSV { return &OSV{CacheDir: t.TempDir(), Offline: true} }
	cases := []struct {
		name string
		root string
		opts Options
		want string
	}{
		{"no vulnerability matching", root, Options{}, vulnOff},
		{"advisor reports missing", root, Options{Advisor: statusFunc(vulnMissing)}, vulnMissing},
		{"advisor reports ok", root, Options{Advisor: statusFunc(vulnOK)}, vulnOK},
		{"advisor reports off", root, Options{Advisor: statusFunc(vulnOff)}, vulnOff},
		{"plain advisor, quiet", root, Options{Advisor: warnAdvisor(nil)}, vulnOK},
		{"plain advisor that warns", root, Options{Advisor: warnAdvisor{"couldn't fetch vulnerability data"}}, vulnPartial},
		{"OSV not cached offline", lock, Options{OSV: offline()}, vulnPartial},
		{"OSV with nothing to look up", root, Options{OSV: offline(), Advisor: statusFunc(vulnOK)}, vulnOK},
		{"advisor ok, OSV not cached", lock, Options{OSV: offline(), Advisor: statusFunc(vulnOK)}, vulnPartial},
		{"advisor missing, OSV not cached", lock, Options{OSV: offline(), Advisor: statusFunc(vulnMissing)}, vulnPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, st := scanWithStatus(t, c.root, c.opts)
			if st.vulnData != c.want {
				t.Errorf("vuln_data %q, want %q", st.vulnData, c.want)
			}
		})
	}

	// A canceled scan never asked the advisor, so its data is missing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, st, _ := scanStatus(ctx, root, Options{Exec: noPHP, Advisor: statusFunc(vulnOK)}, engine.Hooks{})
	if st.vulnData != vulnMissing {
		t.Errorf("canceled: vuln_data %q", st.vulnData)
	}
}

func TestThousands(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 250000: "250,000", 1234567: "1,234,567", -4500: "-4,500"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, want %q", n, got, want)
		}
	}
}
