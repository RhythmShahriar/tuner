package local

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// osvRecords are shaped like api.osv.dev's /v1/vulns answers.
var osvRecords = map[string]string{
	"GHSA-aaaa": `{"id":"GHSA-aaaa","summary":"Query binding exploitation ","aliases":["CVE-2021-21263"],
		"affected":[{"package":{"ecosystem":"Packagist","name":"laravel/framework"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.20.11"},{"introduced":"7.0.0"},{"fixed":"7.30.2"},{"introduced":"8.0.0"},{"fixed":"8.22.1"}]}]}],
		"database_specific":{"severity":"HIGH"},
		"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-21263"},{"type":"PACKAGE","url":"https://github.com/laravel/framework"}]}`,
	"GHSA-bbbb": `{"id":"GHSA-bbbb","summary":"Cookie issue","affected":[{"package":{"ecosystem":"Packagist","name":"laravel/framework"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"v8.40.0"}]}]}],
		"database_specific":{"severity":"MODERATE"}}`,
	"GHSA-cccc": `{"id":"GHSA-cccc","summary":"Unfixed","affected":[{"package":{"ecosystem":"Packagist","name":"acme/abandoned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
}

type fakeOSV struct {
	*httptest.Server
	hits atomic.Int32
	down atomic.Bool
}

func newFakeOSV(t *testing.T) *fakeOSV {
	f := &fakeOSV{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string }
					Version string
				}
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var results []string
			for _, q := range req.Queries {
				switch {
				case q.Package.Ecosystem != "Packagist":
					results = append(results, `{}`)
				case q.Package.Name == "laravel/framework" && q.Version == "8.0.0":
					results = append(results, `{"vulns":[{"id":"GHSA-aaaa","modified":"2024-01-01T00:00:00Z"},{"id":"GHSA-bbbb"}]}`)
				case q.Package.Name == "acme/abandoned":
					results = append(results, `{"vulns":[{"id":"GHSA-cccc"}]}`)
				default:
					results = append(results, `{}`)
				}
			}
			w.Write([]byte(`{"results":[` + strings.Join(results, ",") + `]}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			body, ok := osvRecords[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

const lockFile = `{
	"packages": [
		{"name": "laravel/framework", "version": "v8.0.0"},
		{"name": "monolog/monolog", "version": "2.9.1"},
		{"name": "acme/abandoned", "version": "1.0.0"},
		{"name": "acme/branch", "version": "dev-main"}
	],
	"packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.0"}]
}`

func TestComposer(t *testing.T) {
	api := newFakeOSV(t)
	cache := t.TempDir()
	root := tree(t, map[string]string{"composer.lock": lockFile, "index.php": "<?php"})
	osv := func(offline bool) *OSV {
		return &OSV{HTTP: api.Client(), Base: api.URL, CacheDir: cache, Offline: offline, UserAgent: "test"}
	}

	res := scanTree(t, root, Options{OSV: osv(false)})
	if got := ids(res); !slices.Equal(got, []string{"vuln-composer-laravel-framework /composer.lock", "vuln-composer-acme-abandoned /composer.lock"}) {
		t.Fatalf("findings %v, warnings %v", got, res.Warnings)
	}
	f := find(res, "vuln-composer-laravel-framework")
	if f.Severity != engine.High || f.Title != "laravel/framework 8.0.0: 2 known vulnerabilities" || f.Source != OSVSource ||
		len(f.Advisories) != 2 || f.Advisories[0].ID != "GHSA-aaaa" || f.Advisories[0].FixedIn != "8.22.1" ||
		!slices.Equal(f.Advisories[0].CVEs, []string{"CVE-2021-21263"}) || f.Advisories[0].Title != "Query binding exploitation" ||
		!slices.Contains(f.Tags, "laravel") || !strings.Contains(f.Fix, "8.40.0 or later") {
		t.Errorf("laravel finding: %+v", f)
	}
	if f := find(res, "vuln-composer-acme-abandoned"); f.Severity != engine.Medium || !strings.Contains(f.Fix, "No fixed version") {
		t.Errorf("unfixed finding: %+v", f)
	}
	if !res.Fingerprint.Has("laravel") {
		t.Error("laravel/framework in composer.lock should mark the site Laravel")
	}

	// Cached: offline with the API down gives the same answer, with no requests.
	api.down.Store(true)
	hits := api.hits.Load()
	res = scanTree(t, root, Options{OSV: osv(true)})
	if len(res.Findings) != 2 || len(res.Warnings) != 0 || api.hits.Load() != hits {
		t.Errorf("offline: %v %v, %d requests", ids(res), res.Warnings, api.hits.Load()-hits)
	}

	// Nothing cached and the API down: a warning, not an error.
	res = scanTree(t, root, Options{OSV: &OSV{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}})
	if len(res.Findings) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "4 Composer packages") {
		t.Errorf("down: %v %v", ids(res), res.Warnings)
	}
	res = scanTree(t, root, Options{OSV: &OSV{CacheDir: t.TempDir(), Offline: true}})
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "run once online") {
		t.Errorf("offline, uncached: %v", res.Warnings)
	}
}

func TestLockPackages(t *testing.T) {
	pkgs, err := lockPackages([]byte(lockFile))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{"laravel/framework", "8.0.0"}, {"monolog/monolog", "2.9.1"}, {"acme/abandoned", "1.0.0"}, {"phpunit/phpunit", "9.6.0"}}
	if !slices.Equal(pkgs, want) {
		t.Errorf("got %v", pkgs)
	}
	if _, err := lockPackages([]byte("not json")); err == nil {
		t.Error("bad lock file parsed")
	}
	root := tree(t, map[string]string{"composer.lock": "{broken"})
	if res := scanTree(t, root, Options{}); len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "composer.lock") {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func TestParseEnv(t *testing.T) {
	env := parseEnv([]byte("# c\nexport APP_DEBUG=true # on\nAPP_NAME=\"My App\"\nEMPTY=\nBAD LINE\n"))
	if env["APP_DEBUG"] != "true" || env["APP_NAME"] != "My App" || env["EMPTY"] != "" || len(env) != 3 {
		t.Errorf("%q", env)
	}
}
