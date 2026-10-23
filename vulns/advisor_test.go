package vulns

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// Responses shaped like the real APIs, including their inconsistencies:
// unfixed as "0" vs 0, kev as false vs an object, severity as a letter.
var api = map[string]string{
	"/plugin/contact-form-7/": `{"error":0,"message":null,"data":{"name":"Contact Form 7","plugin":"contact-form-7","closed":0,"vulnerability":[
		{"uuid":"u1","name":"Contact Form 7 [contact-form-7] < 5.3.2","operator":{"min_version":null,"min_operator":null,"max_version":"5.3.2","max_operator":"lt","unfixed":"0","closed":"0"},
		 "source":[{"id":"CVE-2020-35489","name":"CVE-2020-35489","link":"https://www.cve.org/CVERecord?id=CVE-2020-35489","description":"[en] Unrestricted file upload.","date":"2020-12-17"},
		           {"id":"wf1","name":"Contact Form 7 &lt;= 5.3.1 - Arbitrary File Upload","link":"https://www.wordfence.com/x","description":"…","date":"2020-12-17"}],
		 "impact":{"cvss3":{"score":"10.0","severity":"critical","vector":"CVSS:3.1/AV:N"},"kev":{"date_added":"2021-01-01"}}},
		{"uuid":"u2","name":"Contact Form 7 < 5.0.4","operator":{"max_version":"5.0.4","max_operator":"lt","unfixed":"0"},
		 "source":[{"id":"CVE-2018-20979","name":"CVE-2018-20979","link":"https://www.cve.org/x"}],"impact":{"cvss":{"score":"7.5","severity":"h"}}}
	]}}`,
	"/plugin/old-gallery/":     `{"error":0,"data":{"name":"Old Gallery","closed":1,"closed_reason":"security-issue","closed_date":"2024-02-01","vulnerability":[]}}`,
	"/plugin/no-version/":      `{"error":0,"data":{"name":"X","closed":0,"vulnerability":[{"uuid":"u3","name":"X < 2.0","operator":{"max_version":"2.0","max_operator":"lt","unfixed":"0"},"source":[],"impact":{}}]}}`,
	"/plugin/akismet/":         `{"error":0,"data":{"name":"Akismet","closed":0,"vulnerability":[]}}`,
	"/core/6.4.1/":             `{"error":0,"data":{"core":"6.4.1","vulnerability":[{"uuid":"c1","name":"6.4.1","source":[{"id":"CVE-2024-31211","name":"CVE-2024-31211","link":"https://cve.org/y","description":"[en] RCE via deserialization."}],"impact":{"cvss3":{"score":"9.8","severity":"critical"},"kev":false}}]}}`,
	"/php/7.4.3/":              `{"error":0,"data":{"php":"7.4.3","name":"PHP 7.4","status":"d","date_start":"2019-11-28","date_end":"2022-11-28","vulnerability":[{"uuid":"p1","name":"PHP < 7.4.33","operator":{"max_version":"7.4.33","max_operator":"lt","unfixed":0},"source":[{"id":"CVE-2022-31630","name":"CVE-2022-31630","link":"https://cve.org/p"}],"impact":{"cvss3":{"score":"7.1","severity":"high"},"kev":false}}]}}`,
	"/nginx/1.25.3/":           `{"error":0,"data":{"nginx":"1.25.3","name":"nginx 1.25","date_end":"2099-01-01","vulnerability":[]}}`,
	"/plugins/info/1.2/":       ``, // routed by slug below
	"/core/version-check/1.7/": `{"offers":[{"response":"upgrade","current":"7.1.3"}]}`,
}

var wporg = map[string]string{
	"contact-form-7": `{"slug":"contact-form-7","version":"6.2.3","last_updated":"2026-10-21 8:43am GMT"}`,
	"akismet":        `{"slug":"akismet","version":"5.5","last_updated":"2021-01-10 1:00pm GMT"}`,
	"old-gallery":    `{"error":"closed"}`,
}

type fakeAPI struct {
	*httptest.Server
	hits   atomic.Int32
	down   atomic.Bool
	mu     sync.Mutex
	paths  []string          // every path requested
	routes map[string]string // per-test responses, checked first
}

// requested reports whether any request's path starts with prefix.
func (f *fakeAPI) requested(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.paths, func(p string) bool { return strings.HasPrefix(p, prefix) })
}

// newFakeAPI fakes WPVulnerability, api.wordpress.org and php.net. Paths
// not in api or routes fall back to the real responses in testdata: PHP
// branch records (/php/8.4.0/) and php.net's release states.
func newFakeAPI(t *testing.T, routes ...map[string]string) *fakeAPI {
	f := &fakeAPI{routes: map[string]string{}}
	for _, r := range routes {
		maps.Copy(f.routes, r)
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		if f.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if body, ok := f.routes[r.URL.Path]; ok {
			w.Write([]byte(body))
			return
		}
		if r.URL.Path == "/releases/states.php" {
			http.ServeFile(w, r, "testdata/phpnet-states.json")
			return
		}
		if _, ok := api[r.URL.Path]; !ok && strings.HasPrefix(r.URL.Path, "/php/") {
			if body, err := gunzip("testdata/php_" + strings.Trim(strings.TrimPrefix(r.URL.Path, "/php/"), "/") + ".json.gz"); err == nil {
				w.Write(body)
				return
			}
		}
		if r.URL.Path == "/plugins/info/1.2/" || r.URL.Path == "/themes/info/1.2/" {
			body, ok := wporg[r.URL.Query().Get("slug")]
			if !ok {
				body = `{"error":"Plugin not found."}`
			}
			w.Write([]byte(body))
			return
		}
		body, ok := api[r.URL.Path]
		if !ok {
			body = `{"error":0,"data":{"vulnerability":[]}}`
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(f.Close)
	return f
}

func newAdvisor(f *fakeAPI, cache string) *Advisor {
	c := &Client{HTTP: f.Client(), CacheDir: cache, VulnBase: f.URL, WPOrgBase: f.URL, PHPNetBase: f.URL, UserAgent: "test", Pace: -1}
	return &Advisor{Client: c, Now: func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }}
}

var base, _ = url.Parse("https://example.com")

func byID(fs []engine.Finding) map[string]engine.Finding {
	m := map[string]engine.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestAdvise(t *testing.T) {
	f := newFakeAPI(t)
	a := newAdvisor(f, t.TempDir())
	fp := fingerprint.Result{
		Tech:      []string{"wordpress", "php"},
		WordPress: "6.4.1",
		PHP:       "7.4.3", PHPBuild: "7.4.3-4ubuntu2.19", PHPSource: "x-powered-by /wp-login.php",
		Server: "nginx/1.25.3",
		Components: []fingerprint.Component{
			{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"},
			{Type: "plugin", Slug: "old-gallery", Version: "1.0"},
			{Type: "plugin", Slug: "no-version"},
			{Type: "plugin", Slug: "akismet", Version: "5.0"},
		},
	}
	findings, warnings := a.Advise(context.Background(), base, fp)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	got := byID(findings)

	cf7, ok := got["vuln-plugin-contact-form-7"]
	if !ok {
		t.Fatalf("no contact-form-7 finding; got %v", keys(got))
	}
	if cf7.Severity != engine.Critical || len(cf7.Advisories) != 1 {
		t.Errorf("cf7: severity %s, %d advisories (5.0.4 bound must not match 5.3.1)", cf7.Severity, len(cf7.Advisories))
	}
	ad := cf7.Advisories[0]
	if !ad.KEV || ad.FixedIn != "5.3.2" || ad.Title != "Contact Form 7 <= 5.3.1 - Arbitrary File Upload" || ad.CVEs[0] != "CVE-2020-35489" {
		t.Errorf("advisory = %+v", ad)
	}
	if !strings.Contains(cf7.Fix, "5.3.2 or later (latest is 6.2.3)") || !strings.Contains(cf7.Impact, "Known Exploited") {
		t.Errorf("cf7 fix %q / impact %q", cf7.Fix, cf7.Impact)
	}
	if cf7.URL != "https://example.com/wp-content/plugins/contact-form-7/" || cf7.Source == "" {
		t.Errorf("cf7 URL %q source %q", cf7.URL, cf7.Source)
	}

	if core := got["vuln-core"]; core.Severity != engine.Critical || !strings.Contains(core.Fix, "7.1.3") {
		t.Errorf("core = %+v", core)
	}
	if c := got["wp-plugin-closed"]; !strings.Contains(strings.Join(c.Evidence.Matched, " "), "security-issue") {
		t.Errorf("closed = %+v", c)
	}
	if u := got["wp-components-unverified"]; u.Severity != engine.Info || u.Confidence != "low" {
		t.Errorf("unverified = %+v", u)
	}
	if o := got["wp-components-outdated"]; !strings.Contains(strings.Join(o.Evidence.Matched, ""), "akismet 5.0 → 5.5") {
		t.Errorf("outdated = %+v", o)
	}
	if ab := got["wp-components-abandoned"]; !strings.Contains(strings.Join(ab.Evidence.Matched, ""), "akismet") {
		t.Errorf("abandoned = %+v", ab)
	}
	php := got["vuln-php"]
	if php.Confidence != "low" || !strings.Contains(php.Impact, "backported") || !strings.Contains(php.Caveat, "distro build") {
		t.Errorf("php on an Ubuntu build should be low confidence: %+v", php)
	}
	if ev := php.Evidence.Matched; ev[len(ev)-1] != "version from x-powered-by /wp-login.php" {
		t.Errorf("php evidence doesn't say where the version came from: %v", ev)
	}
	if eol := got["php-eol"]; eol.Severity != engine.High || !strings.Contains(eol.Impact, "never fixed") {
		t.Errorf("php-eol for PHP 7.4 = %+v", eol)
	}
	if _, ok := got["php-version-hidden"]; ok {
		t.Error("php-version-hidden with a known PHP version")
	}
	if _, ok := got["nginx-eol"]; ok {
		t.Error("nginx 1.25 is supported until 2099 in the fixture")
	}
}

func TestCacheAutoUpdate(t *testing.T) {
	f := newFakeAPI(t)
	cache := t.TempDir()
	fp := fingerprint.Result{Tech: []string{"wordpress"}, Components: []fingerprint.Component{{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"}}}
	ctx := context.Background()

	newAdvisor(f, cache).Advise(ctx, base, fp)
	first := f.hits.Load()
	if first == 0 {
		t.Fatal("nothing fetched")
	}

	// Fresh cache: no network.
	newAdvisor(f, cache).Advise(ctx, base, fp)
	if f.hits.Load() != first {
		t.Errorf("fresh cache refetched: %d → %d hits", first, f.hits.Load())
	}

	// Expired cache refetches automatically.
	age(t, cache, 25*time.Hour)
	newAdvisor(f, cache).Advise(ctx, base, fp)
	if f.hits.Load() == first {
		t.Error("expired cache was not refreshed")
	}

	// Expired cache and the API down: fall back to stale data, with a warning.
	age(t, cache, 25*time.Hour)
	f.down.Store(true)
	fs, warnings := newAdvisor(f, cache).Advise(ctx, base, fp)
	if _, ok := byID(fs)["vuln-plugin-contact-form-7"]; !ok || len(warnings) != 1 || !strings.Contains(warnings[0], "older than") {
		t.Errorf("stale fallback: findings %v, warnings %v", keys(byID(fs)), warnings)
	}

	// Offline with nothing cached: a clear warning, no fetch.
	f.down.Store(false)
	hits := f.hits.Load()
	a := newAdvisor(f, t.TempDir())
	a.Client.Offline = true
	_, warnings = a.Advise(ctx, base, fp)
	if f.hits.Load() != hits || len(warnings) == 0 || !strings.Contains(warnings[0], "not cached") {
		t.Errorf("offline: %d new hits, warnings %v", f.hits.Load()-hits, warnings)
	}

	// Refresh re-fetches everything cached, ignoring the TTL.
	ok, failed, err := newAdvisor(f, cache).Client.Refresh(ctx)
	if err != nil || ok < 2 || failed != 0 {
		t.Errorf("Refresh: ok %d failed %d err %v", ok, failed, err)
	}
}

// age backdates every cache entry.
func age(t *testing.T, dir string, by time.Duration) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, _ := os.ReadFile(p)
		var e cacheEntry[map[string]any]
		if err := jsonUnmarshal(data, &e); err != nil {
			t.Fatal(err)
		}
		e.Fetched = e.Fetched.Add(-by)
		return writeJSON(p, e)
	})
}

func keys(m map[string]engine.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
