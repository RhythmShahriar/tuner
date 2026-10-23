package vulns

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// The fake serves real captures from 2026-10-23: php.net's release states
// (8.2 to 8.5 supported) and WPVulnerability's PHP 8.1 to 8.5 records,
// which include the PHP2Shell fixes of 2026-10-21.

func TestPHPBranches(t *testing.T) {
	f := newFakeAPI(t)
	cache := t.TempDir()
	c := newAdvisor(f, cache).Client
	all, stale, err := c.PHPBranches(context.Background())
	if err != nil || stale {
		t.Fatalf("err %v stale %v", err, stale)
	}
	var versions []string
	for _, b := range all {
		versions = append(versions, b.Version)
	}
	if want := []string{"3.0", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"}; !slices.Equal(versions, want) {
		t.Errorf("branches %v, want %v", versions, want)
	}
	if b := all[0]; b.State != "" || b.SecurityEnd != "2000-10-20" {
		t.Errorf("null state: %+v", b)
	}

	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	sup, _, err := c.supportedBranches(context.Background(), now)
	if err != nil || len(sup) != 4 || sup[0].Version != "8.2" {
		t.Errorf("supported %+v, err %v", sup, err)
	}
	// php.net's state lags; the support end date wins.
	if (Branch{Version: "8.2", State: "security", SecurityEnd: "2026-12-31"}).Supported(time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Error("8.2 supported after its end date")
	}

	// Cached on disk, so a refresh picks it up.
	if _, err := os.Stat(filepath.Join(cache, "php.net", "releases", "states.json")); err != nil {
		t.Error(err)
	}
	ok, failed, err := c.Refresh(context.Background())
	if err != nil || ok != 1 || failed != 0 {
		t.Errorf("Refresh: ok %d failed %d err %v", ok, failed, err)
	}
}

func TestPHPVersionHidden(t *testing.T) {
	f := newFakeAPI(t)
	a := newAdvisor(f, t.TempDir())
	fp := fingerprint.Result{Tech: []string{"wordpress", "php"}, Server: "cloudflare"}
	findings, warnings := a.Advise(context.Background(), base, fp)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	h, ok := byID(findings)["php-version-hidden"]
	if !ok {
		t.Fatalf("no php-version-hidden finding; got %v", keys(byID(findings)))
	}
	// Eight critical advisories in the last 180 days; the newest, PHP2Shell, first.
	if h.Title != "PHP version hidden: can't rule out CVE-2026-109618 (critical) and 7 more" {
		t.Errorf("title %q", h.Title)
	}
	if h.Severity != engine.Medium || h.Confidence != "low" || len(h.Advisories) != 8 || h.Source == "" {
		t.Errorf("severity %s confidence %s, %d advisories", h.Severity, h.Confidence, len(h.Advisories))
	}
	ev := h.Evidence.Matched
	if len(ev) != 6 || !strings.HasPrefix(ev[0], "CVE-2026-109618 ") || !strings.HasSuffix(ev[0], " — fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35") ||
		ev[5] != "…and 3 more" {
		t.Errorf("evidence:\n%s", strings.Join(ev, "\n"))
	}
	// Only listed for the branches it affects.
	i := slices.IndexFunc(h.Advisories, func(ad engine.Advisory) bool { return slices.Contains(ad.CVEs, "CVE-2026-17544") })
	if i < 0 || h.Advisories[i].FixedIn != "8.5.9, 8.4.24" {
		t.Errorf("CVE-2026-17544: %+v", h.Advisories)
	}
	for _, ad := range h.Advisories {
		if ad.Severity != engine.Critical || strings.HasPrefix(ad.Title, "PHP 8.") {
			t.Errorf("advisory %+v", ad)
		}
	}
	if !strings.Contains(h.Fix, "php -v") || !strings.Contains(h.Fix, "older than 8.5.12, 8.4.27, 8.3.36, 8.2.35") ||
		!strings.Contains(h.Fix, "older than 8.2 are end of life") {
		t.Errorf("fix %q", h.Fix)
	}
}

func TestPHPVersionHiddenQuiet(t *testing.T) {
	// A year on, nothing is recent: no finding, and no warning either.
	f := newFakeAPI(t)
	a := newAdvisor(f, t.TempDir())
	a.Now = func() time.Time { return time.Date(2027, 10, 23, 0, 0, 0, 0, time.UTC) }
	findings, warnings := a.Advise(context.Background(), base, fingerprint.Result{Tech: []string{"php"}})
	if len(findings) != 0 || len(warnings) != 0 {
		t.Errorf("findings %v, warnings %v", keys(byID(findings)), warnings)
	}

	// Not a PHP site: php.net isn't even asked.
	f = newFakeAPI(t)
	findings, _ = newAdvisor(f, t.TempDir()).Advise(context.Background(), base, fingerprint.Result{Server: "nginx"})
	if len(findings) != 0 || f.requested("/releases/") || f.requested("/php/") {
		t.Errorf("static site: findings %v, requests %v", keys(byID(findings)), f.paths)
	}

	// php.net down: a warning, not a silent pass.
	f = newFakeAPI(t, map[string]string{"/releases/states.php": "<html>maintenance</html>"})
	findings, warnings = newAdvisor(f, t.TempDir()).Advise(context.Background(), base, fingerprint.Result{Tech: []string{"php"}})
	if len(findings) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "recent PHP advisories") {
		t.Errorf("php.net down: findings %v, warnings %v", keys(byID(findings)), warnings)
	}
}

func TestPHPEndOfLife(t *testing.T) {
	f := newFakeAPI(t)
	a := newAdvisor(f, t.TempDir())
	fp := fingerprint.Result{Tech: []string{"wordpress", "php"}, PHP: "8.1.2", PHPSource: "x-powered-by /wp-login.php"}
	findings, warnings := a.Advise(context.Background(), base, fp)
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	got := byID(findings)
	if _, ok := got["php-version-hidden"]; ok {
		t.Error("php-version-hidden with a known version")
	}

	eol := got["php-eol"]
	if eol.Severity != engine.High || !strings.Contains(eol.Impact, "never fixed") || !strings.Contains(eol.Impact, "13 flaws disclosed since support ended") ||
		!strings.Contains(eol.Fix, "8.2 or later") {
		t.Errorf("php-eol = %+v", eol)
	}

	php := got["vuln-php"]
	byCVE := map[string]engine.Advisory{}
	for _, ad := range php.Advisories {
		for _, c := range ad.CVEs {
			if _, dup := byCVE[c]; dup {
				t.Errorf("%s listed twice", c)
			}
			byCVE[c] = ad
		}
	}
	// Disclosed after 8.1's end of life (2025-12-31): inferred from 8.2, unfixed.
	if ad, ok := byCVE["CVE-2026-109618"]; !ok || ad.FixedIn != "" || ad.Severity != engine.Critical {
		t.Errorf("CVE-2026-109618 = %+v", ad)
	}
	// 8.2-only flaws from before 8.1's end of life aren't inferred.
	if _, ok := byCVE["CVE-2024-8932"]; ok && byCVE["CVE-2024-8932"].FixedIn == "" {
		t.Error("CVE-2024-8932 inferred, but it predates 8.1's end of life")
	}
	// 8.1's own advisories keep their fixed version.
	if ad := byCVE["CVE-2025-14177"]; ad.FixedIn != "8.1.34" {
		t.Errorf("CVE-2025-14177 = %+v", ad)
	}
	ev := strings.Join(php.Evidence.Matched, "\n")
	if !strings.Contains(ev, "(no fix for this branch)") || !strings.Contains(ev, "version from x-powered-by /wp-login.php") {
		t.Errorf("evidence:\n%s", ev)
	}
	if php.Severity != engine.Critical || php.Confidence != "high" || !strings.Contains(php.Fix, "supported PHP branch (8.2 or later)") ||
		!strings.Contains(php.Impact, "never be fixed") {
		t.Errorf("vuln-php: %s %s\nfix %s\nimpact %s", php.Severity, php.Confidence, php.Fix, php.Impact)
	}
}

// Fixtures reproduce the API's quirks: "impact": [] for unscored advisories,
// unfixed as 0 or "0", and null bounds.
func TestNewerPHPFlaws(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"/php/7.4.33/": `{"error":0,"data":{"php":"7.4","name":"PHP 7.4","date_end":"2022-11-28","vulnerability":[
			{"uuid":"own","name":"PHP 7.4 < 7.4.33","operator":{"min_version":null,"max_version":"7.4.33","max_operator":"lt","unfixed":0},
			 "source":[{"id":"CVE-2022-0001","link":"https://cve.org/1","description":"[en] Own flaw.","date":"2022-10-01"}],"impact":[]}]}}`,
		"/php/8.2.0/": `{"error":0,"data":{"php":"8.2","name":"PHP 8.2","date_end":"2026-12-31","vulnerability":[
			{"uuid":"a","name":"PHP 8.2 < 8.2.20","operator":{"min_version":null,"min_operator":null,"max_version":"8.2.20","max_operator":"lt","unfixed":"0"},
			 "source":[{"id":"CVE-2024-0002","link":"https://cve.org/2","description":"[en] In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, the parser overflows.","date":"2024-06-01"}],
			 "impact":{"cvss3":{"score":"9.8","severity":"c"},"kev":{"date_added":"2024-07-01"}}},
			{"uuid":"b","name":"PHP 8.2 < 8.2.20","operator":{"min_version":"8.2.0","min_operator":"ge","max_version":"8.2.20","max_operator":"lt","unfixed":0},
			 "source":[{"id":"CVE-2024-0003","link":"https://cve.org/3","description":"[en] Only 8.2.","date":"2024-06-01"}],"impact":[]},
			{"uuid":"c","name":"PHP 8.2 < 8.2.5","operator":{"max_version":"8.2.5","max_operator":"lt","unfixed":0},
			 "source":[{"id":"CVE-2022-0001","link":"https://cve.org/1","description":"[en] Own flaw.","date":"2023-01-05"}],"impact":[]},
			{"uuid":"d","name":"PHP 8.2 < 8.2.1","operator":{"max_version":"8.2.1","max_operator":"lt","unfixed":0},
			 "source":[{"id":"CVE-2022-0004","link":"https://cve.org/4","description":"[en] Old.","date":"2022-11-01"}],"impact":[]},
			{"uuid":"e","name":"PHP 8.2 < 8.2.30","operator":{"max_version":"8.2.30","max_operator":"lt","unfixed":0},
			 "source":[{"id":"CVE-2025-0005","link":"https://cve.org/5","description":"[en] Unscored.","date":"2025-03-01"}],"impact":[]}
		]}}`,
	})
	a := newAdvisor(f, t.TempDir())
	ctx := context.Background()
	rec, _, err := a.Client.Advisories(ctx, "php", "7.4.33")
	if err != nil {
		t.Fatal(err)
	}
	flaws, from, _, err := a.newerPHPFlaws(ctx, rec, "7.4.33", a.Now())
	if err != nil || from != "8.2" {
		t.Fatalf("from %q, err %v", from, err)
	}
	var ids []string
	for _, v := range flaws {
		ids = append(ids, v.CVEs[0])
		if v.FixedIn() != "" || !v.Affects("7.4.33") {
			t.Errorf("%s: fixed in %q", v.CVEs[0], v.FixedIn())
		}
	}
	// 0003 has a lower bound, 0001 is already listed, 0004 predates the end of life.
	if want := []string{"CVE-2024-0002", "CVE-2025-0005"}; !slices.Equal(ids, want) {
		t.Errorf("inferred %v, want %v", ids, want)
	}
	if flaws[0].Title != "The parser overflows." || !flaws[0].KEV || flaws[0].Severity != "critical" {
		t.Errorf("flaw %+v", flaws[0])
	}

	// A supported branch infers nothing, and doesn't ask php.net.
	rec.EndOfLife = "2099-01-01"
	f.mu.Lock()
	f.paths = nil
	f.mu.Unlock()
	if flaws, _, _, err := a.newerPHPFlaws(ctx, rec, "7.4.33", a.Now()); len(flaws) != 0 || err != nil || f.requested("/releases/") {
		t.Errorf("supported: %v %v", flaws, err)
	}
}
