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
