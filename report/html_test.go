// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/base64"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/matchers"
)

// htmlBatch is a two-site batch and the scan before it. Site a's Server
// header and a finding title carry markup a hostile site could send.
func htmlBatch() (now, before []Report) {
	gallery := engine.Finding{
		ID: "vuln-plugin-gallery", Title: "gallery 1.5: 2 known vulnerabilities", Severity: engine.High, Confidence: "high",
		Target: "https://a.test", URL: "https://a.test/wp-content/plugins/gallery/", Path: "/wp-content/plugins/gallery/",
		Fix: "Update gallery to 1.6 or later.", Source: "WPVulnerability",
		Advisories: []engine.Advisory{
			{ID: "WPV-1", Title: "Stored XSS", CVEs: []string{"CVE-2025-1"}, Severity: engine.Medium, FixedIn: "1.5.1",
				References: []string{"https://www.cve.org/CVERecord?id=CVE-2025-1"}},
			{ID: "WPV-2", Title: "SQL injection <b>bold</b>", CVEs: []string{"CVE-2026-2"}, Severity: engine.High, KEV: true, FixedIn: "1.6",
				References: []string{"javascript:alert(1)"}},
		},
	}
	dotenv := engine.Finding{
		ID: "leak-dotenv", Title: `.env file exposed <img src=x onerror=alert(1)>`, Severity: engine.Critical, Confidence: "high",
		Target: "https://a.test", URL: "https://a.test/.env", Path: "/.env",
		Evidence: engine.Evidence{Request: "GET /.env", Status: 200, Matched: []string{"DB_PASSWORD=…"},
			Secrets: []matchers.Secret{{Kind: "env", Name: "DB_PASSWORD", Masked: "hu•••••"}}},
		Impact:     "Anyone can read the database password.",
		Fix:        "Delete the file:\n\n    rm .env\n",
		References: []string{"https://owasp.org/www-project-top-ten/", "javascript:alert(2)"},
	}
	xmlrpc := engine.Finding{ID: "xmlrpc", Title: "XML-RPC is on", Severity: engine.Low, Confidence: "high",
		Target: "https://a.test", URL: "https://a.test/xmlrpc.php", Path: "/xmlrpc.php", Fix: "Block xmlrpc.php."}
	php := engine.Finding{ID: "vuln-php", Title: "PHP 8.1.2: 1 known vulnerability", Severity: engine.Medium, Confidence: "low",
		Caveat: "likely: a distro build may already include the fix", Target: "https://b.test", URL: "https://b.test/", Path: "/"}
	old := engine.Finding{ID: "leak-git-config", Title: "Git config exposed", Severity: engine.High, Confidence: "high",
		Target: "https://a.test", URL: "https://a.test/.git/config", Path: "/.git/config"}

	fp := fingerprint.Result{Tech: []string{"wordpress", "php"}, WordPress: "6.9", PHP: "8.1.2", Server: `<img src=x onerror=alert(3)>`,
		Components: []fingerprint.Component{{Type: "plugin", Slug: "gallery", Version: "1.5", Source: "readme"}}}
	mk := func(target string, score int, fp fingerprint.Result, fs ...engine.Finding) Report {
		return New(&engine.Result{Target: target, Fingerprint: fp, Score: score, Checks: 40, Requests: 61, Findings: fs}, "1.2.3")
	}
	oldGallery := gallery
	oldGallery.Advisories = gallery.Advisories[:1]
	now = []Report{
		mk("https://a.test", 41, fp, dotenv, gallery, xmlrpc),
		mk("https://b.test", 85, fingerprint.Result{Tech: []string{"php"}, PHP: "8.1.2"}, php),
	}
	now[1].SetStatus(Status{Complete: false, StoppedBy: "max-time", VulnData: "ok"})
	before = []Report{mk("https://a.test/", 60, fp, oldGallery, xmlrpc, old)}
	return now, before
}

func writeLogo(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const logoSVG = `<?xml version="1.0"?>
<!-- Acme -->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><defs><linearGradient id="g"><stop offset="0" stop-color="#f00"/></linearGradient></defs><rect width="10" height="10" fill="url(#g)"/><text x="1" y="8">A&amp;B</text></svg>`

func TestHTMLGolden(t *testing.T) {
	now, before := htmlBatch()
	var b bytes.Buffer
	err := Write("html", &b, now, WriteOptions{
		Many: true, Version: "1.2.3", Since: before, SinceName: "last-week.json",
		Failed: []TargetError{{Target: "https://down.test", Error: "connection refused"}},
		Brand:  Brand{Name: "Acme Agency", LogoPath: writeLogo(t, "logo.svg", []byte(logoSVG))},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	golden(t, "html-batch.golden", out)

	if strings.Contains(strings.ToLower(out), "<script") {
		t.Error("the page has a script tag")
	}
	if strings.Contains(out, "<img src=x") || !strings.Contains(out, "&lt;img src=x onerror=alert(3)&gt;") {
		t.Error("the Server header is not escaped")
	}
	if !strings.Contains(out, ".env file exposed &lt;img src=x onerror=alert(1)&gt;") {
		t.Error("the finding title is not escaped")
	}
	// The only src is the embedded logo; every href is an anchor in the
	// page or an http(s) link from an advisory or a reference.
	for _, m := range regexp.MustCompile(`\ssrc="([^"]*)"`).FindAllStringSubmatch(out, -1) {
		if !strings.HasPrefix(html.UnescapeString(m[1]), "data:image/svg+xml;base64,") {
			t.Errorf("src=%q", m[1])
		}
	}
	allowed := map[string]bool{"https://www.cve.org/CVERecord?id=CVE-2025-1": true, "https://owasp.org/www-project-top-ten/": true}
	for _, m := range regexp.MustCompile(`\shref="([^"]*)"`).FindAllStringSubmatch(out, -1) {
		if href := html.UnescapeString(m[1]); !strings.HasPrefix(href, "#site-") && !allowed[href] {
			t.Errorf("href=%q", m[1])
		}
	}
	for _, want := range []string{
		"<title>Acme Agency security report: 3 sites</title>",
		"Prepared by Acme Agency with rhythm-tuner 1.2.3 · compared with last-week.json",
		`<span class="down">down 19 since last-week.json (was 60)</span>`,
		`<span class="new">NEW</span> SQL injection &lt;b&gt;bold&lt;/b&gt;`, // a new advisory on a known plugin
		"Fixed since last-week.json (1)",
		"not scanned: connection refused",
		"Incomplete: stopped by --max-time",
		"javascript:alert(2)", // shown as text
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestHTMLMarksOnlyNewFindings(t *testing.T) {
	now, before := htmlBatch()
	a := htmlSiteFor(0, now[0], &before[0], true, "old.json")
	if a.New != 2 || len(a.Fixed) != 1 || a.Fixed[0].Title != "Git config exposed" {
		t.Fatalf("new %d, fixed %+v", a.New, a.Fixed)
	}
	marks := map[string]bool{}
	for _, g := range a.Groups {
		for _, f := range g.Findings {
			marks[f.ID] = f.New
			if f.ID == "vuln-plugin-gallery" && (f.Advisories[0].New || !f.Advisories[1].New) {
				t.Errorf("advisory marks: %+v", f.Advisories)
			}
		}
	}
	if !marks["leak-dotenv"] || !marks["vuln-plugin-gallery"] || marks["xmlrpc"] {
		t.Errorf("marks: %v", marks)
	}
	if a.TrendShort != "-19" || a.TrendClass != "down" {
		t.Errorf("trend %q %q", a.TrendShort, a.TrendClass)
	}
	// Without --since nothing is marked and no trend shows.
	plain := htmlSiteFor(0, now[0], nil, false, "")
	if plain.New != 0 || plain.Trend != "" || plain.Compared {
		t.Errorf("without since: %+v", plain)
	}
}

func TestHTMLSingleCleanSite(t *testing.T) {
	r := New(&engine.Result{Target: "https://ok.test", Score: 100}, "1.2.3")
	var b bytes.Buffer
	if err := Write("html", &b, []Report{r}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<title>Security report: https://ok.test</title>", "Nothing out of tune.", "Made with rhythm-tuner 1.2.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(out, "Overview") || strings.Contains(out, "<img") {
		t.Error("a single unbranded site has no overview or logo")
	}
	if FormatForExt("client.html") != "html" || FormatForExt("client.HTM") != "html" {
		t.Error("html extensions")
	}
}

func TestLogo(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)
	uri, err := LogoDataURI(writeLogo(t, "logo.png", png))
	if err != nil || uri != "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png) {
		t.Errorf("png: %v %.40s", err, uri)
	}
	if uri, err := LogoDataURI(writeLogo(t, "logo.jpg", []byte("\xff\xd8\xff\xe0rest"))); err != nil || !strings.HasPrefix(uri, "data:image/jpeg;base64,") {
		t.Errorf("jpeg: %v", err)
	}
	uri, err = LogoDataURI(writeLogo(t, "logo.svg", []byte(logoSVG)))
	if err != nil {
		t.Fatal(err)
	}
	svg, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "data:image/svg+xml;base64,"))
	want := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><defs><linearGradient id="g"><stop offset="0" stop-color="#f00"></stop></linearGradient></defs><rect width="10" height="10" fill="url(#g)"></rect><text x="1" y="8">A&amp;B</text></svg>`
	if string(svg) != want {
		t.Errorf("svg rebuilt as\n%s\nwant\n%s", svg, want)
	}

	big := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, MaxLogoSize)...)
	if _, err := LogoDataURI(writeLogo(t, "big.png", big)); err == nil || !strings.Contains(err.Error(), "is over 512 KB") {
		t.Errorf("big: %v", err)
	}
	if _, err := LogoDataURI(filepath.Join(t.TempDir(), "missing.png")); err == nil {
		t.Error("missing file")
	}
	for name, bad := range map[string]string{
		"script":     `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"onload":     `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`,
		"href":       `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.test/x.svg#a"/></svg>`,
		"image":      `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.test/p.png"/></svg>`,
		"style":      `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.test/)"/></svg>`,
		"remote url": `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://evil.test/#g)"/></svg>`,
		"foreign":    `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>`,
		"doctype":    `<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"></svg>`,
		"html ns":    `<svg xmlns="http://www.w3.org/2000/svg"><h:p xmlns:h="http://www.w3.org/1999/xhtml"/></svg>`,
		"not svg":    `<html><body>hi</body></html>`,
		"text":       `just text`,
		"two roots":  `<svg xmlns="http://www.w3.org/2000/svg"></svg><svg xmlns="http://www.w3.org/2000/svg"></svg>`,
		"pi":         `<svg xmlns="http://www.w3.org/2000/svg"><?php echo 1 ?></svg>`,
		"css escape": `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="u\rl(http://evil.test/)"/></svg>`,
		"hex escape": `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="\75rl(http://evil.test/)"/></svg>`,
		"other func": `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="image(http://evil.test/)"/></svg>`,
		"bare paren": `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="(http://evil.test/)"/></svg>`,
		"url chain":  `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(#g) url(http://evil.test/)"/></svg>`,
	} {
		if _, err := LogoDataURI(writeLogo(t, "bad.svg", []byte(bad))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Transforms, colors and local references are plain values.
	for _, v := range []string{"url(#g)", `url("#g")`, "URL( #g )", "translate(10 20) rotate(-45.5)", "rgb(255, 0, 0)", "matrix(1,0,0,1,0,0)", "#f00", "none"} {
		if !safeValue(v) {
			t.Errorf("safeValue(%q) = false", v)
		}
	}

	// A logo that fails stops the html writer instead of being left out.
	r := New(&engine.Result{Target: "https://ok.test"}, "1")
	if err := Write("html", &bytes.Buffer{}, []Report{r}, WriteOptions{Brand: Brand{LogoPath: writeLogo(t, "big.png", big)}}); err == nil {
		t.Error("oversized logo written")
	}
}
