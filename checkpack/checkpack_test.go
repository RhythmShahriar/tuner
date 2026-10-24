// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const goodCheck = `id: pack-test
name: Pack test
severity: low
request:
  path: ["/x"]
match:
  all:
    - status: 200
`

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func source(minTuner string, files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{ConfigName: {Data: []byte(`{"min_tuner": "` + minTuner + `"}`)}}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

// testKey signs the packs the fake releases serve; otherKey is a key the
// clients don't trust.
var (
	testKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	otherKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
)

func build(t *testing.T, src fstest.MapFS, created time.Time) map[string][]byte {
	t.Helper()
	b, err := Build(src, "abc1234def", created)
	if err != nil {
		t.Fatal(err)
	}
	b.Sign(testKey)
	return b.Files
}

// release is a fake checks-latest release whose assets can be swapped.
type release struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newRelease(t *testing.T, files map[string][]byte) *release {
	t.Helper()
	r := &release{files: files, hits: map[string]int{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		name := strings.TrimPrefix(req.URL.Path, "/checks-latest/")
		r.hits[name]++
		data, ok := r.files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *release) set(files map[string][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files = files
}

func (r *release) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[name]
}

func (r *release) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.hits {
		n += v
	}
	return n
}

func (r *release) client(dir string) *Client {
	return &Client{
		BaseURL: r.URL + "/checks-latest", CacheDir: dir, Tuner: "0.3.0", UserAgent: "test",
		Keys: testKeys(),
	}
}

func testKeys() []ed25519.PublicKey { return []ed25519.PublicKey{testKey.Public().(ed25519.PublicKey)} }

// withSums recomputes and re-signs the checksum file, as a broken CI run
// or someone holding the signing key would. The checks after the
// signature must hold even then.
func withSums(files map[string][]byte) map[string][]byte {
	files[SumsName] = fmt.Appendf(nil, "%s  %s\n%s  %s\n",
		sum(files[ArchiveName]), ArchiveName, sum(files[ManifestName]), ManifestName)
	files[SigName] = Sign(files[SumsName], testKey)
	return files
}

type entry struct {
	name, link string
	typ        byte
	data       string
}

func tarGz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Size: int64(len(e.data))}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestBuildIsReproducible(t *testing.T) {
	src := source("0.2.0", map[string]string{"a/x.yaml": goodCheck, "a/x_test.yaml": "positive: []", "LICENSE": "MIT"})
	a, b := build(t, src, t0), build(t, src, t0)
	for name := range a {
		if !bytes.Equal(a[name], b[name]) {
			t.Errorf("%s differs between builds", name)
		}
	}
	fsys, err := extract(a[ArchiveName])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Open("a/x_test.yaml"); err == nil {
		t.Error("fixtures should stay out of the pack")
	}
	if _, err := fsys.Open("LICENSE"); err != nil {
		t.Error("LICENSE missing from the pack")
	}
}

// The real checks/ tree must always build, so CI can publish it.
func TestBuildRealChecks(t *testing.T) {
	b, err := Build(os.DirFS("../checks"), "HEAD", t0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Checks < 10 || b.Manifest.Version != "2026.10.01-120000" {
		t.Errorf("manifest = %+v", b.Manifest)
	}
}

func TestValidPack(t *testing.T) {
	rel := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	dir := t.TempDir()
	p, err := rel.client(dir).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Loaded) != 1 || p.Loaded[0].ID != "pack-test" || p.Version != "2026.10.01-120000" || p.Stale || p.Warning != nil {
		t.Fatalf("pack = %+v", p)
	}
	// Within the TTL the cache is used without asking the release.
	before := rel.total()
	if _, err := rel.client(dir).Get(context.Background()); err != nil || rel.total() != before {
		t.Errorf("fresh cache: err %v, %d new requests", err, rel.total()-before)
	}
}

func TestTamperedChecksum(t *testing.T) {
	good := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
	// A newer pack whose archive was swapped after the sums were made.
	bad := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0.Add(time.Hour))
	bad[ArchiveName] = tarGz(t, entry{name: "a/x.yaml", typ: tar.TypeReg, data: strings.Replace(goodCheck, "low", "info", 1)})
	rel := newRelease(t, bad)
	dir := t.TempDir()
	if _, err := rel.client(dir).Get(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want checksum mismatch", err)
	}
	c := rel.client(dir)
	if c.Cached() {
		t.Error("tampered pack was cached")
	}

	// With a good pack cached, a mismatch (maybe a mid-upload release)
	// falls back to it, marked stale.
	rel.set(good)
	c.Force = true // past the back-off the failure started
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	rel.set(bad)
	c.Force = false
	c.TTL = time.Nanosecond
	p, err := c.Get(context.Background())
	if err != nil || !p.Stale || p.Warning == nil || p.Loaded[0].Severity != "low" {
		t.Fatalf("stale fallback: p=%+v err=%v", p, err)
	}
}

func TestUnsafeArchives(t *testing.T) {
	for name, archive := range map[string][]byte{
		"dotdot":   tarGz(t, entry{name: "../evil.yaml", typ: tar.TypeReg, data: goodCheck}),
		"nested":   tarGz(t, entry{name: "a/../../evil.yaml", typ: tar.TypeReg, data: goodCheck}),
		"absolute": tarGz(t, entry{name: "/etc/evil.yaml", typ: tar.TypeReg, data: goodCheck}),
		"symlink":  tarGz(t, entry{name: "a/x.yaml", typ: tar.TypeSymlink, link: "/etc/passwd"}),
		"hardlink": tarGz(t, entry{name: "a/x.yaml", typ: tar.TypeLink, link: "../../etc/passwd"}),
		"device":   tarGz(t, entry{name: "a/x.yaml", typ: tar.TypeChar}),
		"empty":    tarGz(t),
		"garbage":  []byte("not a tarball"),
	} {
		t.Run(name, func(t *testing.T) {
			files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
			files[ArchiveName] = archive
			rel := newRelease(t, withSums(files))
			_, err := rel.client(t.TempDir()).Get(context.Background())
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("err = %v, want ErrRejected", err)
			}
		})
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	old := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
	// A pack from a newer Tuner with a matcher this binary doesn't know.
	files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0.Add(time.Hour))
	newer := strings.Replace(goodCheck, "- status: 200", "- status: 200\n      json_path: $.x", 1)
	files[ArchiveName] = tarGz(t, entry{name: "a/x.yaml", typ: tar.TypeReg, data: newer})
	files = withSums(files)

	rel := newRelease(t, files)
	if _, err := rel.client(t.TempDir()).Get(context.Background()); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "json_path") {
		t.Fatalf("err = %v, want rejection naming json_path", err)
	}

	// The last good pack stays in use, with the reason attached.
	rel.set(old)
	dir := t.TempDir()
	c := rel.client(dir)
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	rel.set(files)
	c.Force = true
	p, err := c.Get(context.Background())
	if err != nil || p.Version != "2026.10.01-120000" || p.Warning == nil {
		t.Fatalf("p=%+v err=%v", p, err)
	}
}

func TestMinTunerTooNew(t *testing.T) {
	rel := newRelease(t, build(t, source("99.0.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	dir := t.TempDir()
	_, err := rel.client(dir).Get(context.Background())
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "needs rhythm-tuner 99.0.0") {
		t.Fatalf("err = %v", err)
	}
	if rel.count(ArchiveName) != 0 {
		t.Error("archive downloaded for a pack the manifest already ruled out")
	}
	// The verdict is cached for the TTL: no download on every scan.
	before := rel.total()
	if _, err := rel.client(dir).Get(context.Background()); !strings.Contains(fmt.Sprint(err), "99.0.0") || rel.total() != before {
		t.Errorf("second run: err %v, %d new requests", err, rel.total()-before)
	}
	// Dev builds take any pack.
	c := rel.client(t.TempDir())
	c.Tuner = "dev"
	if _, err := c.Get(context.Background()); err != nil {
		t.Errorf("dev build: %v", err)
	}
}

func TestSchemaTooNew(t *testing.T) {
	files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
	files[ManifestName] = bytes.Replace(files[ManifestName], []byte(`"schema": 1`), []byte(`"schema": 2`), 1)
	rel := newRelease(t, withSums(files))
	if _, err := rel.client(t.TempDir()).Get(context.Background()); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

func TestOffline(t *testing.T) {
	rel := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	dir := t.TempDir()
	c := rel.client(dir)
	c.Offline = true
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrNotCached) {
		t.Fatalf("offline, empty cache: err = %v", err)
	}
	if rel.total() != 0 {
		t.Fatal("offline mode made requests")
	}

	if _, err := rel.client(dir).Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := rel.total()
	c.TTL = time.Nanosecond // the cache is now stale, and offline uses it anyway
	p, err := c.Get(context.Background())
	if err != nil || !p.Stale || len(p.Loaded) != 1 || rel.total() != before {
		t.Fatalf("offline with cache: p=%+v err=%v requests=%d", p, err, rel.total()-before)
	}
}

func TestTTLRefresh(t *testing.T) {
	src := source("0.2.0", map[string]string{"a/x.yaml": goodCheck})
	rel := newRelease(t, build(t, src, t0))
	dir := t.TempDir()
	if _, err := rel.client(dir).Get(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Expired, same pack: only the manifest and sums are fetched again.
	c := rel.client(dir)
	c.TTL = time.Nanosecond
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rel.count(ArchiveName) != 1 || rel.count(ManifestName) != 2 {
		t.Errorf("unchanged pack: %v", rel.hits)
	}

	// Expired, new pack: it replaces the cached one.
	src["a/y.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(goodCheck, "pack-test", "pack-new", 1))}
	rel.set(build(t, src, t0.Add(24*time.Hour)))
	p, err := c.Get(context.Background())
	if err != nil || p.Version != "2026.10.02-120000" || len(p.Loaded) != 2 {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if p, _ := rel.client(dir).Get(context.Background()); p.Version != "2026.10.02-120000" {
		t.Errorf("new pack not cached: %s", p.Version)
	}
}

func TestSupersedes(t *testing.T) {
	p := &Pack{Manifest: Manifest{Created: t0}}
	for _, tc := range []struct {
		b    BuildInfo
		want bool
	}{
		{BuildInfo{}, true},                                          // build time unknown
		{BuildInfo{Time: t0.Add(-time.Hour)}, true},                  // older binary
		{BuildInfo{Time: t0}, false},                                 // same commit
		{BuildInfo{Time: t0.Add(time.Hour)}, false},                  // newer binary
		{BuildInfo{Time: t0.Add(-time.Hour), Modified: true}, false}, // local edits
	} {
		if got := p.Supersedes(tc.b); got != tc.want {
			t.Errorf("Supersedes(%+v) = %v, want %v", tc.b, got, tc.want)
		}
	}
}
