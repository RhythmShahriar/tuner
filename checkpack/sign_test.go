// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cachedGood fetches a good pack into a fresh cache and returns a client
// whose cache has gone stale, so its next Get consults the release.
func cachedGood(t *testing.T, rel *release) *Client {
	t.Helper()
	c := rel.client(t.TempDir())
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.TTL = time.Nanosecond
	return c
}

// A newer release than the cached pack, with its signature broken in
// different ways. Each must leave the cached pack in use, with a warning,
// and nothing about the bad pack cached.
func TestBadSignatureKeepsCache(t *testing.T) {
	src := source("0.2.0", map[string]string{"a/x.yaml": goodCheck})
	good := build(t, src, t0)
	newer := func() map[string][]byte {
		return build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0.Add(time.Hour))
	}

	flipped := newer()
	flipped[SumsName] = bytes.Clone(flipped[SumsName])
	flipped[SumsName][0] ^= 1 // still parses, no longer what was signed
	missing := newer()
	delete(missing, SigName)
	other := newer()
	other[SigName] = Sign(other[SumsName], otherKey)
	garbage := newer()
	garbage[SigName] = []byte("not base64!\n")

	for name, tc := range map[string]struct {
		files map[string][]byte
		want  string
	}{
		"flipped byte in sums": {flipped, "not signed by a trusted key"},
		"missing signature":    {missing, "checks-sha256.txt.sig: HTTP 404"},
		"another key":          {other, "not signed by a trusted key"},
		"malformed signature":  {garbage, "is malformed"},
	} {
		t.Run(name, func(t *testing.T) {
			rel := newRelease(t, maps.Clone(good))
			c := cachedGood(t, rel)
			rel.set(tc.files)
			p, err := c.Get(context.Background())
			if err != nil || !p.Stale || p.Version != "2026.10.01-120000" {
				t.Fatalf("p=%+v err=%v, want the cached pack", p, err)
			}
			if p.Warning == nil || !strings.Contains(p.Warning.Error(), tc.want) {
				t.Errorf("warning = %v, want %q", p.Warning, tc.want)
			}
			if rel.count(ArchiveName) != 1 {
				t.Errorf("archive of an unsigned pack downloaded: %v", rel.hits)
			}

			// With no cache, there is no pack at all.
			if _, err := rel.client(t.TempDir()).Get(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("no cache: err = %v", err)
			}
		})
	}
}

func TestSignedPackAccepted(t *testing.T) {
	files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
	rel := newRelease(t, files)
	c := rel.client(t.TempDir())
	// A second trusted key, as during a rotation, doesn't get in the way.
	c.Keys = append([]ed25519.PublicKey{otherKey.Public().(ed25519.PublicKey)}, c.Keys...)
	p, err := c.Get(context.Background())
	if err != nil || p.Warning != nil || len(p.Loaded) != 1 {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if rel.count(SigName) != 1 {
		t.Errorf("signature fetched %d times", rel.count(SigName))
	}
}

func TestNoTrustedKeys(t *testing.T) {
	rel := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	c := rel.client(t.TempDir())
	c.Keys = []ed25519.PublicKey{}
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrNoTrustedKeys) {
		t.Fatalf("err = %v, want ErrNoTrustedKeys", err)
	}
	if rel.total() != 0 {
		t.Error("a build that trusts no key fetched a pack")
	}
}

// TUNER_CHECKS_INSECURE: an unsigned pack is used, its checksums still
// verified.
func TestInsecureSkipsSignature(t *testing.T) {
	files := build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0)
	delete(files, SigName)
	rel := newRelease(t, files)
	dir := t.TempDir()
	c := rel.client(dir)
	c.Insecure, c.Keys = true, []ed25519.PublicKey{}
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The unsigned pack is not trusted once the bypass is gone.
	strict := rel.client(dir)
	if _, err := strict.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("unsigned cached pack used without the bypass: err = %v", err)
	}

	files[ArchiveName] = []byte("swapped")
	rel.set(files)
	fresh := rel.client(t.TempDir())
	fresh.Insecure = true
	if _, err := fresh.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("insecure mode skipped checksums: err = %v", err)
	}
}

// A pack cached before packs were signed is replaced on the next run,
// not kept for the rest of the TTL.
func TestUnsignedCacheRefetched(t *testing.T) {
	rel := newRelease(t, build(t, source("0.2.0", map[string]string{"a/x.yaml": goodCheck}), t0))
	dir := t.TempDir()
	if _, err := rel.client(dir).Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pack.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	delete(st, "sums")
	delete(st, "sig")
	data, _ = json.Marshal(st)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before := rel.count(SumsName)
	p, err := rel.client(dir).Get(context.Background())
	if err != nil || p.Warning != nil || rel.count(SumsName) != before+1 {
		t.Fatalf("p=%+v err=%v hits=%v", p, err, rel.hits)
	}
}

func TestPackMustKeepBuiltIns(t *testing.T) {
	other := strings.Replace(goodCheck, "pack-test", "pack-other", 1)
	src := source("0.2.0", map[string]string{"a/x.yaml": goodCheck})
	rel := newRelease(t, build(t, src, t0))
	c := rel.client(t.TempDir())
	c.BuiltIn = []string{"pack-test", "pack-other"}
	_, err := c.Get(context.Background())
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "lacks built-in checks pack-other") {
		t.Fatalf("err = %v, want a rejection naming pack-other", err)
	}

	// Retired on purpose: fine.
	retired := source("0.2.0", map[string]string{"a/x.yaml": goodCheck})
	retired[ConfigName].Data = []byte(`{"min_tuner": "0.2.0", "retired": ["pack-other"]}`)
	rel.set(build(t, retired, t0.Add(time.Hour)))
	c.Force = true
	p, err := c.Get(context.Background())
	if err != nil || p.Warning != nil || len(p.Retired) != 1 {
		t.Fatalf("retired: p=%+v err=%v", p, err)
	}

	// A cached pack is held to the running binary's built-ins too.
	c.Force, c.BuiltIn = false, []string{"pack-test", "pack-third"}
	if _, err := c.Get(context.Background()); !errors.Is(err, ErrRejected) {
		t.Errorf("cached pack missing pack-third: err = %v", err)
	}

	// A pack that both defines and retires a check doesn't build.
	both := source("0.2.0", map[string]string{"a/x.yaml": goodCheck, "a/y.yaml": other})
	both[ConfigName].Data = []byte(`{"min_tuner": "0.2.0", "retired": ["pack-other"]}`)
	if _, err := Build(both, "abc", t0); err == nil || !strings.Contains(err.Error(), "pack-other is retired") {
		t.Errorf("Build: err = %v", err)
	}
}

func TestKeyParsing(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(testKey.Public().(ed25519.PublicKey))
	if k, err := ParsePublicKey(pub + "\n"); err != nil || !k.Equal(testKey.Public()) {
		t.Errorf("ParsePublicKey: %v", err)
	}
	for _, s := range []string{base64.StdEncoding.EncodeToString(testKey.Seed()), base64.StdEncoding.EncodeToString(testKey)} {
		if k, err := ParsePrivateKey(s); err != nil || !k.Equal(testKey) {
			t.Errorf("ParsePrivateKey(%d bytes): %v", len(s), err)
		}
	}
	corrupt := bytes.Clone(testKey)
	corrupt[40] ^= 1
	for _, s := range []string{"!!", "AAAA", base64.StdEncoding.EncodeToString(corrupt)} {
		if _, err := ParsePrivateKey(s); err == nil {
			t.Errorf("ParsePrivateKey(%q) accepted", s)
		}
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Error("short public key accepted")
	}
	if _, err := TrustedKeys(); err != nil {
		t.Errorf("embedded keys: %v", err)
	}
}
