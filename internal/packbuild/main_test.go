// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/checkpack"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from this build")

// testSeed is a fixed signing key, so the signature is golden too.
var testSeed = bytes.Repeat([]byte{7}, ed25519.SeedSize)

func build(t *testing.T, extra ...string) (code int, out, stdout, stderr string) {
	t.Helper()
	out = t.TempDir()
	var o, e bytes.Buffer
	args := append([]string{"-src", "testdata/checks", "-out", out,
		"-commit", "0123456789abcdef0123456789abcdef01234567", "-time", "2026-10-01T12:00:00+02:00"}, extra...)
	code = run(args, &o, &e)
	return code, out, o.String(), e.String()
}

// The published assets must be byte for byte what a local build of the
// same commit gives, signature included, so anyone can check a release.
// A Go upgrade that changes compress/flate output changes the archive;
// review the diff and rerun with -update.
func TestGolden(t *testing.T) {
	t.Setenv("PACKBUILD_TEST_KEY", base64.StdEncoding.EncodeToString(testSeed))
	code, out, stdout, stderr := build(t, "-sign-key-env", "PACKBUILD_TEST_KEY")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "pack 2026.10.01-100000: 1 checks, 0 data files, 0 local rules, min rhythm-tuner 0.2.0, commit 0123456789") || strings.Contains(stdout, "unsigned") {
		t.Errorf("stdout:\n%s", stdout)
	}
	names := []string{checkpack.ArchiveName, checkpack.ManifestName, checkpack.SumsName, checkpack.SigName}
	for _, name := range names {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		golden := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run go test -update to create it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from %s", name, golden)
		}
	}
	if entries, _ := os.ReadDir(out); len(entries) != len(names) {
		t.Errorf("%d files written, want %d", len(entries), len(names))
	}

	sums, _ := os.ReadFile(filepath.Join(out, checkpack.SumsName))
	sig, _ := os.ReadFile(filepath.Join(out, checkpack.SigName))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err != nil || !ed25519.Verify(pub, sums, raw) {
		t.Errorf("signature does not verify: %v", err)
	}
	manifest, _ := os.ReadFile(filepath.Join(out, checkpack.ManifestName))
	if !bytes.Contains(manifest, []byte(`"retired": [`)) {
		t.Errorf("manifest lacks retired:\n%s", manifest)
	}
}

func TestUnsigned(t *testing.T) {
	code, out, stdout, _ := build(t)
	if code != 0 || !strings.Contains(stdout, "unsigned: rhythm-tuner only uses it with TUNER_CHECKS_INSECURE=1") {
		t.Fatalf("exit %d:\n%s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(out, checkpack.SigName)); err == nil {
		t.Error("signature written without a key")
	}
}

func TestBadKeys(t *testing.T) {
	t.Setenv("PACKBUILD_EMPTY", "")
	t.Setenv("PACKBUILD_BAD", "not-a-key")
	for env, want := range map[string]string{
		"PACKBUILD_EMPTY": "PACKBUILD_EMPTY is empty; refusing to build an unsigned pack",
		"PACKBUILD_BAD":   "PACKBUILD_BAD: private key is not valid base64",
	} {
		code, out, _, stderr := build(t, "-sign-key-env", env)
		if code != 2 || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d, stderr %q", env, code, stderr)
		}
		if entries, _ := os.ReadDir(out); len(entries) != 0 {
			t.Errorf("%s: files written", env)
		}
	}
}

func TestMissingFlags(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"-src", "testdata/checks"}, &o, &e); code != 2 || !strings.Contains(e.String(), "-commit and an RFC 3339 -time are required") {
		t.Errorf("exit %d: %s", code, e.String())
	}
}

func TestGenKey(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"-gen-key"}, &o, &e); code != 0 {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	var priv ed25519.PrivateKey
	var pub ed25519.PublicKey
	for _, line := range strings.Split(strings.TrimSpace(o.String()), "\n") {
		v := line[strings.LastIndex(line, " ")+1:]
		var err error
		switch {
		case strings.HasPrefix(line, "private"):
			priv, err = checkpack.ParsePrivateKey(v)
		case strings.HasPrefix(line, "public"):
			pub, err = checkpack.ParsePublicKey(v)
		}
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
	}
	if priv == nil || pub == nil || !pub.Equal(priv.Public()) {
		t.Errorf("key pair doesn't match:\n%s", o.String())
	}
}

// Fingerprint data and local rules travel in the pack; rule fixtures
// stay out, like check fixtures.
func TestDataAndLocalRules(t *testing.T) {
	code, out, stdout, stderr := build(t, "-data", "testdata/data", "-local", "testdata/local")
	if code != 0 || !strings.Contains(stdout, "1 checks, 1 data files, 1 local rules") {
		t.Fatalf("exit %d: %s\n%s", code, stderr, stdout)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var m checkpack.Manifest
	if err := json.Unmarshal(read(checkpack.ManifestName), &m); err != nil || !slices.Equal(m.Data, []string{"rest-namespaces.json"}) || m.Local != 1 {
		t.Fatalf("manifest %+v, %v", m, err)
	}
	fsys, _, err := checkpack.Open(m, read(checkpack.ArchiveName), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := fs.ReadFile(fsys, "data/rest-namespaces.json"); err != nil || !bytes.Contains(data, []byte("contact-form-7")) {
		t.Errorf("data: %q %v", data, err)
	}
	if _, err := fs.Stat(fsys, "local/sample.yaml"); err != nil {
		t.Error(err)
	}
	if _, err := fs.Stat(fsys, "local/sample_test.yaml"); err == nil {
		t.Error("rule fixtures should stay out of the pack")
	}

	// A folder named on the command line must exist; the defaults may not.
	if code, _, _, stderr := build(t, "-data", "testdata/nope"); code != 2 || !strings.Contains(stderr, "-data testdata/nope: not a directory") {
		t.Errorf("missing -data: exit %d %s", code, stderr)
	}
}
