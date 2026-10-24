// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package signature

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/sigverify"
	"github.com/RhythmShahriar/rhythm/kit/update"

	"github.com/RhythmShahriar/tuner/internal/release"
)

// The kit's signed fixture: checksums.txt of RhythmShahriar/rhythm
// v0.1.0 and its Sigstore bundle, as the shared release workflow made it.
const (
	fixRepo    = "RhythmShahriar/rhythm"
	fixVersion = "0.1.0"
	fixSigner  = "https://github.com/RhythmShahriar/.github/.github/workflows/release-go.yml@refs/heads/master"
)

func fixtures(t *testing.T) (sums, bundle []byte) {
	t.Helper()
	sums, err := os.ReadFile("testdata/rhythm_v0.1.0_checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = os.ReadFile("testdata/rhythm_v0.1.0_checksums.txt.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return sums, bundle
}

// fakeAPI serves one release of repo tagged v0.1.0 on 127.0.0.1 (ports
// 23100-23139) with the fixture's checksums.txt, its bundle (unless
// noBundle) and a platform archive for binary.
func fakeAPI(t *testing.T, repo, binary string, noBundle bool) *update.Updater {
	t.Helper()
	sums, bundle := fixtures(t)
	u := &update.Updater{Repo: repo, Binary: binary, Current: "0.0.9", OS: "linux", Arch: "amd64"}
	archive := u.ArchiveName()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/repos/"+repo+"/releases/tags/v"+fixVersion, func(w http.ResponseWriter, r *http.Request) {
		assets := []string{
			fmt.Sprintf(`{"name":"checksums.txt","browser_download_url":"%s/dl/checksums.txt"}`, base),
			fmt.Sprintf(`{"name":%q,"browser_download_url":"%s/dl/archive"}`, archive, base),
		}
		if !noBundle {
			assets = append(assets, fmt.Sprintf(`{"name":"checksums.txt.sigstore.json","browser_download_url":"%s/dl/bundle"}`, base))
		}
		fmt.Fprintf(w, `{"tag_name":"v%s","assets":[%s]}`, fixVersion, strings.Join(assets, ","))
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(sums) })
	mux.HandleFunc("/dl/bundle", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bundle) })
	mux.HandleFunc("/dl/archive", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not reached")) })
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	base = srv.URL
	u.API = srv.URL
	return u
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	for port := 23100; port <= 23139; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in 23100-23139")
	return nil
}

func byTag(t *testing.T, u *update.Updater) *update.Release {
	t.Helper()
	t.Setenv("RHYTHM_OFFLINE", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("RHYTHM_GITHUB_TOKEN", "")
	rel, err := u.ByTag(context.Background(), fixVersion)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// A release of Tuner whose bundle was made for another repository is
// refused before any checksum is read. The binary is left alone.
func TestTunerRefusesBundleOfAnotherRepository(t *testing.T) {
	u := fakeAPI(t, release.Repo, release.Binary, false)
	u.Verifier = NewVerifier(true)
	rel := byTag(t, u)

	// sigverify itself rejects the bundle: its certificate names
	// RhythmShahriar/rhythm, not Tuner.
	if _, err := u.Checksums(context.Background(), rel); !isSignatureErr(err) || !errors.Is(err, sigverify.ErrSignature) {
		t.Fatalf("Checksums: err = %v, want a signature error", err)
	}
	dest := filepath.Join(t.TempDir(), release.Binary)
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := u.InstallWith(context.Background(), rel, dest, update.InstallOptions{})
	if !isSignatureErr(err) {
		t.Fatalf("InstallWith: err = %v, want a signature error", err)
	}
	if !strings.Contains(err.Error(), "refusing to install "+release.Repo+" "+fixVersion) {
		t.Errorf("message %q does not say what was refused", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "old" {
		t.Errorf("binary changed to %q", b)
	}
}

// A release with no bundle fails closed.
func TestTunerRefusesMissingBundle(t *testing.T) {
	u := fakeAPI(t, release.Repo, release.Binary, true)
	u.Verifier = NewVerifier(true)
	_, err := u.Checksums(context.Background(), byTag(t, u))
	if !isSignatureErr(err) || !strings.Contains(err.Error(), "no checksums.txt.sigstore.json") {
		t.Fatalf("err = %v, want a missing-bundle signature error", err)
	}
}

// The same check passes the fixture for the repository it was signed
// for, so the refusals above come from the identity and not a broken
// verifier.
func TestVerifierAcceptsItsOwnRepository(t *testing.T) {
	u := fakeAPI(t, fixRepo, "rhythm", false)
	v := newVerifier(fixRepo, true)
	u.Verifier = v
	all, err := u.Checksums(context.Background(), byTag(t, u))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Error("no archives listed")
	}
	sums, bundle := fixtures(t)
	signer, err := v.VerifyChecksums(context.Background(), fixRepo, fixVersion, sums, bundle)
	if err != nil || signer != fixSigner {
		t.Errorf("signer %q, err %v", signer, err)
	}
}

// Tuner's check refuses an Updater pointed at another repository, even
// with a bundle that is valid for that repository.
func TestVerifierPinnedToTuner(t *testing.T) {
	sums, bundle := fixtures(t)
	signer, err := NewVerifier(true).VerifyChecksums(context.Background(), fixRepo, fixVersion, sums, bundle)
	if !errors.Is(err, sigverify.ErrSignature) || signer != "" {
		t.Fatalf("signer %q, err %v, want a signature error", signer, err)
	}
	if !strings.Contains(err.Error(), "for "+release.Repo+" releases, not "+fixRepo) {
		t.Errorf("message %q", err)
	}
}

// isSignatureErr reports whether the kit refused the release over its
// signature (update.ErrSignature).
func isSignatureErr(err error) bool {
	var se *update.ErrSignature
	return errors.As(err, &se)
}
