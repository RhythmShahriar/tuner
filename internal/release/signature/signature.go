// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package signature checks that a release's checksums.txt was signed for
// Tuner's repository and the release tag.
//
// Tuner never replaces its own binary: `rhythm update` and the installers
// do. The check lives in its own package, out of the rhythm-tuner binary,
// so the Sigstore libraries (about 14 MB) are only linked into a command
// that installs or locks a release. Such a command sets
// update.Updater.Verifier to NewVerifier. The kit then refuses any
// release whose signature is missing or was made for another repository
// or tag.
package signature

import (
	"context"
	"fmt"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/sigverify"

	"github.com/RhythmShahriar/tuner/internal/release"
)

// Verifier checks the Sigstore bundle over a release's checksums.txt with
// kit/sigverify: signed through GitHub Actions by the shared release
// workflow, for its repository and for the release tag. It refuses any
// other repository before it reads the bundle, so an Updater pointed
// elsewhere can't borrow Tuner's trust. It implements update.Verifier and
// is safe for concurrent use. The trusted root is loaded on first use.
type Verifier struct {
	repo    string
	offline bool

	once sync.Once
	v    *sigverify.Verifier
	err  error
}

// NewVerifier returns the signature check for Tuner's releases. offline
// (--offline or RHYTHM_OFFLINE) uses the Sigstore root embedded in the
// kit instead of refreshing it through TUF.
func NewVerifier(offline bool) *Verifier { return newVerifier(release.Repo, offline) }

func newVerifier(repo string, offline bool) *Verifier {
	return &Verifier{repo: repo, offline: offline}
}

// VerifyChecksums reports the workflow identity that signed checksums for
// version of repo, or an error wrapping sigverify.ErrSignature when the
// bundle doesn't prove it.
func (r *Verifier) VerifyChecksums(ctx context.Context, repo, version string, checksums, bundle []byte) (string, error) {
	if repo != r.repo {
		return "", fmt.Errorf("%w: this check is for %s releases, not %s", sigverify.ErrSignature, r.repo, repo)
	}
	r.once.Do(func() { r.v, r.err = sigverify.New(sigverify.Options{Offline: r.offline}) })
	if r.err != nil {
		return "", r.err
	}
	return r.v.VerifyChecksums(ctx, repo, version, checksums, bundle)
}
