// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// packbuild builds the check pack release assets from checks/. CI and
// `make pack` both run it, so a local build matches the published one byte
// for byte given the same commit:
//
//	go run ./internal/packbuild -commit "$(git rev-parse HEAD)" -time "$(git log -1 --format=%cI)"
//
// CI adds -sign-key-env TUNER_PACK_SIGNING_KEY to also write the signature
// of the checksum file. Ed25519 signatures are deterministic, so signed
// builds are reproducible too. The key is read from the environment and
// never from a file, so it cannot end up committed next to the checks.
//
// -gen-key prints a new key pair: the private key for the Actions secret
// and the public key for checkpack/keys.go.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/RhythmShahriar/tuner/checkpack"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("packbuild", flag.ContinueOnError)
	flags.SetOutput(stderr)
	src := flags.String("src", "checks", "checks directory")
	out := flags.String("out", "dist/checks-pack", "output directory")
	commit := flags.String("commit", "", "commit SHA the pack is built from (required)")
	at := flags.String("time", "", "that commit's time, RFC 3339 (required)")
	keyEnv := flags.String("sign-key-env", "", "sign with the base64 Ed25519 private key in this environment variable")
	genKey := flags.Bool("gen-key", false, "print a new signing key pair and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *genKey {
		return generateKey(stdout, stderr)
	}
	var key ed25519.PrivateKey
	if *keyEnv != "" {
		v := os.Getenv(*keyEnv)
		if v == "" {
			// CI must never publish an unsigned pack because a secret is unset.
			fmt.Fprintf(stderr, "packbuild: %s is empty; refusing to build an unsigned pack\n", *keyEnv)
			return 2
		}
		k, err := checkpack.ParsePrivateKey(v)
		if err != nil {
			fmt.Fprintf(stderr, "packbuild: %s: %v\n", *keyEnv, err)
			return 2
		}
		key = k
	}
	created, err := time.Parse(time.RFC3339, *at)
	if *commit == "" || err != nil {
		fmt.Fprintln(stderr, "packbuild: -commit and an RFC 3339 -time are required")
		return 2
	}

	built, err := checkpack.Build(os.DirFS(*src), *commit, created)
	if err != nil {
		fmt.Fprintln(stderr, "packbuild:", err)
		return 1
	}
	if key != nil {
		built.Sign(key)
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fmt.Fprintln(stderr, "packbuild:", err)
		return 1
	}
	names := make([]string, 0, len(built.Files))
	for name := range built.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		p := filepath.Join(*out, name)
		if err := os.WriteFile(p, built.Files[name], 0o644); err != nil { //nolint:gosec // public release assets
			fmt.Fprintln(stderr, "packbuild:", err)
			return 1
		}
		fmt.Fprintln(stdout, p)
	}
	m := built.Manifest
	fmt.Fprintf(stdout, "pack %s: %d checks, min rhythm-tuner %s, commit %s\n", m.Version, m.Checks, m.MinTuner, m.Commit)
	if key == nil {
		fmt.Fprintln(stdout, "unsigned: rhythm-tuner only uses it with TUNER_CHECKS_INSECURE=1")
	}
	return 0
}

// generateKey prints a fresh Ed25519 key pair.
func generateKey(stdout, stderr io.Writer) int {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "packbuild:", err)
		return 1
	}
	fmt.Fprintf(stdout, "private (TUNER_PACK_SIGNING_KEY secret, keep it out of the repo): %s\n",
		base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Fprintf(stdout, "public (add to trustedKeys in checkpack/keys.go): %s\n", base64.StdEncoding.EncodeToString(pub))
	return 0
}
