// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package checkpack lets checks update like data. CI publishes the checks/
// tree as a "check pack" (a tar.gz, a manifest, a checksum file and its
// signature) on the rolling checks-latest release and Tuner fetches it,
// verifies it and uses it in place of the checks compiled into the binary
// when it is newer.
//
// A pack is only ever data: declarative YAML checks that make GET requests
// to the scanned site and match the replies. Its sha256 sums file is
// signed with an Ed25519 key whose public half is compiled into Tuner (see
// keys.go), so a pack can only come from CI, not from whoever can upload
// release assets or run a mirror. The archive is checked against the
// signed sums, unpacked in memory with strict limits and loaded with
// engine.LoadChecks, which rejects unknown fields; that is how an older
// binary refuses a pack that relies on matchers it doesn't have. A pack
// must also carry every built-in check unless its manifest retires it, so
// a smaller pack cannot quietly drop coverage.
package checkpack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing/fstest"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/update"

	"github.com/RhythmShahriar/tuner/engine"
)

// Schema is the pack layout this binary understands. Bump it only for
// changes an older binary can't detect on its own; new matcher fields
// don't need it, since unknown YAML fields already fail to load.
const Schema = 1

// Release asset names.
const (
	ManifestName = "checks-manifest.json"
	ArchiveName  = "checks.tar.gz"
	SumsName     = "checks-sha256.txt"
)

// ConfigName is the file in checks/ that sets the pack's min_tuner. It is
// JSON, not YAML, so engine.LoadChecks never mistakes it for a check.
const ConfigName = "pack.json"

// Limits for unpacking; the real pack is a few hundred KB.
const (
	maxArchive = 16 << 20
	maxFile    = 1 << 20
	maxTotal   = 32 << 20
	maxFiles   = 5000
	maxSmall   = 64 << 10 // manifest and sums
)

// Manifest describes a pack. It travels next to the archive, so a client
// can reject an incompatible pack before downloading it.
type Manifest struct {
	Schema   int       `json:"schema"`
	Version  string    `json:"version"`   // from the commit time, e.g. 2026.10.23-142501
	Commit   string    `json:"commit"`    // the tuner commit the pack was built from
	Created  time.Time `json:"created"`   // that commit's time; orders packs and builds
	MinTuner string    `json:"min_tuner"` // oldest rhythm-tuner that can run these checks
	Checks   int       `json:"checks"`
	Retired  []string  `json:"retired,omitempty"` // check IDs removed on purpose; older binaries still have them built in
}

// Built is a pack ready to publish: the release assets and the
// signature once Sign has run.
type Built struct {
	Manifest Manifest
	Files    map[string][]byte // asset name → contents
}

// Build packs every check in src, the checks/ tree, reproducibly: the same
// tree, commit and time always give byte-identical assets.
func Build(src fs.FS, commit string, created time.Time) (*Built, error) {
	cfg, err := readConfig(src)
	if err != nil {
		return nil, err
	}
	loaded, err := engine.LoadChecks(src)
	if err != nil {
		return nil, err
	}
	created = created.UTC().Truncate(time.Second)
	m := Manifest{
		Schema:   Schema,
		Version:  created.Format("2006.01.02-150405"),
		Commit:   commit,
		Created:  created,
		MinTuner: cfg.MinTuner,
		Checks:   len(loaded),
		Retired:  cfg.Retired,
	}
	for _, c := range loaded {
		if slices.Contains(cfg.Retired, c.ID) {
			return nil, fmt.Errorf("%s: %s is retired but %s still defines it", ConfigName, c.ID, c.File)
		}
	}

	// The checks themselves and the LICENSE that covers them; fixtures
	// are for CI and stay out of the pack.
	names := []string{}
	for _, c := range loaded {
		names = append(names, c.File)
	}
	if _, err := fs.Stat(src, "LICENSE"); err == nil {
		names = append(names, "LICENSE")
	}
	slices.Sort(names)

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data, err := fs.ReadFile(src, name)
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(data)),
			ModTime: created, Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	manifest = append(manifest, '\n')
	archive := buf.Bytes()
	sums := fmt.Sprintf("%s  %s\n%s  %s\n", sum(archive), ArchiveName, sum(manifest), ManifestName)
	return &Built{Manifest: m, Files: map[string][]byte{
		ManifestName: manifest, ArchiveName: archive, SumsName: []byte(sums),
	}}, nil
}

// Sign adds the signature of the checksum file, made with key.
func (b *Built) Sign(key ed25519.PrivateKey) {
	b.Files[SigName] = Sign(b.Files[SumsName], key)
}

type config struct {
	MinTuner string   `json:"min_tuner"`
	Retired  []string `json:"retired"` // IDs deleted from checks/; see Manifest.Retired
}

func readConfig(src fs.FS) (config, error) {
	var cfg config
	data, err := fs.ReadFile(src, ConfigName)
	if err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", ConfigName, err)
	}
	if !semver.MatchString(cfg.MinTuner) {
		return cfg, fmt.Errorf("%s: min_tuner %q: want a version like 0.3.0", ConfigName, cfg.MinTuner)
	}
	slices.Sort(cfg.Retired)
	cfg.Retired = slices.Compact(cfg.Retired)
	return cfg, nil
}

var semver = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// ErrRejected marks a pack this binary must not use: a newer schema, a
// newer min_tuner, an unsafe archive, or checks it can't load. Retrying
// won't help until the pack or Tuner changes, unlike a network or checksum
// error, which may be a release caught mid-upload.
var ErrRejected = errors.New("check pack rejected")

// Compatible reports whether this binary (version tuner) may use a pack.
// Dev builds are assumed to be new enough.
func (m Manifest) Compatible(tuner string) error {
	switch {
	case m.Schema != Schema:
		return fmt.Errorf("%w: pack schema %d, this rhythm-tuner reads %d; run: rhythm update", ErrRejected, m.Schema, Schema)
	case !semver.MatchString(m.MinTuner):
		return fmt.Errorf("%w: bad min_tuner %q", ErrRejected, m.MinTuner)
	case m.Version == "" || m.Created.IsZero():
		return fmt.Errorf("%w: manifest has no version", ErrRejected)
	case update.IsRelease(tuner) && update.Newer(tuner, m.MinTuner):
		return fmt.Errorf("%w: pack %s needs rhythm-tuner %s or newer; run: rhythm update",
			ErrRejected, m.Version, strings.TrimPrefix(m.MinTuner, "v"))
	}
	return nil
}

// Open verifies an archive against its manifest and loads its checks.
func Open(m Manifest, archive []byte, tuner string) (fs.FS, []*engine.Check, error) {
	if err := m.Compatible(tuner); err != nil {
		return nil, nil, err
	}
	fsys, err := extract(archive)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	loaded, err := engine.LoadChecks(fsys)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if len(loaded) != m.Checks {
		return nil, nil, fmt.Errorf("%w: manifest lists %d checks, archive has %d", ErrRejected, m.Checks, len(loaded))
	}
	return fsys, loaded, nil
}

// Covers rejects a pack that lacks a check this binary has built in,
// unless the manifest retires it. Without this a pack with fewer checks,
// by mistake or by tampering, would silently scan less than the binary.
func (m Manifest) Covers(loaded []*engine.Check, builtIn []string) error {
	have := map[string]bool{}
	for _, c := range loaded {
		have[c.ID] = true
	}
	var missing []string
	for _, id := range builtIn {
		if !have[id] && !slices.Contains(m.Retired, id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: pack %s lacks built-in checks %s and does not retire them",
			ErrRejected, m.Version, strings.Join(missing, ", "))
	}
	return nil
}

// extract unpacks a tar.gz into memory. Only regular files with clean,
// relative paths are accepted; links, devices, absolute paths and ".."
// fail the whole pack rather than being skipped, since a well-formed pack
// never has them.
func extract(archive []byte) (fs.FS, error) {
	if len(archive) > maxArchive {
		return nil, errors.New("archive too large")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := fstest.MapFS{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		name := hdr.Name
		if hdr.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, `\`) || path.IsAbs(hdr.Name) {
			return nil, fmt.Errorf("archive: unsafe path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("archive: %q is not a regular file", hdr.Name)
		}
		if hdr.Size < 0 || hdr.Size > maxFile {
			return nil, fmt.Errorf("archive: %q is too large", hdr.Name)
		}
		if total += hdr.Size; total > maxTotal || len(out) >= maxFiles {
			return nil, errors.New("archive: too large when unpacked")
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("archive: %q appears twice", name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("archive: %q is truncated", name)
		}
		out[name] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	if len(out) == 0 {
		return nil, errors.New("archive is empty")
	}
	return out, nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// parseSums reads a sha256sum-style file into name → hex digest.
func parseSums(data []byte) map[string]string {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return sums
}

// verify checks data against the digest listed for name.
func verify(sums map[string]string, name string, data []byte) error {
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s: not listed in %s", name, SumsName)
	}
	if got := sum(data); got != want {
		return fmt.Errorf("%s: checksum mismatch (got %s, want %s)", name, got[:12], want[:min(12, len(want))])
	}
	return nil
}
