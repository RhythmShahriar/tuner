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
//
// Besides checks, a pack may carry fingerprint data (data/*.json, such as
// the REST namespace to plugin map) and local scan rules (local/*.yaml),
// so both can be refreshed without a release too. They are data as well
// and have their own size and count limits.
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

// Folders in a pack that hold data rather than checks, and their limits.
// Fingerprint data is a handful of lookup tables of tens of KB; local
// rules are small YAML files, but there may be hundreds of them.
const (
	DataDir  = "data"  // fingerprint data, <name>.json
	LocalDir = "local" // local scan rules, <name>.yaml

	maxDataFile   = 512 << 10
	maxDataFiles  = 32
	maxDataTotal  = 8 << 20
	maxLocalFile  = 256 << 10
	maxLocalFiles = 1000
)

// Extras are the files a pack carries next to the checks. Either may be
// nil. Only *.json at the root of Data and *.yaml (not _test.yaml) at the
// root of Local are packed.
type Extras struct {
	Data  fs.FS // fingerprint/data
	Local fs.FS // local/rules
}

var (
	dataName  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.json$`)
	localName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.yaml$`)
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
	Data     []string  `json:"data,omitempty"`    // fingerprint data files under data/
	Local    int       `json:"local,omitempty"`   // local scan rules under local/
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
	return BuildWith(src, Extras{}, commit, created)
}

// BuildWith is Build with fingerprint data and local rules added.
func BuildWith(src fs.FS, x Extras, commit string, created time.Time) (*Built, error) {
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
		if top, _, _ := strings.Cut(c.File, "/"); top == DataDir || top == LocalDir {
			return nil, fmt.Errorf("%s: the %s/ folder is reserved for pack data; move the check", c.File, top)
		}
	}

	// The checks themselves and the LICENSE that covers them; fixtures
	// are for CI and stay out of the pack.
	files := map[string][]byte{}
	for _, c := range loaded {
		if files[c.File], err = fs.ReadFile(src, c.File); err != nil {
			return nil, err
		}
	}
	if data, err := fs.ReadFile(src, "LICENSE"); err == nil {
		files["LICENSE"] = data
	}
	if m.Data, err = addExtras(files, x.Data, DataDir, "*.json"); err != nil {
		return nil, err
	}
	local, err := addExtras(files, x.Local, LocalDir, "*.yaml")
	if err != nil {
		return nil, err
	}
	m.Local = len(local)
	if err := checkExtras(files); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data := files[name]
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

// addExtras copies the files matching pattern at the root of src into
// files under dir and returns their base names. Fixtures stay out, as for
// checks.
func addExtras(files map[string][]byte, src fs.FS, dir, pattern string) ([]string, error) {
	if src == nil {
		return nil, nil
	}
	names, err := fs.Glob(src, pattern)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, name := range names {
		if engine.IsFixture(name) {
			continue
		}
		data, err := fs.ReadFile(src, name)
		if err != nil {
			return nil, err
		}
		files[dir+"/"+name] = data
		out = append(out, name)
	}
	return out, nil
}

// checkExtras applies the data/ and local/ rules to a pack's files, at
// build time and again when a pack is unpacked: flat folders, plain file
// names, valid JSON, and the size and count limits.
func checkExtras(files map[string][]byte) error {
	var dataFiles, localFiles, dataTotal int
	for name, data := range files {
		dir, base, nested := strings.Cut(name, "/")
		switch {
		case !nested || dir != DataDir && dir != LocalDir:
			continue
		case dir == DataDir:
			dataFiles++
			dataTotal += len(data)
			switch {
			case !dataName.MatchString(base):
				return fmt.Errorf("%s: data files are <name>.json directly under %s/", name, DataDir)
			case len(data) > maxDataFile:
				return fmt.Errorf("%s: larger than %d KB", name, maxDataFile>>10)
			case !json.Valid(data):
				return fmt.Errorf("%s: not valid JSON", name)
			}
		default:
			localFiles++
			switch {
			case !localName.MatchString(base):
				return fmt.Errorf("%s: local rules are <name>.yaml directly under %s/", name, LocalDir)
			case len(data) > maxLocalFile:
				return fmt.Errorf("%s: larger than %d KB", name, maxLocalFile>>10)
			}
		}
	}
	switch {
	case dataFiles > maxDataFiles:
		return fmt.Errorf("%s/: %d files, at most %d", DataDir, dataFiles, maxDataFiles)
	case dataTotal > maxDataTotal:
		return fmt.Errorf("%s/: larger than %d MB in all", DataDir, maxDataTotal>>20)
	case localFiles > maxLocalFiles:
		return fmt.Errorf("%s/: %d files, at most %d", LocalDir, localFiles, maxLocalFiles)
	}
	return nil
}

// checksOnly hides data/ and local/, so engine.LoadChecks sees checks only.
func checksOnly(m fstest.MapFS) fstest.MapFS {
	out := fstest.MapFS{}
	for name, f := range m {
		if top, _, _ := strings.Cut(name, "/"); top != DataDir && top != LocalDir {
			out[name] = f
		}
	}
	return out
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

// Open verifies an archive against its manifest and loads its checks. The
// returned filesystem is the whole pack, data/ and local/ included.
func Open(m Manifest, archive []byte, tuner string) (fs.FS, []*engine.Check, error) {
	if err := m.Compatible(tuner); err != nil {
		return nil, nil, err
	}
	fsys, err := extract(archive)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	loaded, err := engine.LoadChecks(checksOnly(fsys))
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
func extract(archive []byte) (fstest.MapFS, error) {
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
	files := make(map[string][]byte, len(out))
	for name, f := range out {
		files[name] = f.Data
	}
	if err := checkExtras(files); err != nil {
		return nil, fmt.Errorf("archive: %w", err)
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
