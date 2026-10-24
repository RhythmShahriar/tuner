// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checkpack

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

const (
	// DefaultBase is the rolling release CI publishes packs to.
	DefaultBase = "https://github.com/RhythmShahriar/tuner/releases/download/checks-latest"
	DefaultTTL  = 24 * time.Hour

	// Backoff is how long a failed refresh is not retried. Without it a
	// host that hangs or a firewall that drops the traffic would delay
	// every scan by the whole fetch timeout.
	Backoff = time.Hour
)

// ErrNotCached means there's no usable cached pack and the client may not
// fetch one (offline).
var ErrNotCached = errors.New("no check pack cached")

// ErrUnreachable wraps network failures: the release could not be reached
// or stopped answering, as opposed to answering with something wrong.
var ErrUnreachable = errors.New("check pack host unreachable")

// Client fetches and caches check packs, like vulns.Client does for
// vulnerability data: a fresh cache is used as is, a stale one is
// refreshed, and when the refresh fails the stale copy is still used.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	BaseURL   string        // where the release assets live; "" means DefaultBase
	CacheDir  string        // "" disables the disk cache
	TTL       time.Duration // consult the release after this long; 0 means DefaultTTL
	Offline   bool          // never fetch; use the cached pack however old
	Force     bool          // always consult the release (rhythm tuner update)
	Tuner     string        // the running version, checked against min_tuner

	// Keys verify the signature on the checksum file; nil means the keys
	// compiled into this build.
	Keys []ed25519.PublicKey
	// Insecure skips the signature check, for private forks that publish
	// their own packs (TUNER_CHECKS_INSECURE=1). Checksums still apply.
	Insecure bool
	// BuiltIn lists the IDs of the binary's own checks. A pack must carry
	// each one or retire it in its manifest.
	BuiltIn []string
	// Now is the clock; nil means time.Now. Tests use it to expire the
	// TTL and the back-off.
	Now func() time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// Pack is a verified pack, ready to scan with.
type Pack struct {
	Manifest
	FS      fs.FS
	Loaded  []*engine.Check // the pack's checks, parsed
	Checked time.Time       // when the release was last consulted
	Stale   bool            // older than the TTL: offline, or the refresh failed
	Warning error           // why a newer pack, if any, isn't the one returned
}

// Data returns the fingerprint data file name (e.g. rest-namespaces.json)
// from the pack, or false when the pack has none, in which case the copy
// built into the binary applies.
func (p *Pack) Data(name string) ([]byte, bool) {
	if p == nil || p.FS == nil || !dataName.MatchString(name) {
		return nil, false
	}
	data, err := fs.ReadFile(p.FS, DataDir+"/"+name)
	return data, err == nil
}

// LocalRules returns the pack's local scan rules as a filesystem of
// <name>.yaml files, or nil when the pack has none, so the rules built
// into the binary apply.
func (p *Pack) LocalRules() fs.FS {
	if p == nil || p.FS == nil {
		return nil
	}
	if names, _ := fs.Glob(p.FS, LocalDir+"/*.yaml"); len(names) == 0 {
		return nil
	}
	sub, err := fs.Sub(p.FS, LocalDir)
	if err != nil {
		return nil
	}
	return sub
}

// DefaultCacheDir is ~/.cache/rhythm/tuner/checks (or the OS equivalent).
func DefaultCacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "rhythm", "tuner", "checks")
}

// state is the cache file. The archive lives inside it so the pack and its
// manifest are replaced in one atomic write.
//
// The signed sums travel with the archive, so the signature is checked
// again on every use: a key removed from a later build stops trusting a
// pack cached under it.
type state struct {
	Checked  time.Time `json:"checked"`
	Failed   time.Time `json:"failed,omitzero"`    // last refresh that failed; no retry until Backoff has passed
	Rejected string    `json:"rejected,omitempty"` // the newest pack, when this binary can't use it
	Manifest *Manifest `json:"manifest,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Sums     []byte    `json:"sums,omitempty"` // checks-sha256.txt as signed
	Sig      []byte    `json:"sig,omitempty"`  // its signature
	Archive  []byte    `json:"archive,omitempty"`
}

// keep copies the pack part of st, if any, into a new state.
func (st *state) keep(next *state) *state {
	if st != nil {
		next.Manifest, next.SHA256, next.Sums, next.Sig, next.Archive = st.Manifest, st.SHA256, st.Sums, st.Sig, st.Archive
	}
	return next
}

// Get returns the pack to use. It errors only when there is no usable pack
// at all; a pack returned alongside a failed or rejected refresh carries
// the reason in Warning.
func (c *Client) Get(ctx context.Context) (*Pack, error) {
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	if c.Keys == nil {
		keys, err := TrustedKeys()
		if err != nil {
			return nil, err
		}
		c.Keys = keys
	}
	if len(c.Keys) == 0 && !c.Insecure {
		return nil, ErrNoTrustedKeys
	}
	st := c.load()
	now := c.now()
	backingOff := st != nil && !c.Force && now.Sub(st.Failed) < Backoff
	if st != nil && (c.Offline || backingOff || (!c.Force && now.Sub(st.Checked) < c.TTL)) {
		p, err := c.open(st)
		// A pack cached before packs were signed, or under a key this
		// build no longer trusts, is replaced rather than kept for a day.
		if c.Offline || backingOff || !errors.Is(err, errSignature) {
			if backingOff && err != nil {
				// Already reported when the refresh failed; quiet until
				// the back-off ends.
				return nil, ErrNotCached
			}
			return p, err
		}
	}
	if c.Offline {
		return nil, ErrNotCached
	}

	next, err := c.fetch(ctx, st)
	switch {
	case err == nil:
		_ = c.save(next)
		return c.open(next)
	case errors.Is(err, ErrRejected):
		// Remember the verdict so every scan doesn't download the same
		// pack again; keep the last good one.
		keep := st.keep(&state{Checked: now, Rejected: err.Error()})
		_ = c.save(keep)
		if p, perr := c.open(keep); perr == nil {
			return p, nil
		}
		return nil, err
	}
	// Network, checksum or signature trouble: maybe the release is
	// mid-upload or the network is down. Fall back to the cache without
	// recording a check and back off before trying again.
	failed := &state{Failed: now}
	if st != nil {
		failed = st.keep(&state{Checked: st.Checked, Rejected: st.Rejected, Failed: now})
	}
	_ = c.save(failed)
	if st != nil {
		if p, perr := c.open(st); perr == nil {
			p.Stale, p.Warning = true, fmt.Errorf("couldn't refresh the check pack: %w", err)
			return p, nil
		}
	}
	return nil, err
}

// fetch consults the release and returns the state to cache. The
// signature is checked before anything in the sums is believed and the
// small manifest before the archive, so an incompatible or unchanged pack
// costs three tiny downloads rather than the archive.
func (c *Client) fetch(ctx context.Context, st *state) (*state, error) {
	rawSums, err := c.get(ctx, SumsName, maxSmall)
	if err != nil {
		return nil, err
	}
	var sig []byte
	if !c.Insecure {
		if sig, err = c.get(ctx, SigName, maxSmall); err != nil {
			return nil, fmt.Errorf("%w: %w", errSignature, err)
		}
		if err := verifySig(rawSums, sig, c.Keys); err != nil {
			return nil, err
		}
	}
	sums := parseSums(rawSums)
	rawManifest, err := c.get(ctx, ManifestName, maxSmall)
	if err != nil {
		return nil, err
	}
	if err := verify(sums, ManifestName, rawManifest); err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrRejected, ManifestName, err)
	}
	if err := m.Compatible(c.Tuner); err != nil {
		return nil, err
	}
	now := c.now()
	next := &state{Checked: now, Manifest: &m, Sums: rawSums, Sig: sig}
	if st != nil && len(st.Archive) > 0 && st.SHA256 == sums[ArchiveName] {
		next.SHA256, next.Archive = st.SHA256, st.Archive
		if _, err := c.verified(next); err != nil {
			return nil, err
		}
		return next, nil
	}

	archive, err := c.get(ctx, ArchiveName, maxArchive)
	if err != nil {
		return nil, err
	}
	if err := verify(sums, ArchiveName, archive); err != nil {
		return nil, err
	}
	next.SHA256, next.Archive = sum(archive), archive
	if _, err := c.verified(next); err != nil {
		return nil, err
	}
	return next, nil
}

// verified checks a pack's signature and contents and loads its checks.
// It runs on every use, not just after download: the binary may have
// changed since the pack was cached, along with its trusted keys and
// built-in checks.
func (c *Client) verified(st *state) (*opened, error) {
	if sum(st.Archive) != st.SHA256 {
		return nil, errors.New("cached check pack is corrupt")
	}
	if !c.Insecure {
		if err := verifySig(st.Sums, st.Sig, c.Keys); err != nil {
			return nil, err
		}
		if parseSums(st.Sums)[ArchiveName] != st.SHA256 {
			return nil, fmt.Errorf("%w: %s does not list this archive", errSignature, SumsName)
		}
	}
	fsys, loaded, err := Open(*st.Manifest, st.Archive, c.Tuner)
	if err != nil {
		return nil, err
	}
	if err := st.Manifest.Covers(loaded, c.BuiltIn); err != nil {
		return nil, err
	}
	return &opened{fsys, loaded}, nil
}

type opened struct {
	fsys   fs.FS
	loaded []*engine.Check
}

// open verifies and loads a cached pack.
func (c *Client) open(st *state) (*Pack, error) {
	if st.Manifest == nil || len(st.Archive) == 0 {
		if st.Rejected != "" {
			return nil, errors.New(st.Rejected)
		}
		return nil, ErrNotCached
	}
	o, err := c.verified(st)
	if err != nil {
		return nil, err
	}
	p := &Pack{
		Manifest: *st.Manifest, FS: o.fsys, Loaded: o.loaded, Checked: st.Checked,
		Stale: c.now().Sub(st.Checked) > c.TTL,
	}
	if st.Rejected != "" {
		p.Warning = errors.New(st.Rejected)
	}
	return p, nil
}

func (c *Client) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBase
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnreachable, name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
	}
	return data, nil
}

// Cached reports whether a pack is cached, usable or not. Callers use it
// to wait less for a refresh when there is something to fall back on.
func (c *Client) Cached() bool {
	st := c.load()
	return st != nil && len(st.Archive) > 0
}

func (c *Client) path() string {
	if c.CacheDir == "" {
		return ""
	}
	return filepath.Join(c.CacheDir, "pack.json")
}

// load reads the cache; a missing or unreadable cache is no cache.
func (c *Client) load() *state {
	p := c.path()
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p) //nolint:gosec // a fixed name in the cache dir
	if err != nil {
		return nil
	}
	var st state
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	return &st
}

// save writes atomically so a crash never leaves a torn cache file.
func (c *Client) save(st *state) error {
	p := c.path()
	if p == "" {
		return nil
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}
