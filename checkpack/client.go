package checkpack

import (
	"context"
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
)

// ErrNotCached means there's no usable cached pack and the client may not
// fetch one (offline).
var ErrNotCached = errors.New("no check pack cached")

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
type state struct {
	Checked  time.Time `json:"checked"`
	Rejected string    `json:"rejected,omitempty"` // the newest pack, when this binary can't use it
	Manifest *Manifest `json:"manifest,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Archive  []byte    `json:"archive,omitempty"`
}

// Get returns the pack to use. It errors only when there is no usable pack
// at all; a pack returned alongside a failed or rejected refresh carries
// the reason in Warning.
func (c *Client) Get(ctx context.Context) (*Pack, error) {
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	st := c.load()
	if st != nil && (c.Offline || (!c.Force && time.Since(st.Checked) < c.TTL)) {
		return c.open(st)
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
		keep := &state{Checked: time.Now().UTC(), Rejected: err.Error()}
		if st != nil {
			keep.Manifest, keep.SHA256, keep.Archive = st.Manifest, st.SHA256, st.Archive
		}
		_ = c.save(keep)
		if p, perr := c.open(keep); perr == nil {
			return p, nil
		}
		return nil, err
	}
	// Network or checksum trouble: maybe the release is mid-upload, so
	// fall back to the cache without recording a check, and retry next run.
	if st != nil {
		if p, perr := c.open(st); perr == nil {
			p.Stale, p.Warning = true, fmt.Errorf("couldn't refresh the check pack: %w", err)
			return p, nil
		}
	}
	return nil, err
}

// fetch consults the release and returns the state to cache. The small
// manifest is checked first, so an incompatible or unchanged pack costs
// two tiny downloads rather than the archive.
func (c *Client) fetch(ctx context.Context, st *state) (*state, error) {
	rawSums, err := c.get(ctx, SumsName, maxSmall)
	if err != nil {
		return nil, err
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
	now := time.Now().UTC()
	if st != nil && len(st.Archive) > 0 && st.SHA256 == sums[ArchiveName] {
		return &state{Checked: now, Manifest: &m, SHA256: st.SHA256, Archive: st.Archive}, nil
	}

	archive, err := c.get(ctx, ArchiveName, maxArchive)
	if err != nil {
		return nil, err
	}
	if err := verify(sums, ArchiveName, archive); err != nil {
		return nil, err
	}
	if _, _, err := Open(m, archive, c.Tuner); err != nil {
		return nil, err
	}
	return &state{Checked: now, Manifest: &m, SHA256: sum(archive), Archive: archive}, nil
}

// open verifies and loads a cached pack. It runs on every use, not just
// after download: the binary may have changed since the pack was cached.
func (c *Client) open(st *state) (*Pack, error) {
	if st.Manifest == nil || len(st.Archive) == 0 {
		if st.Rejected != "" {
			return nil, errors.New(st.Rejected)
		}
		return nil, ErrNotCached
	}
	if sum(st.Archive) != st.SHA256 {
		return nil, errors.New("cached check pack is corrupt")
	}
	fsys, loaded, err := Open(*st.Manifest, st.Archive, c.Tuner)
	if err != nil {
		return nil, err
	}
	p := &Pack{
		Manifest: *st.Manifest, FS: fsys, Loaded: loaded, Checked: st.Checked,
		Stale: time.Since(st.Checked) > c.TTL,
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
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
	}
	return data, nil
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
