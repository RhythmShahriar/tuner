// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package cache is the on-disk cache for vulnerability data: fresh entries
// are reused and stale ones refreshed. When the network is down the last
// good copy is used.
//
// It follows rhythm's kit/cache (Store, Load, ReadJSON, WriteJSON,
// WriteFile) and adds what Tuner needs on top: a format number in every
// entry, checks that an entry actually holds data, file names that are
// safe on Windows, a bounded in-memory memo for long-running processes, and
// the age of a stale copy for warnings.
package cache

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxMemo is how many lookups a Store remembers in memory.
const DefaultMaxMemo = 2000

// How long a failed lookup is remembered before it is tried again, so a
// long-running process recovers once a data service is back.
const errorMemo = time.Minute

var (
	// ErrOffline means the data isn't cached and the store is offline.
	ErrOffline = errors.New("not cached; offline mode is on")
	// ErrOldFormat means the only cached copy has another format (an older
	// Tuner wrote it) and the store is offline, so it can't be refetched.
	ErrOldFormat = errors.New("cached by an older Tuner; offline mode is on")
)

// Store caches JSON-encodable values under Dir/<kind>/<key>.json.
type Store struct {
	Dir     string        // "" disables the disk cache
	TTL     time.Duration // refresh entries older than this
	Offline bool          // never fetch; use cached data however old
	Force   bool          // always fetch, ignoring the TTL
	Format  int           // entries in another format are treated as missing
	MaxMemo int           // lookups remembered in memory; 0 means DefaultMaxMemo

	mu   sync.Mutex
	memo *lru
}

// Entry is what lands on disk.
type Entry[T any] struct {
	Format  int       `json:"format"`
	Key     string    `json:"key,omitempty"` // what was looked up, as given to Load
	Fetched time.Time `json:"fetched"`
	Data    T         `json:"data"`
}

// Info describes the data Load returned.
type Info struct {
	Stale   bool      // served from a copy older than the TTL
	Fetched time.Time // when the data was fetched
}

// Valid reports whether v is worth serving: a type's own Valid method
// decides when it has one; otherwise any non-zero value is (an empty,
// non-nil list included).
func Valid(v any) bool {
	if vv, ok := v.(interface{ Valid() bool }); ok {
		return vv.Valid()
	}
	rv := reflect.ValueOf(v)
	return rv.IsValid() && !rv.IsZero()
}

// usable reports whether e can be served: format, a fetch time and data.
// A truncated, hand-edited or unwrapped file is not.
func (e *Entry[T]) usable(format int) bool {
	return e.Format == format && !e.Fetched.IsZero() && Valid(e.Data)
}

// Read returns the cached entry for kind/key. ok is false when there is
// none or it can't be served (corrupt, empty or another format); old
// reports a readable entry in another format.
func Read[T any](s *Store, kind, key string) (e Entry[T], ok, old bool) {
	path := s.Path(kind, key)
	if path == "" || ReadJSON(path, &e) != nil {
		return e, false, false
	}
	// Different keys can share a file name (a_b/c and a/b_c both clean
	// up to the same characters), so an entry that names another key is
	// someone else's data. Entries from before keys were stored can't
	// be told apart and are trusted.
	if e.Key != "" && e.Key != key {
		return Entry[T]{}, false, false
	}
	if e.usable(s.Format) {
		return e, true, false
	}
	return e, false, e.Format != s.Format && Valid(e.Data)
}

// Write stores data for kind/key as fetched now. A store without a
// directory writes nothing.
func Write[T any](s *Store, kind, key string, data T) error {
	path := s.Path(kind, key)
	if path == "" {
		return nil
	}
	return WriteJSON(path, Entry[T]{Format: s.Format, Key: key, Fetched: time.Now().UTC(), Data: data})
}

// Load returns fresh cached data for kind/key, else fetches and stores it,
// else falls back to stale cached data. Repeated and concurrent calls for
// one key share a single lookup; a successful one is remembered for the
// TTL, a failed one for a minute. A forced refresh reports a failed fetch
// instead of falling back.
func Load[T any](s *Store, ctx context.Context, kind, key string, fetch func(context.Context) (T, error)) (T, Info, error) {
	m := s.lookup(kind + "/" + key)
	m.once.Do(func() {
		defer m.done.Store(true)
		cached, have, old := Read[T](s, kind, key)
		info := Info{Stale: time.Since(cached.Fetched) > s.TTL, Fetched: cached.Fetched}
		switch {
		case have && s.Offline:
			m.v, m.info = cached.Data, info
			return
		case have && !s.Force && !info.Stale:
			m.v, m.info = cached.Data, info
			return
		case s.Offline && old:
			m.err = ErrOldFormat
			return
		case s.Offline:
			m.err = ErrOffline
			return
		}
		data, err := fetch(ctx)
		if err != nil {
			if have && !s.Force {
				m.v, m.info = cached.Data, Info{Stale: true, Fetched: cached.Fetched}
				return
			}
			m.err = err
			return
		}
		m.v, m.info = data, Info{Fetched: time.Now()}
		_ = Write(s, kind, key, data)
	})
	if m.err != nil {
		var zero T
		return zero, Info{}, m.err
	}
	return m.v.(T), m.info, nil
}

// Entries calls fn with the kind and key of every entry under the store's
// directory, for refreshing them all. The key is the one stored in the
// entry, or the file name for entries that predate stored keys.
func (s *Store) Entries(fn func(kind, key string) error) error {
	if s.Dir == "" {
		return nil
	}
	err := filepath.WalkDir(s.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		rel, err := filepath.Rel(s.Dir, filepath.Dir(p))
		if err != nil {
			return err
		}
		var e struct {
			Key string `json:"key"`
		}
		_ = ReadJSON(p, &e)
		if e.Key == "" {
			e.Key = strings.TrimSuffix(d.Name(), ".json")
		}
		return fn(filepath.ToSlash(rel), e.Key)
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Path is the file kind/key is cached in, or "" without a directory or a
// usable key.
func (s *Store) Path(kind, key string) string {
	name := SafeName(key)
	if s.Dir == "" || name == "" {
		return ""
	}
	return filepath.Join(s.Dir, filepath.FromSlash(kind), name+".json")
}

var unsafeKey = regexp.MustCompile(`[^A-Za-z0-9._@~-]`)

// Windows reserves these device names, with or without an extension and in
// any case: a cache file called con.json can't be created there.
var reserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)

// SafeName turns a key into a file name (without the extension) that is
// valid on every OS: "/" becomes "~", other unsafe characters become "_"
// and a Windows device name gets a trailing "_" (con → con_). It returns
// "" for keys that can't name a file, like "" and "..".
//
// "/" gets its own character because Composer names (vendor/package)
// may hold "_" but never "~": with "_" for both, foo_bar/baz and
// foo/bar_baz would share a file.
func SafeName(key string) string {
	if key == "" || key == "." || key == ".." {
		return ""
	}
	name := unsafeKey.ReplaceAllString(strings.ReplaceAll(key, "/", "~"), "_")
	if stem, rest, dotted := strings.Cut(name, "."); reserved.MatchString(stem) {
		name = stem + "_"
		if dotted {
			name += "." + rest
		}
	}
	return name
}

// ReadJSON decodes the JSON file at path into v.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // callers build paths from their own cache dir and a sanitized key
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// WriteJSON writes v as JSON atomically (temp file + rename), creating the
// directory, so a crash never leaves a torn file.
func WriteJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFile(path, data)
}

// WriteFile writes data atomically, creating the directory.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
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
	return os.Rename(tmp.Name(), path)
}

// --- in-memory memo ---

type memo struct {
	once sync.Once
	done atomic.Bool
	at   time.Time
	v    any
	info Info
	err  error
}

// lookup returns the shared lookup for id, starting a new one when there
// is none or the old one has expired.
func (s *Store) lookup(id string) *memo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.memo == nil {
		s.memo = newLRU(s.MaxMemo)
	}
	if m := s.memo.get(id); m != nil && !m.expired(s.TTL) {
		return m
	}
	m := &memo{at: time.Now()}
	s.memo.put(id, m)
	return m
}

// expired reports whether a finished lookup should be done again: in a
// long-running process, a success after the TTL and a failure after a
// minute. A lookup still in flight never expires.
func (m *memo) expired(ttl time.Duration) bool {
	if !m.done.Load() {
		return false
	}
	keep := ttl
	if m.err != nil {
		keep = errorMemo
	}
	return keep > 0 && time.Since(m.at) > keep
}

// lru keeps the most recently used lookups, up to max.
type lru struct {
	max   int
	order *list.List // front is most recent; values are *lruItem
	items map[string]*list.Element
}

type lruItem struct {
	id string
	m  *memo
}

func newLRU(max int) *lru {
	if max <= 0 {
		max = DefaultMaxMemo
	}
	return &lru{max: max, order: list.New(), items: map[string]*list.Element{}}
}

func (l *lru) get(id string) *memo {
	e, ok := l.items[id]
	if !ok {
		return nil
	}
	l.order.MoveToFront(e)
	return e.Value.(*lruItem).m
}

func (l *lru) put(id string, m *memo) {
	if e, ok := l.items[id]; ok {
		e.Value.(*lruItem).m = m
		l.order.MoveToFront(e)
		return
	}
	l.items[id] = l.order.PushFront(&lruItem{id: id, m: m})
	for l.order.Len() > l.max {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.items, oldest.Value.(*lruItem).id)
	}
}

func (l *lru) len() int { return l.order.Len() }
