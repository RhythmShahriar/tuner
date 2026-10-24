// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/vulns/cache"
)

// store keeps targets in memory and in targets.json; each scan is in
// scans/<id>.json. Scans still queued or running are also in memory;
// finished ones are read from disk, so a server that runs for months
// holds only its active scans.
type store struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	targets map[string]*Target
	active  map[string]*scan
}

var idPattern = regexp.MustCompile(`^[a-z]_[0-9a-f]{12,32}$`)

func openStore(dir string, now func() time.Time) (*store, []string, error) {
	if err := os.MkdirAll(filepath.Join(dir, "scans"), 0o700); err != nil {
		return nil, nil, err
	}
	st := &store{dir: dir, now: now, targets: map[string]*Target{}, active: map[string]*scan{}}
	var list []*Target
	if err := cache.ReadJSON(st.targetsFile(), &list); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	for _, t := range list {
		st.targets[t.ID] = t
	}
	interrupted, err := st.markInterrupted()
	return st, interrupted, err
}

func (st *store) targetsFile() string { return filepath.Join(st.dir, "targets.json") }

func (st *store) scanFile(id string) string { return filepath.Join(st.dir, "scans", id+".json") }

// markInterrupted rewrites scans a previous server left queued or
// running: they will never finish now.
func (st *store) markInterrupted() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(st.dir, "scans"))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !idPattern.MatchString(id) {
			continue
		}
		var rec scanRecord
		if err := cache.ReadJSON(st.scanFile(id), &rec); err != nil {
			continue
		}
		if rec.Status != statusQueued && rec.Status != statusRunning {
			continue
		}
		rec.Error = "the server stopped while the scan was " + rec.Status
		rec.Status = statusInterrupted
		t := st.now().UTC()
		rec.Finished = &t
		if err := cache.WriteJSON(st.scanFile(id), rec); err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// saveTargets writes targets.json; the caller holds st.mu.
func (st *store) saveTargets() error {
	list := make([]*Target, 0, len(st.targets))
	for _, t := range st.targets {
		list = append(list, t)
	}
	slices.SortFunc(list, func(a, b *Target) int { return a.Created.Compare(b.Created) })
	return cache.WriteJSON(st.targetsFile(), list)
}

// target returns a copy of the target with id.
func (st *store) target(id string) (Target, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.targets[id]
	if !ok {
		return Target{}, false
	}
	return *t, true
}

// addTarget stores a new target, or returns the one already registered
// for the same URL (created false).
func (st *store) addTarget(t *Target) (_ Target, created bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, old := range st.targets {
		if old.URL == t.URL {
			return *old, false, nil
		}
	}
	st.targets[t.ID] = t
	if err := st.saveTargets(); err != nil {
		delete(st.targets, t.ID)
		return Target{}, false, err
	}
	return *t, true, nil
}

// updateTarget applies fn to the stored target and saves.
func (st *store) updateTarget(id string, fn func(*Target)) (Target, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.targets[id]
	if !ok {
		return Target{}, os.ErrNotExist
	}
	fn(t)
	return *t, st.saveTargets()
}

func (st *store) deleteTarget(id string) (bool, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.targets[id]; !ok {
		return false, nil
	}
	delete(st.targets, id)
	return true, st.saveTargets()
}

func (st *store) listTargets() []Target {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Target, 0, len(st.targets))
	for _, t := range st.targets {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b Target) int { return a.Created.Compare(b.Created) })
	return out
}

// saveScan writes the scan's record.
func (st *store) saveScan(sc *scan) error {
	return cache.WriteJSON(st.scanFile(sc.id), sc.record())
}

func (st *store) setActive(sc *scan) {
	st.mu.Lock()
	st.active[sc.id] = sc
	st.mu.Unlock()
}

func (st *store) dropActive(id string) {
	st.mu.Lock()
	delete(st.active, id)
	st.mu.Unlock()
}

// scan returns the active scan with id, or a finished one rebuilt from
// its file.
func (st *store) scan(id string) (*scan, bool) {
	if !idPattern.MatchString(id) {
		return nil, false
	}
	st.mu.Lock()
	sc, ok := st.active[id]
	st.mu.Unlock()
	if ok {
		return sc, true
	}
	var rec scanRecord
	if err := cache.ReadJSON(st.scanFile(id), &rec); err != nil {
		return nil, false
	}
	return scanFromRecord(rec), true
}
