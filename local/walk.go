// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // WordPress publishes MD5 checksums for core files; this compares, it doesn't protect
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/tuner/engine"
)

// One walk of the project feeds every check that looks at files. Each
// check is a visitor with its own root and its own folders to skip; a
// folder is only skipped when no visitor wants it. Files are read once,
// by a pool of workers. The one exception is the few files WordPress
// detection reads before the walk (version.php, wp-config.php, plugin
// and must-use plugin headers, theme style.css): a rule may read them
// again. The bytes are shared by every visitor that
// asked for them.

// need says what a visitor wants from a file.
type need uint8

const (
	needVisit  need = 1 << iota // see the file, without reading it
	needHead                    // its first maxRead bytes
	needMD5                     // the MD5 of the whole file
	needSHA256                  // the SHA-256 of the whole file
)

// entry is a file or folder the walk meets.
type entry struct {
	path string      // absolute
	name string      // base name
	typ  fs.FileMode // type bits from the folder listing
}

// regular reports whether e is a regular file. Links aren't followed in
// the walk, so a link to a file isn't one.
func (e *entry) regular() bool { return e.typ.IsRegular() }

// fileData is what the walk read of a file, shared by the visitors that
// asked for it.
type fileData struct {
	size        int64  // -1 when unknown
	head        []byte // nil unless asked for, or when the file couldn't be read
	md5, sha256 string // lower-case hex, when asked for and read
	lowered     []byte
}

// lower returns head in lower case, computed once per file so every
// visitor's cheap bytes.Contains prefilter shares one copy.
func (f *fileData) lower() []byte {
	if f.lowered == nil && f.head != nil {
		f.lowered = bytes.ToLower(f.head)
	}
	return f.lowered
}

// visitor is one check that looks at files in the tree.
type visitor interface {
	// root is the folder it covers. Entries outside it aren't shown to it.
	root() string
	// enter is called for each folder below root, from the walk's own
	// goroutine. false skips the folder's contents for this visitor.
	enter(e *entry) bool
	// need is called for each file below root, from the walk's own
	// goroutine. 0 leaves the file out for this visitor.
	need(e *entry) need
	// visit is called with what was read, from a worker goroutine, so it
	// must guard its own state.
	visit(e *entry, f *fileData)
	// checks is how many checks the visitor counts in the summary.
	checks() int
}

// walkTree walks the project root once for every visitor. It stops at
// MaxEntries entries, warns once about unreadable entries, skips
// FIFOs, sockets and devices with a warning and leaves out SkipDirs.
func (s *scan) walkTree(ctx context.Context, vs ...visitor) {
	for _, v := range vs {
		if fi, err := os.Stat(v.root()); err == nil && fi.IsDir() {
			s.checks += v.checks()
		}
	}
	type job struct {
		e    entry
		mask uint64 // the visitors that want it
		need need
	}
	jobs := make(chan job, 256)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for j := range jobs {
				if ctx.Err() != nil {
					continue // drain
				}
				f := s.load(&j.e, j.need)
				if ctx.Err() != nil {
					continue // f may be cut short: don't judge it
				}
				for i, v := range vs {
					if j.mask&(1<<i) != 0 {
						v.visit(&j.e, f)
					}
				}
			}
		})
	}

	// active holds, per folder, the visitors still interested in it.
	active := map[string]uint64{}
	underRoot := func(dir string) bool {
		return slices.ContainsFunc(vs, func(v visitor) bool {
			return strings.HasPrefix(v.root(), dir+string(filepath.Separator))
		})
	}
	skip := map[string]bool{}
	for _, d := range s.opts.SkipDirs {
		if !filepath.IsAbs(d) {
			d = filepath.Join(s.root, d)
		}
		skip[filepath.Clean(d)] = true
	}
	entries := 0
	var unreadable []string
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if active[p] != 0 || active[filepath.Dir(p)] != 0 || p == s.root {
				unreadable = append(unreadable, s.rel(p)+": "+errText(err))
			}
			return nil // keep going
		}
		if entries++; entries > s.opts.MaxEntries {
			s.warn("stopped after %s entries, so the file checks are incomplete; scan a smaller folder to cover the rest", thousands(s.opts.MaxEntries))
			s.stoppedBy = "budget"
			return fs.SkipAll
		}
		if entries%1024 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		e := entry{path: p, name: d.Name(), typ: d.Type()}
		parent := active[filepath.Dir(p)]
		if d.IsDir() {
			if skip[p] && p != s.root {
				return fs.SkipDir
			}
			var mask uint64
			for i, v := range vs {
				if p == v.root() || (parent&(1<<i) != 0 && v.enter(&e)) {
					mask |= 1 << i
				}
			}
			if mask == 0 && !underRoot(p) {
				return fs.SkipDir
			}
			active[p] = mask
			return nil
		}
		if parent == 0 {
			return nil
		}
		// FIFOs, sockets and devices can block a read forever.
		if special := fs.ModeNamedPipe | fs.ModeSocket | fs.ModeDevice | fs.ModeCharDevice; e.typ&special != 0 {
			s.skip(p, fileKind(e.typ))
			return nil
		}
		var j job
		for i, v := range vs {
			if parent&(1<<i) != 0 {
				if n := v.need(&e); n != 0 {
					j.mask |= 1 << i
					j.need |= n
				}
			}
		}
		if j.mask == 0 {
			return nil
		}
		j.e = e
		select {
		case jobs <- j:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(jobs)
	wg.Wait()
	if err != nil && ctx.Err() == nil {
		s.warn("walking %s: %v", s.rel(s.root), err)
	}
	if len(unreadable) > 0 {
		s.warn("couldn't read %d entr%s, so the file checks may be incomplete (first: %s)",
			len(unreadable), plural2(len(unreadable), "y", "ies"), unreadable[0])
	}
}

// load reads what n asks for, opening the file at most once.
func (s *scan) load(e *entry, n need) *fileData {
	f := &fileData{size: -1}
	if !e.regular() || n&(needHead|needMD5|needSHA256) == 0 {
		if fi, err := os.Lstat(e.path); err == nil {
			f.size = fi.Size()
		}
		return f
	}
	var md, sh hash.Hash
	var hs []hash.Hash
	if n&needMD5 != 0 {
		md = md5.New() //nolint:gosec // see the import
		hs = append(hs, md)
	}
	if n&needSHA256 != 0 {
		sh = sha256.New()
		hs = append(hs, sh)
	}
	if len(hs) > 0 && s.ctx != nil {
		// Every hash sees the same writes, so watching one is enough.
		hs[0] = &ctxHash{Hash: hs[0], ctx: s.ctx}
	}
	read := s.opts.read
	if read == nil {
		read = readFile
	}
	head, size, err := read(e.path, maxRead, hs...)
	f.size = size
	if err != nil {
		if nr := (*notRegularError)(nil); errors.As(err, &nr) {
			s.skip(e.path, nr.kind) // swapped for a FIFO since the listing
		}
		return f
	}
	if n&needHead != 0 {
		f.head = head
	}
	if md != nil {
		f.md5 = hex.EncodeToString(md.Sum(nil))
	}
	if sh != nil {
		f.sha256 = hex.EncodeToString(sh.Sum(nil))
	}
	return f
}

// ctxHash is a hash.Hash whose writes fail once ctx is done, so hashing
// a multi-GB file stops on cancellation or --max-time instead of
// finishing the file. It checks ctx once per hashCheckEvery bytes.
type ctxHash struct {
	hash.Hash
	ctx     context.Context
	written int
}

const hashCheckEvery = 4 << 20

func (h *ctxHash) Write(p []byte) (int, error) {
	if h.written += len(p); h.written >= hashCheckEvery {
		h.written = 0
		if err := h.ctx.Err(); err != nil {
			return 0, err
		}
	}
	return h.Hash.Write(p)
}

// collector gathers a visitor's findings from the worker goroutines.
type collector struct {
	mu    sync.Mutex
	found []engine.Finding
}

func (c *collector) add(fs ...engine.Finding) {
	c.mu.Lock()
	c.found = append(c.found, fs...)
	c.mu.Unlock()
}

// findings returns what was found in a stable order: workers finish in
// any order; reports and hooks should not.
func (c *collector) findings() []engine.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := slices.Clone(c.found)
	sortFindings(out)
	return out
}
