// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// treeOp builds or changes the work folder. Exactly one action is set:
//
//	copy: wp            copy the scenario's wp/ folder (to: names the destination)
//	write: site/.env    write content (mode: octal permissions)
//	mkdir: site/x       make a folder (mode: octal permissions)
//	remove: site/x      remove a file or folder
//	symlink: site/l     a symlink to target
//	mkfifo: site/f      a named pipe (not on Windows)
//	socket: site/s      a listening unix socket, open for the scenario (not on Windows)
//	chmod: site/x       set mode
//
// Paths are relative to the work folder, use forward slashes and may hold
// {{...}} placeholders and YAML escapes such as "\e" for control bytes.
type treeOp struct {
	Copy    string `yaml:"copy"`
	To      string `yaml:"to"`
	Write   string `yaml:"write"`
	Content string `yaml:"content"`
	Mkdir   string `yaml:"mkdir"`
	Remove  string `yaml:"remove"`
	Symlink string `yaml:"symlink"`
	Target  string `yaml:"target"`
	Mkfifo  string `yaml:"mkfifo"`
	Socket  string `yaml:"socket"`
	Chmod   string `yaml:"chmod"`
	Mode    string `yaml:"mode"`
}

type treeRunner struct {
	dir, work string
	expand    func(string) string
	closers   []io.Closer
	chmodded  []string // restored on close so TempDir cleanup can remove them
}

// path resolves p in the work folder; {{home}} and {{cache}} paths are
// already absolute.
func (r *treeRunner) path(p string) string {
	p = filepath.FromSlash(r.expand(p))
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(r.work, p)
}

func (r *treeRunner) apply(ops []treeOp) error {
	for _, op := range ops {
		if err := r.one(op); err != nil {
			return err
		}
	}
	return nil
}

func (r *treeRunner) one(op treeOp) error {
	mode := func(def fs.FileMode) (fs.FileMode, error) {
		if op.Mode == "" {
			return def, nil
		}
		m, err := strconv.ParseUint(op.Mode, 8, 32)
		return fs.FileMode(m), err
	}
	switch {
	case op.Copy != "":
		to := op.To
		if to == "" {
			to = op.Copy
		}
		return copyTree(filepath.Join(r.dir, filepath.FromSlash(op.Copy)), r.path(to))
	case op.Write != "":
		m, err := mode(0o644)
		if err != nil {
			return err
		}
		p := r.path(op.Write)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(r.expand(op.Content)), m)
	case op.Mkdir != "":
		m, err := mode(0o755)
		if err != nil {
			return err
		}
		p := r.path(op.Mkdir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
		return r.chmod(p, m)
	case op.Remove != "":
		return os.RemoveAll(r.path(op.Remove))
	case op.Symlink != "":
		target := r.expand(op.Target)
		if !filepath.IsAbs(target) && !strings.HasPrefix(target, "/") {
			target = filepath.FromSlash(target)
		}
		p := r.path(op.Symlink)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.Symlink(target, p)
	case op.Mkfifo != "":
		return mkfifo(r.path(op.Mkfifo))
	case op.Socket != "":
		c, err := listenUnix(r.path(op.Socket))
		if err != nil {
			return err
		}
		r.closers = append(r.closers, c)
		return nil
	case op.Chmod != "":
		m, err := mode(0)
		if err != nil {
			return err
		}
		return r.chmod(r.path(op.Chmod), m)
	}
	return fmt.Errorf("tree: an entry with no action (%+v)", op)
}

func (r *treeRunner) chmod(p string, m fs.FileMode) error {
	r.chmodded = append(r.chmodded, p)
	return os.Chmod(p, m)
}

func (r *treeRunner) close() {
	for _, c := range r.closers {
		_ = c.Close()
	}
	for _, p := range r.chmodded {
		_ = os.Chmod(p, 0o755) //nolint:gosec // a test folder, opened up so cleanup can delete it
	}
}

// copyTree copies a committed fixture folder into the work folder.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p) //nolint:gosec // a committed fixture file
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644) //nolint:gosec // fixture files are meant to be readable
	})
}
