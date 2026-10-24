// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/tuner/engine"
)

// TargetError is a target that could not be scanned. Batch reports list
// it next to the targets that were, so a script sees every target it asked
// for.
type TargetError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// Brand puts an agency's name and logo on reports meant for clients.
type Brand struct {
	Name     string
	LogoPath string
}

// WriteOptions carries everything a writer may need besides the reports.
type WriteOptions struct {
	Many    bool          // several targets were requested, so JSON is an array
	Array   bool          // JSON is an array even for one target
	Failed  []TargetError // targets that could not be scanned
	Version string        // the rhythm-tuner version, for SARIF's tool driver
	Root    string        // the scan root of a local scan, for fingerprints
	Brand   Brand
}

// Writer renders reports in one format.
type Writer func(w io.Writer, reports []Report, o WriteOptions) error

type writerEntry struct {
	ext string
	fn  Writer
}

var (
	writersMu sync.RWMutex
	writers   = map[string]writerEntry{}
)

// Extensions that name a format without being its main extension.
var extAliases = map[string]string{".ndjson": "jsonl", ".markdown": "md"}

// RegisterWriter adds a report format. name is what --format style flags
// and Write take; ext (with its dot) is the file extension that picks it for -o.
// Registering a name again replaces it.
func RegisterWriter(name, ext string, fn Writer) {
	writersMu.Lock()
	defer writersMu.Unlock()
	writers[name] = writerEntry{ext: strings.ToLower(ext), fn: fn}
}

// Write renders reports in the named format.
func Write(format string, w io.Writer, reports []Report, o WriteOptions) error {
	writersMu.RLock()
	e, ok := writers[format]
	writersMu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown report format %q (known: %s)", format, strings.Join(Formats(), ", "))
	}
	return e.fn(w, reports, o)
}

// Formats lists the registered format names, sorted.
func Formats() []string {
	writersMu.RLock()
	defer writersMu.RUnlock()
	var names []string
	for name := range writers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// FormatForExt returns the format a file name's extension asks for, or ""
// when the extension names none.
func FormatForExt(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return ""
	}
	if name, ok := extAliases[ext]; ok {
		return name
	}
	writersMu.RLock()
	defer writersMu.RUnlock()
	for name, e := range writers {
		if e.ext == ext {
			return name
		}
	}
	return ""
}

func init() {
	RegisterWriter("json", ".json", writeJSON)
	// JSON Lines findings stream through JSONLine while the scan runs, so
	// nothing is left to write once it ends.
	RegisterWriter("jsonl", ".jsonl", func(io.Writer, []Report, WriteOptions) error { return nil })
	RegisterWriter("sarif", ".sarif", writeSARIF)
	RegisterWriter("md", ".md", writeMarkdown)
}

// Stamp gives every finding in res its stable fingerprint. root is the
// folder a local scan started from ("" for remote scans).
//
// Until engine.Finding has a Fingerprint field (contract D1), writers and
// baselines compute fingerprints when they need them, so Stamp has
// nothing to store yet.
func Stamp(res *engine.Result, root string) {}
