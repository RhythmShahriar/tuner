// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package scenarios is Tuner's hermetic scenario suite: the real-world
// failure modes from the October 2026 QA review, each one a folder with an
// expect.yaml. The tests build rhythm-tuner, start loopback fixture servers
// and fixture trees, run the binary and check its exit code, output, report
// files and what the fixture servers were asked.
//
// Nothing leaves the machine: every server listens on 127.0.0.1 or [::1]
// and every data service Tuner talks to (vulnerability data, the check
// pack, the release check) points at a local fake. See README.md for the
// expect.yaml format.
//
// The package has no code outside its tests; this file only holds the
// package documentation.
package scenarios
