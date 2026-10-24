// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package main

// interruptSelf has no portable form on Windows; the tests that call it
// skip there.
func interruptSelf() {}
