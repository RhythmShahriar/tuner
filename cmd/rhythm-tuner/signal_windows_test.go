//go:build windows

package main

// interruptSelf has no portable form on Windows; the tests that call it
// skip there.
func interruptSelf() {}
