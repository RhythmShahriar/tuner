// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.10", "1.2.9", 1},
		{"5.3", "5.3.0", 0},
		{"5.3.1", "5.3.2", -1},
		{"2.0-beta", "2.0", -1},
		{"2.0-beta2", "2.0-rc1", -1},
		{"2.0-RC1", "2.0", -1},
		{"2.0", "2.0-pl1", -1},
		{"2.0.alpha", "2.0.dev", 1},
		{"v1.0", "1.0", 0},
		{"10.0", "9.9.9", 1},
		{"6.4.1", "6.4.10", -1},
		{"1.0.0.1", "1.0.0", 1},
		{"3.20.1", "3.20.1", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	if !satisfies("5.3.1", "lt", "5.3.2") || satisfies("5.3.2", "lt", "5.3.2") {
		t.Error("lt")
	}
	if !satisfies("1.18.0", "le", "1.18.0") || !satisfies("1.0", "ge", "") {
		t.Error("le / empty bound")
	}
}
