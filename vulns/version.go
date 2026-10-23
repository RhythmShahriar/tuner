package vulns

import (
	"strconv"
	"strings"
	"unicode"
)

// Compare orders WordPress-style version strings like PHP's
// version_compare: 1.2.10 > 1.2.9, 2.0-beta < 2.0-rc1 < 2.0 < 2.0-pl1.
// Missing trailing parts count as zero, so 5.3 == 5.3.0.
func Compare(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := range max(len(pa), len(pb)) {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := comparePart(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// parts splits "2.0.1-RC1" into ["2", "0", "1", "rc", "1"].
func parts(v string) []string {
	v = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v")))
	var out []string
	var cur strings.Builder
	digit := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r == '.' || r == '-' || r == '_' || r == '+':
			flush()
		case unicode.IsDigit(r):
			if !digit {
				flush()
			}
			digit = true
			cur.WriteRune(r)
		default:
			if digit {
				flush()
			}
			digit = false
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// Rank of non-numeric parts, as in PHP. A release (a number, or a missing
// part) ranks between rc and pl.
var special = map[string]int{"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "c": 3, "pl": 5, "p": 5}

const releaseRank = 4

func comparePart(x, y string) int {
	nx, ex := strconv.Atoi(x)
	ny, ey := strconv.Atoi(y)
	switch {
	case ex == nil && ey == nil:
		return cmpInt(nx, ny)
	case ex == nil:
		return cmpInt(releaseRank, rank(y))
	case ey == nil:
		return cmpInt(rank(x), releaseRank)
	}
	return cmpInt(rank(x), rank(y))
}

// Unknown words rank below dev, like PHP.
func rank(s string) int {
	if r, ok := special[s]; ok {
		return r
	}
	return -1
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// satisfies reports whether v <op> bound holds. An empty bound always holds.
func satisfies(v, op, bound string) bool {
	if bound == "" {
		return true
	}
	c := Compare(v, bound)
	switch op {
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	case "gt":
		return c > 0
	case "ge":
		return c >= 0
	case "eq":
		return c == 0
	}
	return true // unknown operator: err on the side of reporting
}
