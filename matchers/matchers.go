// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package matchers evaluates check conditions against an HTTP response.
package matchers

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Response is a fetched HTTP response, as seen by matchers.
type Response struct {
	URL    *url.URL
	Status int
	Header http.Header
	Body   []byte
	TLS    *TLSInfo // set on the home page of https targets

	// TLSState is the raw handshake, kept for the engine's TLS probe.
	TLSState *tls.ConnectionState
}

// TLSInfo describes the target's certificate and protocol support.
type TLSInfo struct {
	Version     string    `json:"version"`                // negotiated, e.g. "TLS 1.3"
	NotAfter    time.Time `json:"not_after"`              // leaf certificate expiry
	VerifyError string    `json:"verify_error,omitempty"` // why the chain or hostname failed, if it did
	Legacy      []string  `json:"legacy,omitempty"`       // obsolete versions the server still accepts
}

// Matcher is one condition. Every field that is set must hold.
type Matcher struct {
	Status        Ints              `yaml:"status"`
	Regex         string            `yaml:"regex"`
	NotRegex      string            `yaml:"not_regex"`
	Words         []string          `yaml:"words"`          // any of these substrings
	Magic         string            `yaml:"magic"`          // hex prefix of the body
	Header        map[string]string `yaml:"header"`         // header name → regex
	NotHeader     map[string]string `yaml:"not_header"`     // header name → regex that must not match
	MissingHeader []string          `yaml:"missing_header"` // headers that must be absent
	Scheme        string            `yaml:"scheme"`         // http or https
	NotBaseline   bool              `yaml:"not_baseline"`   // must differ from the soft-404 response
	Cookie        *CookieMatch      `yaml:"cookie"`
	TLS           *TLSMatch         `yaml:"tls"`

	cookieName *regexp.Regexp

	re, notRe         *regexp.Regexp
	header, notHeader map[string]*regexp.Regexp
	magic             []byte
}

// CookieMatch holds when a cookie set by the response lacks a flag.
type CookieMatch struct {
	Name        string `yaml:"name"`         // regex on the cookie name; any cookie if empty
	MissingFlag string `yaml:"missing_flag"` // secure, httponly or samesite
}

// TLSMatch holds when every set condition holds for an https target.
type TLSMatch struct {
	ExpiresWithinDays int  `yaml:"expires_within_days"` // valid now but expires within N days
	Expired           bool `yaml:"expired"`
	Untrusted         bool `yaml:"untrusted"` // chain or hostname does not verify
	Legacy            bool `yaml:"legacy"`    // TLS 1.0 or 1.1 still accepted
}

// Ints accepts either a single int or a list in YAML.
type Ints []int

func (i *Ints) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var v int
		if err := n.Decode(&v); err != nil {
			return err
		}
		*i = Ints{v}
		return nil
	}
	var vs []int
	if err := n.Decode(&vs); err != nil {
		return err
	}
	*i = vs
	return nil
}

// Compile validates the matcher and prepares its regexes.
func (m *Matcher) Compile() error {
	var err error
	if m.Regex != "" {
		if m.re, err = regexp.Compile(m.Regex); err != nil {
			return fmt.Errorf("regex: %w", err)
		}
	}
	if m.NotRegex != "" {
		if m.notRe, err = regexp.Compile(m.NotRegex); err != nil {
			return fmt.Errorf("not_regex: %w", err)
		}
	}
	if m.header, err = compileHeaders(m.Header); err != nil {
		return fmt.Errorf("header: %w", err)
	}
	if m.notHeader, err = compileHeaders(m.NotHeader); err != nil {
		return fmt.Errorf("not_header: %w", err)
	}
	if m.Magic != "" {
		if m.magic, err = hex.DecodeString(m.Magic); err != nil {
			return fmt.Errorf("magic: %w", err)
		}
	}
	if c := m.Cookie; c != nil {
		if m.cookieName, err = regexp.Compile(c.Name); err != nil {
			return fmt.Errorf("cookie.name: %w", err)
		}
		if !slices.Contains([]string{"secure", "httponly", "samesite"}, c.MissingFlag) {
			return fmt.Errorf("cookie.missing_flag: want secure, httponly or samesite, got %q", c.MissingFlag)
		}
	}
	if t := m.TLS; t != nil && t.ExpiresWithinDays == 0 && !t.Expired && !t.Untrusted && !t.Legacy {
		return errors.New("tls: set at least one condition")
	}
	if m.Scheme != "" && m.Scheme != "http" && m.Scheme != "https" {
		return fmt.Errorf("scheme: want http or https, got %q", m.Scheme)
	}
	if len(m.Status) == 0 && m.re == nil && m.notRe == nil && len(m.Words) == 0 && m.magic == nil &&
		len(m.header) == 0 && len(m.notHeader) == 0 && len(m.MissingHeader) == 0 && m.Scheme == "" && !m.NotBaseline && m.Cookie == nil && m.TLS == nil {
		return errors.New("matcher has no conditions")
	}
	return nil
}

func compileHeaders(in map[string]string) (map[string]*regexp.Regexp, error) {
	out := make(map[string]*regexp.Regexp, len(in))
	for name, expr := range in {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = re
	}
	return out, nil
}

// Match reports whether every condition holds, plus a short piece of evidence.
// isBaseline is only called when the matcher needs it, since it may cost a request.
func (m *Matcher) Match(r *Response, isBaseline func() bool) (bool, string) {
	var ev string
	if len(m.Status) > 0 && !slices.Contains(m.Status, r.Status) {
		return false, ""
	}
	if m.Scheme != "" && (r.URL == nil || r.URL.Scheme != m.Scheme) {
		return false, ""
	}
	if m.magic != nil && !bytes.HasPrefix(r.Body, m.magic) {
		return false, ""
	}
	if len(m.Words) > 0 {
		i := slices.IndexFunc(m.Words, func(w string) bool { return bytes.Contains(r.Body, []byte(w)) })
		if i < 0 {
			return false, ""
		}
		ev = m.Words[i]
	}
	if m.notRe != nil && m.notRe.Match(r.Body) {
		return false, ""
	}
	if m.re != nil {
		loc := m.re.FindIndex(r.Body)
		if loc == nil {
			return false, ""
		}
		ev = Snippet(r.Body[loc[0]:loc[1]])
	}
	for name, re := range m.header {
		v, ok := headerMatch(r.Header, name, re)
		if !ok {
			return false, ""
		}
		ev = name + ": " + v
	}
	for name, re := range m.notHeader {
		if _, ok := headerMatch(r.Header, name, re); ok {
			return false, ""
		}
	}
	for _, name := range m.MissingHeader {
		if r.Header.Get(name) != "" {
			return false, ""
		}
		ev = "no " + name + " header"
	}
	if m.Cookie != nil {
		name, ok := m.cookieLacking(r.Header)
		if !ok {
			return false, ""
		}
		ev = "cookie " + name + " without " + m.Cookie.MissingFlag
	}
	if m.TLS != nil {
		e, ok := m.TLS.match(r.TLS)
		if !ok {
			return false, ""
		}
		ev = e
	}
	if m.NotBaseline && isBaseline() {
		return false, ""
	}
	return true, ev
}

// cookieLacking returns the first matching cookie without the flag. Only
// the name is reported; cookie values can be session secrets.
func (m *Matcher) cookieLacking(h http.Header) (string, bool) {
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil || !m.cookieName.MatchString(c.Name) {
			continue
		}
		lacks := false
		switch m.Cookie.MissingFlag {
		case "secure":
			lacks = !c.Secure
		case "httponly":
			lacks = !c.HttpOnly
		case "samesite":
			lacks = c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode
		}
		if lacks {
			return c.Name, true
		}
	}
	return "", false
}

func (t *TLSMatch) match(info *TLSInfo) (string, bool) {
	if info == nil {
		return "", false
	}
	var ev []string
	left := time.Until(info.NotAfter)
	if t.Expired {
		if left > 0 {
			return "", false
		}
		ev = append(ev, "certificate expired "+info.NotAfter.Format("2006-01-02"))
	}
	if t.ExpiresWithinDays > 0 {
		if left <= 0 || left > time.Duration(t.ExpiresWithinDays)*24*time.Hour {
			return "", false
		}
		ev = append(ev, fmt.Sprintf("certificate expires %s (%d days)", info.NotAfter.Format("2006-01-02"), int(left.Hours()/24)))
	}
	if t.Untrusted {
		if info.VerifyError == "" {
			return "", false
		}
		ev = append(ev, info.VerifyError)
	}
	if t.Legacy {
		if len(info.Legacy) == 0 {
			return "", false
		}
		ev = append(ev, "accepts "+strings.Join(info.Legacy, ", "))
	}
	return strings.Join(ev, "; "), true
}

func headerMatch(h http.Header, name string, re *regexp.Regexp) (string, bool) {
	for _, v := range h.Values(name) {
		if re.MatchString(v) {
			return v, true
		}
	}
	return "", false
}

// Block combines matchers: every one in All must hold, and if Any is set,
// at least one of those too.
type Block struct {
	All []Matcher `yaml:"all"`
	Any []Matcher `yaml:"any"`
}

func (b *Block) Compile() error {
	if len(b.All)+len(b.Any) == 0 {
		return errors.New("match needs at least one condition in all or any")
	}
	for i := range b.All {
		if err := b.All[i].Compile(); err != nil {
			return fmt.Errorf("all[%d]: %w", i, err)
		}
	}
	for i := range b.Any {
		if err := b.Any[i].Compile(); err != nil {
			return fmt.Errorf("any[%d]: %w", i, err)
		}
	}
	return nil
}

// Match evaluates the block. Baseline comparisons run last so a soft-404
// probe is only requested when everything else already matched.
func (b *Block) Match(r *Response, isBaseline func() bool) (bool, []string) {
	var ev []string
	add := func(e string) {
		if e != "" {
			ev = append(ev, e)
		}
	}
	never := func() bool { return false }
	for i := range b.All {
		ok, e := b.All[i].Match(r, never)
		if !ok {
			return false, nil
		}
		add(e)
	}
	if len(b.Any) > 0 {
		hit := false
		for i := range b.Any {
			if ok, e := b.Any[i].Match(r, isBaseline); ok {
				add(e)
				hit = true
				break
			}
		}
		if !hit {
			return false, nil
		}
	}
	for i := range b.All {
		if b.All[i].NotBaseline && isBaseline() {
			return false, nil
		}
	}
	return true, ev
}

// Snippet turns matched bytes into a short single-line string.
func Snippet(b []byte) string {
	s := strings.Join(strings.Fields(strings.ToValidUTF8(string(b), "�")), " ")
	if utf8.RuneCountInString(s) > 120 {
		s = string([]rune(s)[:119]) + "…"
	}
	return s
}
