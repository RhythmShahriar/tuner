// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// VerifyTTL is how long an ownership check lasts. A site can change
// hands, so scans after this need a fresh check.
const VerifyTTL = 30 * 24 * time.Hour

// Verification methods.
const (
	MethodDNS  = "dns"
	MethodFile = "file"
)

// Where the proof of ownership goes.
const (
	dnsLabel = "_tuner-verify."
	filePath = "/.well-known/tuner-verify.txt"
)

// Target is a site registered with the API.
type Target struct {
	ID      string    `json:"id"`
	URL     string    `json:"url"`
	Host    string    `json:"host"`
	Token   string    `json:"token"` // the proof to publish
	Created time.Time `json:"created"`
	// Verified is when ownership was last proven; VerifiedBy how.
	Verified   *time.Time `json:"verified,omitempty"`
	VerifiedBy string     `json:"verified_by,omitempty"`
}

// targetView is a Target as the API shows it, with instructions.
type targetView struct {
	Target
	IsVerified bool          `json:"is_verified"`
	Expires    *time.Time    `json:"verification_expires,omitempty"`
	Verify     verifyOptions `json:"verify"`
}

type verifyOptions struct {
	DNS  dnsProof  `json:"dns"`
	File fileProof `json:"file"`
}

type dnsProof struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type fileProof struct {
	URL  string `json:"url"`
	Body string `json:"body"`
}

// verifiedAt reports whether ownership is proven at now.
func (t Target) verifiedAt(now time.Time) bool {
	return t.Verified != nil && now.Before(t.Verified.Add(VerifyTTL))
}

func (s *Server) view(t Target) targetView {
	v := targetView{Target: t, IsVerified: t.verifiedAt(s.cfg.Now())}
	if t.Verified != nil {
		exp := t.Verified.Add(VerifyTTL)
		v.Expires = &exp
	}
	v.Verify.DNS = dnsProof{Name: dnsLabel + hostname(t.Host), Type: "TXT", Value: t.Token}
	v.Verify.File = fileProof{URL: t.proofURL(), Body: t.Token}
	return v
}

// proofURL is where the ownership file goes: the target's own scheme,
// host and port. A site served only over http can prove itself over
// http, since that is how it will be scanned too.
func (t Target) proofURL() string {
	scheme := "https"
	if u, err := url.Parse(t.URL); err == nil && u.Scheme == "http" {
		scheme = "http"
	}
	return scheme + "://" + t.Host + filePath
}

// hostname drops a port from host.
func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

// parseTargetURL accepts what scan accepts for a remote site, minus
// anything a scan by URL can't mean: a user name, a query or fragment.
func parseTargetURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New(`want {"url": "https://example.com"}`)
	}
	// ParseTargetAuth moves user:password@ out of the URL, so it is
	// rejected by what it returned and never echoed back.
	u, _, auth, err := engine.ParseTargetAuth(raw)
	if err != nil {
		return nil, err
	}
	if auth != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%q: give the site's address without a user name, query or fragment", u.Redacted())
	}
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" {
		u.Path = ""
	}
	return u, nil
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	u, err := parseTargetURL(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t, created, err := s.store.addTarget(&Target{
		ID: newID("t_", 8), URL: u.String(), Host: u.Host,
		Token: newID("tuner-verify=", 16), Created: s.cfg.Now().UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
		s.logf("target %s added: %s", t.ID, t.URL)
	}
	writeJSON(w, code, s.view(t))
}

func (s *Server) listTargets(w http.ResponseWriter, _ *http.Request) {
	list := s.store.listTargets()
	views := make([]targetView, len(list))
	for i, t := range list {
		views[i] = s.view(t)
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) getTarget(w http.ResponseWriter, r *http.Request) {
	t, ok := s.store.target(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no target "+r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, s.view(t))
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.deleteTarget(r.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !ok:
		writeError(w, http.StatusNotFound, "no target "+r.PathValue("id"))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// verifyCheck is the outcome of one ownership check.
type verifyCheck struct {
	Method string `json:"method"`
	Where  string `json:"where"` // the DNS name or URL looked at
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

func (s *Server) verifyTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	t, ok := s.store.target(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no target "+r.PathValue("id"))
		return
	}
	var methods []string
	switch req.Method {
	case "":
		methods = []string{MethodDNS, MethodFile}
	case MethodDNS, MethodFile:
		methods = []string{req.Method}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("method %q: want dns or file (or none to try both)", req.Method))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var checks []verifyCheck
	for _, m := range methods {
		c := s.check(ctx, t, m)
		checks = append(checks, c)
		if !c.OK {
			continue
		}
		t, err := s.store.updateTarget(t.ID, func(t *Target) {
			now := s.cfg.Now().UTC()
			t.Verified, t.VerifiedBy = &now, m
		})
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, os.ErrNotExist) {
				code = http.StatusNotFound
			}
			writeError(w, code, err.Error())
			return
		}
		s.logf("target %s verified by %s", t.ID, m)
		writeJSON(w, http.StatusOK, s.view(t))
		return
	}
	writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: "ownership not proven for " + t.Host, Checks: checks})
}

// check runs one ownership check.
func (s *Server) check(ctx context.Context, t Target, method string) verifyCheck {
	if method == MethodDNS {
		name := dnsLabel + hostname(t.Host)
		c := verifyCheck{Method: method, Where: name}
		records, err := s.cfg.Resolver.LookupTXT(ctx, name)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				c.Error = "no TXT record at " + name
			} else {
				c.Error = "DNS lookup failed: " + err.Error()
			}
			return c
		}
		for _, rec := range records {
			if strings.TrimSpace(rec) == t.Token {
				c.OK = true
				return c
			}
		}
		c.Error = fmt.Sprintf("%d TXT records at %s, none is this target's token", len(records), name)
		return c
	}
	u := t.proofURL()
	c := verifyCheck{Method: method, Where: u}
	if err := s.fetchProof(ctx, u, t); err != nil {
		c.Error = err.Error()
		return c
	}
	c.OK = true
	return c
}

// fetchProof GETs the proof file. Redirects may stay on the host (to
// another path, say) but never leave it: following one elsewhere would
// let anyone who controls a site that the target redirects to "prove"
// they own the target. A check that starts on https never drops to
// plain HTTP, where anyone on the path could answer for the site.
func (s *Server) fetchProof(ctx context.Context, u string, t Target) error {
	want := hostname(t.Host)
	secure := strings.HasPrefix(u, "https://")
	client := *s.cfg.HTTP
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		switch {
		case len(via) >= 5:
			return errors.New("too many redirects")
		case !strings.EqualFold(req.URL.Hostname(), want):
			return fmt.Errorf("redirected off the host, to %s; the file must be served by %s itself", req.URL.Host, t.Host)
		case secure && req.URL.Scheme != "https":
			return errors.New("redirected to plain HTTP")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is in the check already
		}
		return fmt.Errorf("couldn't fetch the file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return fmt.Errorf("couldn't read the file: %w", err)
	}
	if strings.TrimSpace(string(body)) != t.Token {
		return errors.New("the file doesn't hold this target's token")
	}
	return nil
}
