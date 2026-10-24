// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// Webhook headers. The signature is "sha256=" and the hex HMAC-SHA256
// of the raw body under the shared secret, as GitHub and Stripe do it.
const (
	SignatureHeader = "X-Tuner-Signature"
	EventHeader     = "X-Tuner-Event"
	DeliveryHeader  = "X-Tuner-Delivery"
	// EventCompleted is the only event so far: a scan ended, however.
	EventCompleted = "scan.completed"
)

// Sign returns the signature header value for body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifySignature reports whether header is body's signature under
// secret, in constant time. Receivers written in Go can call it.
func VerifySignature(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(secret, body)), []byte(header))
}

// WebhookPayload is the JSON a webhook receives.
type WebhookPayload struct {
	Event string    `json:"event"`
	Sent  time.Time `json:"sent"` // receivers can reject old deliveries
	Scan  struct {
		ID       string                  `json:"id"`
		TargetID string                  `json:"target_id"`
		URL      string                  `json:"url"`
		Status   string                  `json:"status"`
		Exit     *int                    `json:"exit_code,omitempty"`
		Error    string                  `json:"error,omitempty"`
		Started  *time.Time              `json:"started,omitempty"`
		Finished *time.Time              `json:"finished,omitempty"`
		Summary  map[engine.Severity]int `json:"summary"`
		// Findings lists each finding's ID, title, severity and URL;
		// GET /v0/scans/{id} has the rest.
		Findings []webhookFinding `json:"findings"`
	} `json:"scan"`
}

type webhookFinding struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity engine.Severity `json:"severity"`
	URL      string          `json:"url"`
}

func payload(rec scanRecord, now time.Time) WebhookPayload {
	var p WebhookPayload
	p.Event, p.Sent = EventCompleted, now.UTC()
	p.Scan.ID, p.Scan.TargetID, p.Scan.URL = rec.ID, rec.TargetID, rec.URL
	p.Scan.Status, p.Scan.Exit, p.Scan.Error = rec.Status, rec.Exit, rec.Error
	p.Scan.Started, p.Scan.Finished, p.Scan.Summary = rec.Started, rec.Finished, rec.Summary
	p.Scan.Findings = []webhookFinding{}
	for _, raw := range rec.Findings {
		var f webhookFinding
		if json.Unmarshal(raw, &f) == nil {
			p.Scan.Findings = append(p.Scan.Findings, f)
		}
	}
	return p
}

// deliver POSTs the completion to u, retrying network errors and 5xx or
// 429 replies after each WebhookRetry wait. Redirects are not followed:
// the signature is for this URL only. publicOnly refuses to connect to a
// private or local address, for a URL a scan request named.
func (s *Server) deliver(u string, rec scanRecord, publicOnly bool) {
	client := *s.cfg.HTTP
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if publicOnly {
		client.Transport = publicTransport(client.Transport)
	}
	host := u
	if pu, err := url.Parse(u); err == nil {
		host = pu.Host // the full URL may carry a secret: log the host only
	}
	for attempt := 0; ; attempt++ {
		body, err := json.Marshal(payload(rec, s.cfg.Now()))
		if err != nil {
			s.logf("scan %s: webhook: %v", rec.ID, err)
			return
		}
		err = s.post(&client, u, rec.ID, body)
		if err == nil {
			s.logf("scan %s: webhook delivered to %s", rec.ID, host)
			return
		}
		var perm permanentError
		if errors.As(err, &perm) || attempt >= len(s.cfg.WebhookRetry) {
			s.logf("scan %s: webhook to %s failed: %v", rec.ID, host, err)
			return
		}
		select {
		case <-time.After(s.cfg.WebhookRetry[attempt]):
		case <-s.ctx.Done():
			// Shutting down: one last try right away, then give up.
			if attempt+1 < len(s.cfg.WebhookRetry) {
				attempt = len(s.cfg.WebhookRetry) - 1
			}
		}
	}
}

// permanentError is a failure that a retry won't change, such as a 400
// reply or a URL that can't be used.
type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func httpError(code int) permanentError { return permanentError{"HTTP " + strconv.Itoa(code)} }

// errPrivateAddr is a webhook host that resolves to an address the scan
// request may not reach: loopback, private, link-local (such as a cloud
// metadata service) or otherwise not public.
var errPrivateAddr = errors.New("private or local address")

// nonPublic lists the ranges beyond what netip's Is* methods cover that
// aren't reachable public hosts.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),
}

// publicAddr reports whether a is a public unicast address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// publicHost reports whether a webhook host can be refused right away: a
// literal private address or localhost. Other names are checked when
// they are dialed, so a name that resolves to one is refused too.
func publicHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return publicAddr(a)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h != "localhost" && !strings.HasSuffix(h, ".localhost")
}

// publicTransport copies rt (the default transport when it isn't an
// *http.Transport) into one that dials public addresses only. The check
// runs on the address actually dialed, after DNS, so a name can't be
// pointed at a private address between a check and the connection. A
// proxy is not used: it would make the connection on our behalf.
func publicTransport(rt http.RoundTripper) http.RoundTripper {
	base, ok := rt.(*http.Transport)
	if !ok {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	t.Proxy = nil
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !publicAddr(ap.Addr()) {
			return errPrivateAddr
		}
		return nil
	}}
	t.DialContext = d.DialContext
	t.DialTLSContext = nil
	return t
}

func (s *Server) post(client *http.Client, u, id string, body []byte) error {
	// Not tied to s.ctx: a shutdown still lets the last try go out.
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return permanentError{"bad webhook URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set(EventHeader, EventCompleted)
	req.Header.Set(DeliveryHeader, id)
	req.Header.Set(SignatureHeader, Sign(s.cfg.WebhookSecret, body))
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL may hold a token
		}
		if errors.Is(err, errPrivateAddr) {
			return permanentError{"the host resolves to a private or local address; start serve with --webhook-allow-private to allow it"}
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	switch c := resp.StatusCode; {
	case c >= 200 && c < 300:
		return nil
	case c == http.StatusTooManyRequests || c >= 500:
		return fmt.Errorf("HTTP %d", c)
	default:
		return httpError(c)
	}
}
