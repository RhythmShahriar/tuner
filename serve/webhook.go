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
	"net/http"
	"net/url"
	"strconv"
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
// the signature is for this URL only.
func (s *Server) deliver(u string, rec scanRecord) {
	client := *s.cfg.HTTP
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
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

// permanentError is a reply that a retry won't change, such as 400.
type permanentError struct{ code int }

func (e permanentError) Error() string { return "HTTP " + strconv.Itoa(e.code) }

func (s *Server) post(client *http.Client, u, id string, body []byte) error {
	// Not tied to s.ctx: a shutdown still lets the last try go out.
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return permanentError{}
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
		return permanentError{c}
	}
}
