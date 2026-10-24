// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package notify tells people what a scan found that is new: a Slack or
// Discord channel, a webhook of their own or an email inbox. Messages
// hold only new findings at or above a severity, as one line each with
// no evidence, so a chat channel never receives a response body or a
// secret.
//
// A notification URL names the backend:
//
//	slack://hooks.slack.com/services/T000/B000/XXXX    Slack incoming webhook
//	discord://discord.com/api/webhooks/123/abc         Discord webhook
//	webhook+https://hooks.example.com/tuner            JSON POST (schema/notify-v0.json)
//	smtp://user@mail.example.com:587?to=a@b.c&from=tuner@b.c
//	smtps://user@mail.example.com:465?to=a@b.c&from=tuner@b.c
//
// Webhook URLs carry their token in the path, so they are secrets: a
// Notifier prints as its scheme and host only. No error repeats the
// URL.
package notify

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/RhythmShahriar/tuner/diff"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
	"github.com/RhythmShahriar/tuner/report"
)

// Schema identifies the JSON layout the webhook backend posts.
const Schema = "rhythm-tuner-notify/v0"

// MaxListed is how many findings a chat or email message lists before it
// says how many more there are. Webhooks get every finding.
const MaxListed = 25

// Item is one new finding in a notification.
type Item struct {
	Target      string          `json:"target"`
	Fingerprint string          `json:"fingerprint"`
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Severity    engine.Severity `json:"severity"`
	Was         engine.Severity `json:"was,omitempty"` // the old severity, when that is what changed
	Confidence  string          `json:"confidence"`
	// Location is the finding's URL, or its path inside the scanned
	// folder for a local scan.
	Location      string   `json:"location"`
	NewAdvisories []string `json:"new_advisories,omitempty"` // CVE or advisory IDs
	Fix           string   `json:"fix,omitempty"`
}

// Message is what every backend sends.
type Message struct {
	Schema  string `json:"schema"`
	Tool    string `json:"tool"`
	Version string `json:"version"`
	// Since names the earlier report the scan was compared with. It is
	// empty on a first run, when every finding counts as new.
	Since       string                  `json:"since,omitempty"`
	MinSeverity engine.Severity         `json:"min_severity"`
	Summary     string                  `json:"summary"`
	Counts      map[engine.Severity]int `json:"counts"`
	Targets     []string                `json:"targets"`
	Findings    []Item                  `json:"findings"`
	// Incomplete holds the scan's status notes when it didn't finish, e.g.
	// "Incomplete: stopped by --max-time", so nobody reads a short list as
	// a clean bill of health.
	Incomplete []string `json:"incomplete,omitempty"`
}

// Build turns a comparison into a message: the new findings at or above
// lowest, most severe first. since is the earlier report's file name (only
// its base name is sent) or "" on a first run.
func Build(res diff.Result, since string, lowest engine.Severity, version string) Message {
	m := Message{
		Schema: Schema, Tool: "rhythm-tuner", Version: safe(version), MinSeverity: lowest,
		Counts: map[engine.Severity]int{}, Targets: []string{}, Findings: []Item{},
	}
	for _, s := range engine.Severities {
		m.Counts[s] = 0 // every severity present, as in a report's summary
	}
	if since != "" {
		m.Since = safe(filepath.Base(since))
	}
	seen := map[string]bool{}
	for _, e := range res.New {
		f := e.Finding
		if r := f.Severity.Rank(); r < 0 || r > lowest.Rank() {
			continue
		}
		it := Item{
			Target: safe(stripUser(e.Target)), Fingerprint: e.Fingerprint, ID: safe(f.ID), Title: safe(f.Title),
			Severity: f.Severity, Was: e.Was, Confidence: safe(string(f.Confidence)),
			Location: safe(stripUser(report.Place(f))), Fix: safeBlock(f.Fix),
		}
		for _, a := range e.NewAdvisories {
			it.NewAdvisories = append(it.NewAdvisories, safe(cmp.Or(first(a.CVEs), a.ID)))
		}
		m.Findings = append(m.Findings, it)
		m.Counts[f.Severity]++
		if !seen[it.Target] {
			seen[it.Target] = true
			m.Targets = append(m.Targets, it.Target)
		}
	}
	for _, n := range res.Incomplete {
		m.Incomplete = append(m.Incomplete, safe(n))
	}
	m.Summary = summary(m)
	return m
}

// summary reads e.g. "Tuner: 3 new findings (2 critical, 1 high) on a.test".
func summary(m Message) string {
	var parts []string
	for _, s := range engine.Severities {
		if n := m.Counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	noun := "findings"
	if len(m.Findings) == 1 {
		noun = "finding"
	}
	if m.Since != "" {
		noun = "new " + noun
	}
	where := ""
	switch len(m.Targets) {
	case 0:
	case 1:
		where = " on " + host(m.Targets[0])
	default:
		where = fmt.Sprintf(" on %d sites", len(m.Targets))
	}
	if len(parts) == 0 {
		return "Tuner: no " + noun + where
	}
	return fmt.Sprintf("Tuner: %d %s (%s)%s", len(m.Findings), noun, strings.Join(parts, ", "), where)
}

// Text renders the message as plain lines for chat and email, grouped by
// target when there are several. esc escapes each line for the backend's
// markup.
func (m Message) Text(esc func(string) string) string {
	var b strings.Builder
	b.WriteString(esc(m.Summary) + "\n")
	if m.Since != "" {
		b.WriteString(esc(fmt.Sprintf("Compared with %s. Showing %s and above.", m.Since, m.MinSeverity)) + "\n")
	} else {
		b.WriteString(esc(fmt.Sprintf("No earlier report to compare with. Showing %s and above.", m.MinSeverity)) + "\n")
	}
	for _, n := range m.Incomplete {
		b.WriteString(esc(n) + "\n")
	}
	listed := 0
	for _, t := range m.Targets {
		b.WriteString("\n")
		if len(m.Targets) > 1 {
			b.WriteString(esc(t) + "\n")
		}
		for _, it := range m.Findings {
			if it.Target != t {
				continue
			}
			if listed == MaxListed {
				fmt.Fprintf(&b, "…and %d more\n", len(m.Findings)-MaxListed)
				return b.String()
			}
			listed++
			b.WriteString(esc(it.Line()) + "\n")
		}
	}
	return b.String()
}

// Line is an item's plain form, e.g.
// "[HIGH] Git config exposed - https://a.test/.git/config".
func (it Item) Line() string {
	label := strings.ToUpper(string(it.Severity))
	if it.Confidence == "low" {
		label += ", likely"
	}
	title := it.Title
	if len(it.NewAdvisories) > 0 {
		title += fmt.Sprintf(" (%d new: %s)", len(it.NewAdvisories), strings.Join(it.NewAdvisories, ", "))
	}
	if it.Was != "" {
		title += " (was " + string(it.Was) + ")"
	}
	return fmt.Sprintf("[%s] %s - %s", label, title, it.Location)
}

// Notifier sends a message to one place.
type Notifier interface {
	Send(ctx context.Context, m Message) error
	// String names the receiver for logs: its scheme and host, never
	// the path, query or user that hold its secrets.
	String() string
}

// Options are what backends need besides the URL.
type Options struct {
	// HTTPClient sends webhook requests. Nil means a client with a 30s
	// timeout that does not follow redirects.
	HTTPClient *http.Client
	// SMTPPassword is the SMTP password, from TUNER_SMTP_PASSWORD. It
	// never goes in the URL, where shell history and process lists see it.
	SMTPPassword string
	// TLSConfig is the base TLS config for SMTP; nil uses the system roots.
	TLSConfig *tls.Config
	// Dial opens SMTP connections; nil uses net.Dialer. Tests point it at
	// a local server.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Parse returns the notifier a URL names. Its errors never include the URL.
func Parse(raw string, o Options) (Notifier, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return nil, errors.New("not a notification URL; want slack://, discord://, webhook+https:// or smtp://")
	}
	shown := Redacted(raw)
	if u.Host == "" {
		return nil, fmt.Errorf("%s: no host in the URL", shown)
	}
	switch strings.ToLower(u.Scheme) {
	case "slack":
		return newHook(u, "https", o, shown, slackBody)
	case "discord":
		return newHook(u, "https", o, shown, discordBody)
	case "webhook+https":
		return newHook(u, "https", o, shown, webhookBody)
	case "webhook+http":
		if !loopback(u.Hostname()) {
			return nil, fmt.Errorf("%s: plain http is only for a receiver on this machine; use webhook+https://", shown)
		}
		return newHook(u, "http", o, shown, webhookBody)
	case "smtp", "smtps":
		return newMailer(u, o, shown)
	}
	return nil, fmt.Errorf("unsupported notification scheme %q; want slack, discord, webhook+https or smtp", safe(u.Scheme))
}

// Redacted is a notification URL as logs may show it: scheme and host
// (with port), no user, path or query.
func Redacted(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "notification URL"
	}
	return safe(strings.ToLower(u.Scheme) + "://" + u.Host)
}

// cleanErr drops the URL that net/http puts in its errors.
func cleanErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// safe cleans a string for a message: control bytes become U+FFFD and
// anything that looks like a secret is masked.
func safe(s string) string { return report.SafeText(matchers.Redact(s)) }

func safeBlock(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = safe(l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// stripUser drops user info from a URL: a target typed as
// https://user:pass@site must not reach a chat channel.
func stripUser(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

// host shortens a target to its host for the summary line.
func host(t string) string {
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		return u.Host
	}
	return t
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
