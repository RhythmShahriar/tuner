// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// hook posts a JSON body to a webhook URL.
type hook struct {
	url    string // the real https URL, with its token; never printed
	shown  string
	client *http.Client
	body   func(Message) any
}

func newHook(u *url.URL, scheme string, o Options, shown string, body func(Message) any) (*hook, error) {
	if strings.Trim(u.Path, "/") == "" {
		return nil, fmt.Errorf("%s: the URL has no path; paste the whole webhook URL", shown)
	}
	real := *u
	real.Scheme = scheme
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	// A redirect would re-send the findings somewhere the user didn't
	// name; a receiver that moved answers 3xx and the user updates the URL.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hook{url: real.String(), shown: shown, client: &c, body: body}, nil
}

func (h *hook) String() string { return h.shown }

func (h *hook) Send(ctx context.Context, m Message) error {
	data, err := json.Marshal(h.body(m))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(data))
	if err != nil {
		return cleanErr(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rhythm-tuner/"+m.Version)
	resp, err := h.client.Do(req)
	if err != nil {
		return cleanErr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("receiver answered %s", resp.Status)
	}
	return nil
}

// slackEscaper escapes the three characters Slack's mrkdwn treats as
// control characters, which also stops <!channel> style mentions.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackBody(m Message) any {
	return map[string]any{
		"text":         m.Text(slackEscaper.Replace),
		"unfurl_links": false,
		"unfurl_media": false,
	}
}

// discordLimit is Discord's content limit, in characters.
const discordLimit = 2000

var discordEscaper = func() *strings.Replacer {
	var pairs []string
	for _, c := range "\\*_~`|>[]()<@" {
		pairs = append(pairs, string(c), "\\"+string(c))
	}
	return strings.NewReplacer(pairs...)
}()

// discordEscape escapes Markdown in a line but leaves URLs as they are,
// since Discord would keep the backslashes inside a link. A URL here was
// parsed and printed by Go, so it holds no spaces or angle brackets.
func discordEscape(line string) string {
	words := strings.Split(line, " ")
	for i, w := range words {
		if !strings.HasPrefix(w, "https://") && !strings.HasPrefix(w, "http://") {
			words[i] = discordEscaper.Replace(w)
		}
	}
	return strings.Join(words, " ")
}

func discordBody(m Message) any {
	text := m.Text(discordEscape)
	if utf8.RuneCountInString(text) > discordLimit {
		r := []rune(text)
		text = string(r[:discordLimit-1]) + "…"
	}
	return map[string]any{
		"username": "Rhythm Tuner",
		"content":  text,
		// Escaping already defuses @everyone; this makes sure Discord
		// pings nobody whatever the text says.
		"allowed_mentions": map[string]any{"parse": []string{}},
		"flags":            4, // SUPPRESS_EMBEDS: no link previews of the scanned site
	}
}

func webhookBody(m Message) any { return m }
