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

// urlMarkup percent-encodes what would start Markdown inside a URL. A
// word only looks like a URL, since titles come from the scanned site:
// "https://x[click](https://evil.test)" must not become a masked link.
var urlMarkup = strings.NewReplacer("[", "%5B", "]", "%5D", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E", "`", "%60", "|", "%7C", "*", "%2A", "~", "%7E", "\\", "%5C")

// discordEscape escapes Markdown in a line. URLs get percent-encoding
// instead of backslashes, since Discord would keep the backslashes inside
// a link; the link still opens the same page.
func discordEscape(line string) string {
	words := strings.Split(line, " ")
	for i, w := range words {
		if strings.HasPrefix(w, "https://") || strings.HasPrefix(w, "http://") {
			words[i] = urlMarkup.Replace(w)
		} else {
			words[i] = discordEscaper.Replace(w)
		}
	}
	return strings.Join(words, " ")
}

// cutEscape drops a backslash left at the end of a cut, whose escaped
// character was cut off; an escaped backslash (an even run) stays.
func cutEscape(s string) string {
	n := len(s) - len(strings.TrimRight(s, `\`))
	if n%2 == 1 {
		return s[:len(s)-1]
	}
	return s
}

func discordBody(m Message) any {
	text := m.Text(discordEscape)
	if utf8.RuneCountInString(text) > discordLimit {
		r := []rune(text)
		text = cutEscape(string(r[:discordLimit-1])) + "…"
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
