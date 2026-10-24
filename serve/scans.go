// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// Scan statuses.
const (
	statusQueued      = "queued"
	statusRunning     = "running"
	statusDone        = "done"     // the scan finished
	statusFailed      = "failed"   // the site couldn't be scanned or the scan crashed
	statusCanceled    = "canceled" // the server stopped it
	statusInterrupted = "interrupted"
)

// Caps on what one scan keeps, so a runaway scan can't fill memory.
const (
	maxFindings = 5000
	maxLogLines = 200
	maxLine     = 1 << 20 // a JSON finding with long evidence is still well under this
)

// ScanOptions are the scan flags a request may set. Anything that reads
// or writes the server's files (--checks, -o, --php) or changes where
// requests go (--proxy, headers) is left out on purpose.
type ScanOptions struct {
	Profile     string   `json:"profile,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ExcludeTags []string `json:"exclude_tags,omitempty"`
	IDs         []string `json:"ids,omitempty"`
	ExcludeIDs  []string `json:"exclude_ids,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	NoVulns     bool     `json:"no_vulns,omitempty"`
}

// listItem is a tag or check ID, globs allowed; never a flag.
var listItem = regexp.MustCompile(`^[A-Za-z0-9*?._-]{1,64}$`)

func (o ScanOptions) validate() error {
	if o.Profile != "" && engine.Profile(o.Profile).Rank() < 0 {
		return fmt.Errorf("profile %q: want one of %v", o.Profile, engine.Profiles)
	}
	if o.Severity != "" && engine.Severity(o.Severity).Rank() < 0 {
		return fmt.Errorf("severity %q: want one of %v", o.Severity, engine.Severities)
	}
	for name, list := range map[string][]string{"tags": o.Tags, "exclude_tags": o.ExcludeTags, "ids": o.IDs, "exclude_ids": o.ExcludeIDs} {
		if len(list) > 50 {
			return fmt.Errorf("%s: at most 50 entries", name)
		}
		for _, v := range list {
			if !listItem.MatchString(v) || strings.HasPrefix(v, "-") {
				return fmt.Errorf("%s: %q isn't a tag or check ID", name, v)
			}
		}
	}
	return nil
}

// args are the scan flags for o.
func (o ScanOptions) args() []string {
	var a []string
	if o.Profile != "" {
		a = append(a, "--profile", o.Profile)
	}
	for _, f := range []struct {
		flag string
		list []string
	}{{"--tags", o.Tags}, {"--exclude-tags", o.ExcludeTags}, {"--id", o.IDs}, {"--exclude-id", o.ExcludeIDs}} {
		if len(f.list) > 0 {
			a = append(a, f.flag, strings.Join(f.list, ","))
		}
	}
	if o.Severity != "" {
		a = append(a, "--severity", o.Severity)
	}
	if o.NoVulns {
		a = append(a, "--no-vulns")
	}
	return a
}

// Event is one Server-Sent Event of a scan: queued, started, finding
// (data is the JSON finding), log (a line the scan printed), done (data
// is the scan).
type Event struct {
	Seq  int             `json:"seq"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// scanRecord is a scan as stored and as the API shows it.
type scanRecord struct {
	ID         string                  `json:"id"`
	TargetID   string                  `json:"target_id"`
	URL        string                  `json:"url"`
	Status     string                  `json:"status"`
	Options    ScanOptions             `json:"options"`
	Created    time.Time               `json:"created"`
	Started    *time.Time              `json:"started,omitempty"`
	Finished   *time.Time              `json:"finished,omitempty"`
	Exit       *int                    `json:"exit_code,omitempty"`
	Error      string                  `json:"error,omitempty"`
	Summary    map[engine.Severity]int `json:"summary"`
	Findings   []json.RawMessage       `json:"findings"`
	Truncated  bool                    `json:"findings_truncated,omitempty"`
	Log        []string                `json:"log,omitempty"`
	Events     []Event                 `json:"events,omitempty"`
	WebhookURL string                  `json:"webhook_url,omitempty"` // stored; never shown
}

// scan is a scan in memory. Event streams wait on changed, which is
// closed and replaced at every new event.
type scan struct {
	id   string
	host string // per-host queue key

	mu      sync.Mutex
	rec     scanRecord
	changed chan struct{}
}

func scanFromRecord(rec scanRecord) *scan {
	sc := &scan{id: rec.ID, rec: rec, changed: make(chan struct{})}
	if final(rec.Status) {
		close(sc.changed)
	}
	return sc
}

func final(status string) bool {
	return status != statusQueued && status != statusRunning
}

// record returns a copy safe to encode while the scan runs on.
func (sc *scan) record() scanRecord {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	r := sc.rec
	r.Findings = append([]json.RawMessage{}, r.Findings...)
	r.Log = append([]string(nil), r.Log...)
	r.Events = append([]Event(nil), r.Events...)
	r.Summary = map[engine.Severity]int{}
	for k, v := range sc.rec.Summary {
		r.Summary[k] = v
	}
	return r
}

// public is the API view: no events (they have their own endpoint) and
// no webhook URL, which may hold a secret.
func (r scanRecord) public() scanRecord {
	r.Events = nil
	r.WebhookURL = ""
	return r
}

// emitLocked appends an event and wakes the streams. The caller holds sc.mu.
func (sc *scan) emitLocked(typ string, data any) {
	b, err := json.Marshal(data)
	if err != nil {
		b = []byte("null")
	}
	sc.rec.Events = append(sc.rec.Events, Event{Seq: len(sc.rec.Events) + 1, Type: typ, Data: b})
	close(sc.changed)
	if !final(sc.rec.Status) {
		sc.changed = make(chan struct{})
	}
}

// eventsFrom returns the events after seq, whether the scan is over and
// a channel that closes at the next event.
func (sc *scan) eventsFrom(seq int) ([]Event, bool, <-chan struct{}) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var out []Event
	if seq < len(sc.rec.Events) {
		out = append(out, sc.rec.Events[max(seq, 0):]...)
	}
	return out, final(sc.rec.Status), sc.changed
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetID string `json:"target_id"`
		ScanOptions
		WebhookURL string `json:"webhook_url"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	t, ok := s.store.target(req.TargetID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no target %q; POST /v0/targets first", req.TargetID))
		return
	}
	if !t.verifiedAt(s.cfg.Now()) {
		msg := "target " + t.ID + " isn't verified; publish its token and POST /v0/targets/" + t.ID + "/verify"
		if t.Verified != nil {
			msg = "target " + t.ID + "'s verification is over 30 days old; POST /v0/targets/" + t.ID + "/verify again"
		}
		writeError(w, http.StatusForbidden, msg)
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.WebhookURL != "" {
		if s.cfg.WebhookSecret == "" {
			writeError(w, http.StatusBadRequest, "webhooks need the server started with a signing secret (TUNER_WEBHOOK_SECRET)")
			return
		}
		u, err := url.Parse(req.WebhookURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			writeError(w, http.StatusBadRequest, "webhook_url: want an http or https URL")
			return
		}
		if !s.cfg.WebhookAllowPrivate && !publicHost(u.Hostname()) {
			writeError(w, http.StatusBadRequest, "webhook_url: "+u.Hostname()+" is a private or local address; start serve with --webhook-allow-private to allow it")
			return
		}
	}
	now := s.cfg.Now().UTC()
	sc := scanFromRecord(scanRecord{
		ID: newID("s_", 8), TargetID: t.ID, URL: t.URL, Status: statusQueued, Options: req.ScanOptions,
		Created: now, Summary: map[engine.Severity]int{}, Findings: []json.RawMessage{}, WebhookURL: req.WebhookURL,
	})
	sc.host = t.Host
	sc.mu.Lock()
	sc.emitLocked("queued", map[string]string{"id": sc.id})
	sc.mu.Unlock()
	if err := s.store.saveScan(sc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.setActive(sc)
	// The answer is the scan as queued: once pushed, a worker may start
	// or even finish it before the response is written.
	queued := sc.record().public()
	if err := s.queue.push(sc); err != nil {
		// Turned away: as if the request never came.
		s.store.dropActive(sc.id)
		_ = os.Remove(s.store.scanFile(sc.id))
		code := http.StatusTooManyRequests
		if !errors.Is(err, errQueueFull) {
			code = http.StatusServiceUnavailable
		}
		writeError(w, code, err.Error())
		return
	}
	s.logf("scan %s queued for %s", sc.id, t.URL)
	w.Header().Set("Location", "/v0/scans/"+sc.id)
	writeJSON(w, http.StatusAccepted, queued)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.store.scan(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no scan "+r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, sc.record().public())
}

// scanEvents streams a scan's events as Server-Sent Events: everything
// so far (after Last-Event-ID when the client reconnects), then each new
// one, closing after done.
func (s *Server) scanEvents(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.store.scan(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no scan "+r.PathValue("id"))
		return
	}
	var seq int
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		_, _ = fmt.Sscan(v, &seq)
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no") // nginx in front: don't buffer the stream
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		events, over, changed := sc.eventsFrom(seq)
		for _, e := range events {
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Type, e.Data); err != nil {
				return
			}
			seq = e.Seq
		}
		if err := rc.Flush(); err != nil {
			return
		}
		if over {
			return
		}
		select {
		case <-changed:
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// work runs queued scans until the queue closes.
func (s *Server) work() {
	for {
		sc := s.queue.next()
		if sc == nil {
			return
		}
		s.runScan(sc)
		s.queue.done(sc)
	}
}

func (s *Server) runScan(sc *scan) {
	sc.mu.Lock()
	now := s.cfg.Now().UTC()
	sc.rec.Status, sc.rec.Started = statusRunning, &now
	target, opts := sc.rec.URL, sc.rec.Options
	sc.emitLocked("started", map[string]string{"id": sc.id, "url": target})
	sc.mu.Unlock()
	_ = s.store.saveScan(sc)
	s.logf("scan %s started", sc.id)

	// The URL goes in whole, scheme included, so the scan can't take it
	// for a local folder; options were checked to be plain values.
	args := append([]string{"scan", target, "--jsonl", "--no-color", "--max-time", s.cfg.MaxScanTime.String()}, opts.args()...)
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.MaxScanTime+time.Minute)
	defer cancel()
	stdout := &lineWriter{fn: func(line []byte) { s.scanOutput(sc, line) }}
	stderr := &lineWriter{fn: func(line []byte) { s.scanLog(sc, string(line)) }}
	exit, err := s.cfg.Runner(ctx, args, stdout, stderr)
	stdout.flush()
	stderr.flush()

	status, msg := statusDone, ""
	switch {
	case s.ctx.Err() != nil:
		status, msg = statusCanceled, "the server stopped during the scan"
	case err != nil:
		status, msg = statusFailed, err.Error()
	case ctx.Err() != nil:
		status, msg = statusFailed, "the scan ran past its time limit"
	case exit == 130:
		status, msg = statusCanceled, "the scan was interrupted"
	case exit != 0 && exit != 1:
		// 2 and 3 mean the site couldn't be scanned or the flags were
		// wrong; the log holds the scan's own message.
		status, msg = statusFailed, fmt.Sprintf("the scan exited %d; see log", exit)
	}
	s.finish(sc, status, exit, msg)
}

// scanOutput takes one line of the scan's --jsonl output: a finding.
func (s *Server) scanOutput(sc *scan, line []byte) {
	var f struct {
		Severity engine.Severity `json:"severity"`
	}
	if !json.Valid(line) || json.Unmarshal(line, &f) != nil {
		s.scanLog(sc, string(line))
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.rec.Findings) >= maxFindings {
		sc.rec.Truncated = true
		return
	}
	raw := json.RawMessage(bytes.Clone(line))
	sc.rec.Findings = append(sc.rec.Findings, raw)
	sc.rec.Summary[f.Severity]++
	sc.emitLocked("finding", raw)
}

// scanLog keeps a line of the scan's stderr: warnings and errors.
func (s *Server) scanLog(sc *scan, line string) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.rec.Log) >= maxLogLines {
		return
	}
	sc.rec.Log = append(sc.rec.Log, line)
	sc.emitLocked("log", line)
}

// finish records the outcome, saves it, drops the scan from memory and
// sends the webhooks.
func (s *Server) finish(sc *scan, status string, exit int, msg string) {
	sc.mu.Lock()
	now := s.cfg.Now().UTC()
	sc.rec.Status, sc.rec.Finished, sc.rec.Error = status, &now, msg
	if exit >= 0 {
		sc.rec.Exit = &exit
	}
	pub := sc.rec
	pub.Events, pub.Findings, pub.Log = nil, nil, nil
	sc.emitLocked("done", pub.public())
	hook := sc.rec.WebhookURL
	sc.mu.Unlock()
	if err := s.store.saveScan(sc); err != nil {
		s.logf("scan %s: couldn't save: %v", sc.id, err)
	}
	s.store.dropActive(sc.id)
	s.logf("scan %s %s%s", sc.id, status, suffix(msg))
	rec := sc.record()
	if u := s.cfg.WebhookURL; u != "" {
		s.hooks.Go(func() { s.deliver(u, rec, false) }) // the operator's choice
	}
	if hook != "" {
		s.hooks.Go(func() { s.deliver(hook, rec, !s.cfg.WebhookAllowPrivate) })
	}
}

func suffix(msg string) string {
	if msg == "" {
		return ""
	}
	return ": " + msg
}

// lineWriter splits a stream into lines for fn, dropping the rest of
// any line over maxLine.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	skip bool
	fn   func([]byte)
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !lw.skip {
				lw.buf = append(lw.buf, p...)
				if len(lw.buf) > maxLine {
					lw.buf, lw.skip = lw.buf[:0], true
				}
			}
			break
		}
		if !lw.skip {
			lw.buf = append(lw.buf, p[:i]...)
			if len(lw.buf) <= maxLine {
				lw.fn(lw.buf)
			}
		}
		lw.buf, lw.skip = lw.buf[:0], false
		p = p[i+1:]
	}
	return n, nil
}

func (lw *lineWriter) flush() {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if len(lw.buf) > 0 && !lw.skip {
		lw.fn(lw.buf)
	}
	lw.buf, lw.skip = nil, false
}

// queue hands scans to workers in order, one scan per host at a time:
// two scans of one site would double its load and race each other's
// rate limits.
type queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	max     int
	pending []*scan
	busy    map[string]bool
	running int
	closed  bool
}

var errQueueFull = errors.New("too many scans queued; try again once some finish")

func newQueue(max int) *queue {
	q := &queue{max: max, busy: map[string]bool{}}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) push(sc *scan) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case q.closed:
		return errors.New("the server is shutting down")
	case len(q.pending) >= q.max:
		return errQueueFull
	}
	q.pending = append(q.pending, sc)
	q.cond.Broadcast()
	return nil
}

// next blocks until a scan whose host is idle is pending, or the queue
// closes (nil).
func (q *queue) next() *scan {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.closed {
			return nil
		}
		for i, sc := range q.pending {
			if !q.busy[sc.host] {
				q.pending = append(q.pending[:i], q.pending[i+1:]...)
				q.busy[sc.host] = true
				q.running++
				return sc
			}
		}
		q.cond.Wait()
	}
}

func (q *queue) done(sc *scan) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.busy, sc.host)
	q.running--
	q.cond.Broadcast()
}

// close stops the workers and returns the scans that never started.
func (q *queue) close() []*scan {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	left := q.pending
	q.pending = nil
	q.cond.Broadcast()
	return left
}

func (q *queue) counts() (queued, running int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), q.running
}
