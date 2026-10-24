// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/RhythmShahriar/tuner/serve"
)

const serveUsage = `Usage:
  rhythm tuner serve [--listen 127.0.0.1:8080] [--data <dir>] [flags]

Runs Tuner as an HTTP API for agencies and hosts. A site is scanned only
after it proves its owner asked for it: a DNS TXT record at
_tuner-verify.<host> or the file https://<host>/.well-known/tuner-verify.txt
holding the token Tuner hands out. Proof lasts 30 days. Each scan runs as
its own rhythm tuner scan process, one at a time per site.

  GET    /v0/health
  POST   /v0/targets               {"url": "https://example.com"} -> token
  GET    /v0/targets[/{id}], DELETE /v0/targets/{id}
  POST   /v0/targets/{id}/verify   {"method": "dns" | "file"} (both if empty)
  POST   /v0/scans                 {"target_id": "t_...", "profile": "quick",
                                    "tags": [...], "exclude_tags": [...],
                                    "ids": [...], "exclude_ids": [...],
                                    "severity": "high", "no_vulns": false,
                                    "webhook_url": "https://..."}
  GET    /v0/scans/{id}            status, summary, findings and log
  GET    /v0/scans/{id}/events     live Server-Sent Events: queued, started,
                                   finding, log, done

Every request needs "Authorization: Bearer $TUNER_SERVE_TOKEN". Without
the variable the API has no authentication and listens on loopback only.

Flags:
      --listen <addr>        address to listen on (default 127.0.0.1:8080);
                             anything but loopback needs TUNER_SERVE_TOKEN
      --data <dir>           targets and scan results (default: your user
                             cache folder, rhythm/tuner/serve)
      --workers <n>          scans at once across all sites (default 2)
      --max-scan-time <d>    stop a scan after this long (default 30m)
      --max-queue <n>        queued scans before new ones get HTTP 429
                             (default 100)
      --webhook <url>        POST every finished scan here, signed
      --webhook-secret <s>   HMAC-SHA256 key for webhook signatures; prefer
                             TUNER_WEBHOOK_SECRET, which ps can't show
      --exec <binary>        Tuner binary to run scans with (default: this one)

Webhooks carry X-Tuner-Signature: sha256=<hex HMAC-SHA256 of the body>,
X-Tuner-Event: scan.completed and X-Tuner-Delivery: <scan id>. They are
retried after 5s, 30s and 2m when the receiver fails or answers 5xx/429.

Examples:
  TUNER_SERVE_TOKEN=$(openssl rand -hex 32) rhythm tuner serve --listen 0.0.0.0:8080 --data /var/lib/tuner
  curl -H "Authorization: Bearer $TUNER_SERVE_TOKEN" -d '{"url":"https://example.com"}' localhost:8080/v0/targets
`

// cmdServe runs the HTTP API until SIGINT or SIGTERM; see serveUsage.
func cmdServe(args []string, stdout, stderr io.Writer) int {
	cfg, listen, err := planServe(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, serveUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\nrun 'rhythm tuner serve --help' for its flags\n", err)
		return exitUsage
	}
	cfg.Log = stderr
	srv, err := serve.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx, listen); err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	return exitOK
}

// planServe parses serve's flags and environment into a server config
// and the listen address. The address and token are checked here, so a
// refused setup is a usage error before anything starts.
func planServe(args []string) (serve.Config, string, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listen := fs.String("listen", "127.0.0.1:8080", "")
	dataDir := fs.String("data", "", "")
	workers := fs.Int("workers", serve.DefaultWorkers, "")
	maxTime := fs.Duration("max-scan-time", serve.DefaultMaxScanTime, "")
	maxQueue := fs.Int("max-queue", serve.DefaultMaxQueue, "")
	webhook := fs.String("webhook", "", "")
	secret := fs.String("webhook-secret", os.Getenv("TUNER_WEBHOOK_SECRET"), "")
	exe := fs.String("exec", "", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return serve.Config{}, "", err
		}
		return serve.Config{}, "", errors.New(updateFlagError(err, fs))
	}
	switch {
	case len(pos) > 0:
		return serve.Config{}, "", fmt.Errorf("serve takes no targets (got %s); register sites with POST /v0/targets", pos[0])
	case *workers < 1:
		return serve.Config{}, "", fmt.Errorf("--workers %d: want 1 or more", *workers)
	case *maxQueue < 1:
		return serve.Config{}, "", fmt.Errorf("--max-queue %d: want 1 or more", *maxQueue)
	case *maxTime < time.Minute:
		return serve.Config{}, "", fmt.Errorf("--max-scan-time %s: want at least 1m", *maxTime)
	case *webhook != "" && *secret == "":
		return serve.Config{}, "", errors.New("--webhook needs a signing secret: set TUNER_WEBHOOK_SECRET (or --webhook-secret)")
	}
	token := os.Getenv("TUNER_SERVE_TOKEN")
	if err := serve.CheckListen(*listen, token); err != nil {
		return serve.Config{}, "", err
	}
	if *dataDir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return serve.Config{}, "", fmt.Errorf("no user cache folder (%w); pass --data", err)
		}
		*dataDir = filepath.Join(cache, "rhythm", "tuner", "serve")
	}
	if *dataDir, err = filepath.Abs(*dataDir); err != nil {
		return serve.Config{}, "", err
	}
	if *exe == "" {
		if *exe, err = os.Executable(); err != nil {
			return serve.Config{}, "", fmt.Errorf("can't find this binary (%w); pass --exec", err)
		}
	}
	return serve.Config{
		DataDir: *dataDir, Token: token, Workers: *workers, MaxScanTime: *maxTime, MaxQueue: *maxQueue,
		// Scans run in the data folder, so nothing they might write
		// lands in the server's working directory.
		Runner:     serve.ExecRunner(*exe, *dataDir),
		WebhookURL: *webhook, WebhookSecret: *secret,
		UserAgent: fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version),
		Version:   version,
	}, *listen, nil
}
