// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package serve

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// childSecrets are environment variables a scan has no use for. They
// are removed from its environment so a scan can't leak them, in a
// verbose log for instance.
var childSecrets = []string{"TUNER_SERVE_TOKEN", "TUNER_WEBHOOK_SECRET"}

// ExecRunner runs scans with the Tuner binary exe, in dir. Canceling a
// scan interrupts it first so it stops cleanly, then kills it if it is
// still running 15 seconds later.
func ExecRunner(exe, dir string) Runner {
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
		cmd := exec.CommandContext(ctx, exe, args...) //nolint:gosec // the configured Tuner binary; args are built from checked options
		cmd.Dir = dir
		cmd.Stdout, cmd.Stderr = stdout, stderr
		cmd.Env = childEnv(os.Environ())
		cmd.Cancel = func() error {
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				return cmd.Process.Kill() // no interrupts on Windows
			}
			return nil
		}
		cmd.WaitDelay = 15 * time.Second
		err := cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		if err != nil {
			return -1, err
		}
		return 0, nil
	}
}

func childEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, s := range childSecrets {
			if strings.EqualFold(name, s) {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}
