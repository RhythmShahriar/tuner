// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ErrLocked means another run holds the state folder's lock.
var ErrLocked = errors.New("another run of this watch is still going")

// LockName is the lock file inside the state folder.
const LockName = "watch.lock"

// Lock takes the state folder's lock so two runs of one watch never
// overlap, whether they come from one long-running watch or from a cron
// job that calls watch --once next to it. The operating system drops the
// lock when the process exits, so a crashed run never leaves it stuck.
// unlock releases it.
func Lock(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, LockName)
	f, err := lockFile(path)
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w (lock %s)", ErrLocked, path)
		}
		return nil, err
	}
	// The PID and start time are for people looking at the file; the
	// lock itself is the OS lock on the open file.
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + " " + time.Now().UTC().Format(time.RFC3339) + "\n")
	return func() { _ = f.Close(); releaseLock(path) }, nil
}
