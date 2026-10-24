// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Scenarios that need these list windows in skip_on; the errors only show
// when one forgets to.

func mkfifo(string) error { return errors.New("named pipes in a folder need a Unix system") }

func listenUnix(string) (io.Closer, error) {
	return nil, errors.New("socket files need a Unix system")
}

func sendSignal(p *os.Process, name string) error {
	if name == "KILL" {
		return p.Kill()
	}
	return fmt.Errorf("can't send %s to a process on Windows", name)
}
