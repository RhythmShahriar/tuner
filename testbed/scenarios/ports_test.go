// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// The fixture servers listen only on this port range, so a run never
// collides with services on ephemeral ports and a firewall rule can name
// it. TUNER_SCENARIO_PORTS overrides it, e.g. "30000-30019".
const defaultPorts = "20240-20259"

// portPool hands out ports from the range. A scenario takes every port it
// needs at once, so scenarios running in parallel can't deadlock holding
// half of what they need.
type portPool struct {
	mu    sync.Mutex
	cond  *sync.Cond
	free  []int
	total int
}

func newPortPool(spec string) (*portPool, error) {
	lo, hi, ok := strings.Cut(spec, "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return nil, fmt.Errorf("port range %q: want e.g. %s", spec, defaultPorts)
	}
	p := &portPool{}
	p.cond = sync.NewCond(&p.mu)
	for port := a; port <= b; port++ {
		p.free = append(p.free, port)
	}
	p.total = len(p.free)
	return p, nil
}

func portsFromEnv() (*portPool, error) {
	spec := os.Getenv("TUNER_SCENARIO_PORTS")
	if spec == "" {
		spec = defaultPorts
	}
	return newPortPool(spec)
}

// listen opens one listener per host, each on a free port from the pool.
// Ports held by something outside the suite are skipped. While other
// scenarios hold ports it waits for them; it fails only when the range
// can't supply len(hosts) usable ports.
func (p *portPool) listen(hosts []string) ([]net.Listener, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(hosts) > p.total {
		return nil, fmt.Errorf("the scenario needs %d ports; the range has %d", len(hosts), p.total)
	}
	for {
		if len(p.free) < len(hosts) {
			p.cond.Wait()
			continue
		}
		out, err := p.try(hosts)
		var short *shortError
		if errors.As(err, &short) && len(p.free) < p.total {
			p.cond.Wait() // a port in use elsewhere in the suite may come back
			continue
		}
		return out, err
	}
}

// shortError means every free port was busy outside the suite.
type shortError struct {
	host string
	busy []error
}

func (e *shortError) Error() string {
	return fmt.Sprintf("no free port for %s in the range: %v", e.host, errors.Join(e.busy...))
}

// try takes ports for hosts from the free list. On failure it puts every
// port back.
func (p *portPool) try(hosts []string) ([]net.Listener, error) {
	var out []net.Listener
	var busy []int
	var busyErrs []error
	giveBack := func() {
		for _, o := range out {
			_ = o.(*pooled).Listener.Close()
			p.free = append(p.free, portOf(o))
		}
		p.free = append(p.free, busy...)
	}
	for _, h := range hosts {
		var l net.Listener
		for l == nil && len(p.free) > 0 {
			port := p.free[0]
			p.free = p.free[1:]
			var err error
			if l, err = net.Listen("tcp", net.JoinHostPort(h, strconv.Itoa(port))); err == nil {
				break
			}
			l = nil
			// Tell a busy port from a host the machine can't listen on at
			// all, such as [::1] without IPv6.
			probe, perr := net.Listen("tcp", net.JoinHostPort(h, "0"))
			if perr != nil {
				p.free = append(p.free, port)
				giveBack()
				return nil, &hostError{host: h, err: perr}
			}
			_ = probe.Close()
			busy = append(busy, port)
			busyErrs = append(busyErrs, err)
		}
		if l == nil {
			giveBack()
			return nil, &shortError{host: h, busy: busyErrs}
		}
		out = append(out, &pooled{Listener: l, pool: p, port: portOf(l)})
	}
	// Busy ports go to the back: another scenario may find them free later.
	p.free = append(p.free, busy...)
	return out, nil
}

func (p *portPool) release(port int) {
	p.mu.Lock()
	p.free = append(p.free, port)
	p.mu.Unlock()
	p.cond.Broadcast()
}

// pooled returns its port to the pool when closed.
type pooled struct {
	net.Listener
	pool *portPool
	port int
	once sync.Once
}

func (l *pooled) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { l.pool.release(l.port) })
	return err
}

func portOf(l net.Listener) int {
	if p, ok := l.(*pooled); ok {
		return p.port
	}
	return l.Addr().(*net.TCPAddr).Port
}

// hostError means the machine can't listen on a host at all, e.g. no
// IPv6 loopback. Scenarios that need that host are skipped.
type hostError struct {
	host string
	err  error
}

func (e *hostError) Error() string { return fmt.Sprintf("can't listen on %s: %v", e.host, e.err) }
