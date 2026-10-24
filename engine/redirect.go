// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// A scan stays on the host the user named. The home page may redirect to
// the www or apex twin of that host or upgrade http to https; the scan
// follows those. Anything else stops the target unless Options.FollowHost
// is set. Even then the user's headers and cookies only go to the named
// host, never over plain http when the target was https. A site also can't
// point the scan at loopback, link-local or private addresses unless the
// target itself is one: every connection is checked at dial time, so a DNS
// answer that changes mid-scan (rebinding) is caught too.

// RedirectError means the home page redirected somewhere the scan won't go.
type RedirectError struct {
	From, To *url.URL
	Internal bool // To resolves to a loopback, link-local or private address
}

func (e *RedirectError) Error() string {
	from, to := e.From.Host, e.To.Host
	if e.From.Scheme != e.To.Scheme {
		from, to = e.From.Scheme+"://"+from, e.To.Scheme+"://"+to
	}
	if e.Internal {
		return fmt.Sprintf("%s redirects to %s, a local or private address; scan that address directly if you mean to", from, to)
	}
	return fmt.Sprintf("%s redirects to %s; scan that host directly if you own it, or pass --follow-host", from, to)
}

// AddressError means a connection would have reached a loopback,
// link-local or private address while the target is a public host.
type AddressError struct {
	Host string
	Addr netip.Addr
}

func (e *AddressError) Error() string {
	return fmt.Sprintf("refusing to connect to %s at %s: a local or private address while the target is not one", e.Host, e.Addr)
}

// resolver looks up the addresses of a host name.
type resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// lookup returns host's addresses, IPv4 first. An IP literal is its own
// answer. Dials go to these addresses in turn, so IPv4 first avoids a
// long wait on networks with broken IPv6.
func (ss *session) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := ss.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	return addrs, nil
}

// internalHost reports whether host resolves to any internal address. A
// lookup that fails counts as public, the stricter choice.
func (ss *session) internalHost(ctx context.Context, host string) bool {
	addrs, err := ss.lookup(ctx, host)
	return err == nil && slices.ContainsFunc(addrs, internal)
}

// Prefixes that carry an IPv4 address inside an IPv6 one. A gateway or
// relay turns them back into IPv4, so 64:ff9b::a9fe:a9fe reaches
// 169.254.169.254 through NAT64 and 2002:7f00:1:: is 127.0.0.1 over 6to4.
var (
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215; read as /96, the common setup
	v4Compat   = netip.MustParsePrefix("::/96")          // deprecated IPv4-compatible form
	sixToFour  = netip.MustParsePrefix("2002::/16")
	teredo     = netip.MustParsePrefix("2001::/32")
)

// internalV4 are IPv4 ranges outside what netip's predicates cover that
// still never lead to a public site. 100.64.0.0/10 is carrier-grade NAT
// space, where Alibaba Cloud's metadata service lives (100.100.100.200).
var internalV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"; 0.x.x.x can reach the local machine
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
}

// embeddedV4 returns the IPv4 address that a carries for a translation
// or tunneling scheme, if any.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a), nat64Local.Contains(a), v4Compat.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:])), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	case teredo.Contains(a):
		// The client address is stored inverted in the last 32 bits.
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	}
	return netip.Addr{}, false
}

// internal reports whether a is loopback, link-local, private, shared
// (carrier-grade NAT) or otherwise non-public, including when it hides
// in an IPv6 translation or tunnel address.
func internal(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	if v4, ok := embeddedV4(a); ok {
		a = v4
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() {
		return true
	}
	return slices.ContainsFunc(internalV4, func(p netip.Prefix) bool { return p.Contains(a) })
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardDial resolves the host itself and dials the checked addresses, so
// the address that was checked is the one connected to.
func (ss *session) guardDial(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addrs, err := ss.lookup(ctx, host)
		if err != nil {
			// Same shape as the standard dialer's error: "dial tcp: lookup ...".
			return nil, &net.OpError{Op: "dial", Net: network, Err: err}
		}
		var first error
		for _, a := range addrs {
			if !ss.internalOK && internal(a) {
				if first == nil {
					first = &AddressError{Host: host, Addr: a}
				}
				continue
			}
			c, err := dial(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return c, nil
			}
			if first == nil || errors.As(first, new(*AddressError)) {
				first = err
			}
		}
		if first == nil {
			first = &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("no addresses for %s", host)}
		}
		return nil, first
	}
}

// guardTransport returns a copy of rt whose connections go through
// guardDial, or rt itself when that isn't possible: a custom RoundTripper,
// or a proxy, where the dial reaches the proxy and not the site. Redirects
// are still checked by name in checkRedirect then.
func (ss *session) guardTransport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	tr, ok := rt.(*http.Transport)
	if !ok || ss.proxied || tr.DialTLSContext != nil {
		return rt
	}
	tr = tr.Clone()
	dial := tr.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: ss.opts.Timeout}).DialContext
	}
	tr.DialContext = ss.guardDial(dial)
	return tr
}

// effectivePort is u's port, or the scheme's default.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

func normHost(u *url.URL) string { return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".") }

// sameSite reports whether to is the scan's own host as seen from from:
// the same host or its www/apex twin, with the same scheme and port or an
// upgrade from http to https (which usually changes the port).
func sameSite(from, to *url.URL) bool {
	a, b := normHost(from), normHost(to)
	if a != b && strings.TrimPrefix(a, "www.") != strings.TrimPrefix(b, "www.") {
		return false
	}
	switch {
	case from.Scheme == to.Scheme:
		return effectivePort(from) == effectivePort(to)
	case from.Scheme == "http" && to.Scheme == "https":
		return true
	}
	return false
}

// headersFor reports whether the user's headers and cookies may go to u.
// It is checked on every request, not once per scan.
func (ss *session) headersFor(u *url.URL) bool { return sameSite(ss.origin, u) }

// setHeaders puts the user agent and, when u is the scan's own host, the
// user's headers on h. It returns the Host override to use, if any.
func (ss *session) setHeaders(h http.Header, u *url.URL) (host string) {
	for k := range ss.headers {
		h.Del(k)
	}
	h.Set("User-Agent", ss.opts.UserAgent)
	if !ss.headersFor(u) {
		return ""
	}
	for k, vs := range ss.headers {
		if strings.EqualFold(k, "Host") {
			host = vs[0]
			continue
		}
		h[k] = vs
	}
	return host
}

// checkRedirect is the home page client's redirect policy.
func (ss *session) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if !ss.opts.FollowHost && !sameSite(ss.origin, req.URL) {
		return &RedirectError{From: ss.origin, To: req.URL}
	}
	// The dial guard catches internal addresses too but not through a
	// proxy. This check also gives a clearer message.
	if !ss.internalOK && ss.internalHost(req.Context(), req.URL.Hostname()) {
		return &RedirectError{From: ss.origin, To: req.URL, Internal: true}
	}
	// Go copies the first request's headers to every hop and only drops
	// Authorization and Cookie when the domain changes. Custom -H headers
	// would still go along, so apply the scan's own rule to each hop. A
	// Host override is left to Go, which keeps it on relative redirects.
	ss.setHeaders(req.Header, req.URL)
	return nil
}
