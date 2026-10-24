// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/RhythmShahriar/tuner/matchers"
)

// tlsInfo inspects the home page's TLS handshake: certificate expiry,
// whether the chain and hostname verify, and which obsolete protocol
// versions the server still accepts.
func (ss *session) tlsInfo(ctx context.Context, home *matchers.Response) *matchers.TLSInfo {
	st := home.TLSState
	if st == nil || len(st.PeerCertificates) == 0 {
		return nil
	}
	leaf := st.PeerCertificates[0]
	info := &matchers.TLSInfo{Version: tls.VersionName(st.Version), NotAfter: leaf.NotAfter}

	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: home.URL.Hostname(), Roots: ss.roots, Intermediates: inter})
	var invalid x509.CertificateInvalidError
	// Expiry has its own check; don't report it twice as "untrusted". x509
	// uses the same reason for not-yet-valid, which stays "untrusted".
	expired := errors.As(err, &invalid) && invalid.Reason == x509.Expired && time.Now().After(leaf.NotAfter)
	if err != nil && !expired {
		info.VerifyError = err.Error()
	}

	if !ss.proxied {
		info.Legacy = ss.legacyVersions(ctx, home.URL)
	}
	return info
}

func (ss *session) legacyVersions(ctx context.Context, u *url.URL) []string {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	var suites []uint16
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, cs.ID)
	}
	var out []string
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if ss.lim.wait(ctx) != nil {
			return out
		}
		ss.requests.Add(1)
		d := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: ss.opts.Timeout},
			Config: &tls.Config{
				ServerName:         u.Hostname(),
				MinVersion:         v, //nolint:gosec // probing whether obsolete versions are accepted
				MaxVersion:         v,
				CipherSuites:       suites,
				InsecureSkipVerify: true, //nolint:gosec // only the protocol version matters here
			},
		}
		if conn, err := d.DialContext(ctx, "tcp", addr); err == nil {
			_ = conn.Close()
			out = append(out, tls.VersionName(v))
		}
	}
	return out
}
