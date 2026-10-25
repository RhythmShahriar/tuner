// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// File is a check's fixture file, <name>_test.yaml next to the check. It
// describes mock servers the check must fire on (Positive) and stay quiet
// on (Negative).
type File struct {
	Positive []Case `yaml:"positive"` // mock sites the check must fire on
	Negative []Case `yaml:"negative"` // mock sites the check must stay quiet on
}

// Case is one mock site.
type Case struct {
	Name    string           `yaml:"name"`           // shown in test output
	Secrets bool             `yaml:"expect_secrets"` // masked secrets must be extracted
	TLS     bool             `yaml:"tls"`            // serve over https with a test certificate
	TLSMin  string           `yaml:"tls_min"`        // lowest protocol the server accepts, e.g. "1.0"
	Cert    *Cert            `yaml:"cert"`           // custom certificate; implies tls
	Routes  map[string]Reply `yaml:"routes"`         // replies by path, with or without the query string
	Default *Reply           `yaml:"default"`        // reply for unknown paths; 404 if unset
}

// Cert describes a custom certificate for a TLS fixture.
type Cert struct {
	ExpiresInDays int  `yaml:"expires_in_days"` // negative for an expired certificate
	Untrusted     bool `yaml:"untrusted"`       // signed by an unknown authority
}

// Reply is what the mock server sends for one path.
type Reply struct {
	Status  int               `yaml:"status"` // default 200
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`     // {{path}} becomes the requested path
	BodyHex string            `yaml:"body_hex"` // bytes in hex, for binary replies; sent before Body
}

// bytes is the reply body as sent.
func (r Reply) bytes() []byte {
	b, _ := hex.DecodeString(r.BodyHex)
	return append(b, r.Body...)
}

// bodies returns every body the case can serve, for the leak assertions.
func (c Case) bodies() [][]byte {
	var out [][]byte
	for _, r := range c.Routes {
		out = append(out, r.bytes())
	}
	if c.Default != nil {
		out = append(out, c.Default.bytes())
	}
	return out
}

// server starts the mock site and returns a client that reaches only it.
func (c Case) server() (*httptest.Server, *http.Client, error) {
	srv, client, err := c.start()
	if err != nil {
		return nil, nil, err
	}
	return srv, pin(client, srv.Listener.Addr().String()), nil
}

// pin returns a copy of client that connects only to addr, the fixture
// server's listener. Fixtures come from pull requests and third-party
// checks directories and the engine follows the home page's redirect, so
// without this a fixture answering / with a redirect could make CI or a
// contributor's machine send requests to any host, internal ones included.
// An off-host redirect is an error, so the case fails and says why.
func pin(client *http.Client, addr string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if base, ok := client.Transport.(*http.Transport); ok {
		tr = base.Clone()
	}
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr.DialContext = func(ctx context.Context, network, to string) (net.Conn, error) {
		if to != addr {
			return nil, fmt.Errorf("fixture tried to reach %s; only the fixture server %s is allowed", to, addr)
		}
		return dialer.DialContext(ctx, network, to)
	}
	tr.DialTLSContext = nil
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != addr {
				return fmt.Errorf("fixture redirects to %s; only the fixture server %s is allowed", req.URL.Redacted(), addr)
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after %d redirects", len(via))
			}
			return nil
		},
	}
}

// start starts the mock site and returns a client set up to reach it.
func (c Case) start() (*httptest.Server, *http.Client, error) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A route with a query string (/?rest_route=/wp/v2/users) wins over
		// its bare path, which still answers any other query, as most
		// sites ignore query strings they don't know.
		reply, ok := c.Routes[r.URL.RequestURI()]
		if !ok {
			reply, ok = c.Routes[r.URL.Path]
		}
		if !ok {
			if c.Default == nil {
				http.NotFound(w, r)
				return
			}
			reply = *c.Default
			reply.Body = strings.ReplaceAll(reply.Body, "{{path}}", r.URL.Path)
		}
		for k, v := range reply.Headers {
			w.Header().Set(k, v)
		}
		if reply.Status == 0 {
			reply.Status = http.StatusOK
		}
		w.WriteHeader(reply.Status)
		_, _ = w.Write(reply.bytes())
	})
	if !c.TLS && c.Cert == nil && c.TLSMin == "" {
		srv := httptest.NewServer(h)
		return srv, srv.Client(), nil
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // legacy-TLS probes fail handshakes on purpose
	srv.TLS = &tls.Config{}                          //nolint:gosec // fixtures test old protocols on purpose
	switch c.TLSMin {
	case "":
	case "1.0":
		srv.TLS.MinVersion = tls.VersionTLS10
	default:
		return nil, nil, fmt.Errorf("tls_min %q: only 1.0 is supported", c.TLSMin)
	}
	if c.Cert == nil {
		srv.StartTLS()
		return srv, srv.Client(), nil
	}
	cert, leaf, err := testCert(time.Duration(c.Cert.ExpiresInDays) * 24 * time.Hour)
	if err != nil {
		return nil, nil, err
	}
	srv.TLS.Certificates = []tls.Certificate{cert}
	srv.StartTLS()
	roots := x509.NewCertPool()
	if !c.Cert.Untrusted {
		roots.AddCert(leaf)
	}
	// Skip verification so expired or untrusted sites can still be scanned,
	// as with --insecure; the probe verifies against roots itself.
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: true}} //nolint:gosec // see above
	return srv, &http.Client{Transport: tr}, nil
}

// testCert makes a self-signed certificate for 127.0.0.1 that expires in ttl.
func testCert(ttl time.Duration) (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	notAfter := time.Now().Add(ttl)
	notBefore := time.Now().Add(-24 * time.Hour)
	if notAfter.Before(notBefore) {
		notBefore = notAfter.Add(-24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tuner test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf, nil
}
