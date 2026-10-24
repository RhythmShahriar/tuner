// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
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
	Positive []Case `yaml:"positive"`
	Negative []Case `yaml:"negative"`
}

// Case is one mock site.
type Case struct {
	Name    string           `yaml:"name"`
	Secrets bool             `yaml:"expect_secrets"` // masked secrets must be extracted
	TLS     bool             `yaml:"tls"`
	TLSMin  string           `yaml:"tls_min"` // lowest protocol the server accepts, e.g. "1.0"
	Cert    *Cert            `yaml:"cert"`    // custom certificate; implies tls
	Routes  map[string]Reply `yaml:"routes"`
	Default *Reply           `yaml:"default"` // reply for unknown paths; 404 if unset
}

// Cert describes a custom certificate for a TLS fixture.
type Cert struct {
	ExpiresInDays int  `yaml:"expires_in_days"` // negative for an expired certificate
	Untrusted     bool `yaml:"untrusted"`
}

// Reply is what the mock server sends for one path.
type Reply struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	BodyHex string            `yaml:"body_hex"`
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

// server starts the mock site and returns a client set up to reach it.
func (c Case) server() (*httptest.Server, *http.Client, error) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply, ok := c.Routes[r.URL.Path]
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
