// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/checks"
)

// Every check ships with <name>_test.yaml next to it, describing mock
// servers it must fire on (positive) and stay quiet on (negative).
type fixtureFile struct {
	Positive []fixtureCase `yaml:"positive"`
	Negative []fixtureCase `yaml:"negative"`
}

type fixtureCase struct {
	Name    string                  `yaml:"name"`
	Secrets bool                    `yaml:"expect_secrets"` // masked secrets must be extracted
	TLS     bool                    `yaml:"tls"`
	TLSMin  string                  `yaml:"tls_min"` // lowest protocol the server accepts, e.g. "1.0"
	Cert    *fixtureCert            `yaml:"cert"`    // custom certificate; implies tls
	Routes  map[string]fixtureReply `yaml:"routes"`
	Default *fixtureReply           `yaml:"default"` // reply for unknown paths; 404 if unset
}

type fixtureCert struct {
	ExpiresInDays int  `yaml:"expires_in_days"` // negative for an expired certificate
	Untrusted     bool `yaml:"untrusted"`
}

type fixtureReply struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	BodyHex string            `yaml:"body_hex"`
}

// server starts the mock site and returns a client set up to reach it.
func (f fixtureCase) server(t *testing.T) (*httptest.Server, *http.Client) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply, ok := f.Routes[r.URL.Path]
		if !ok {
			if f.Default == nil {
				http.NotFound(w, r)
				return
			}
			reply = *f.Default
			reply.Body = strings.ReplaceAll(reply.Body, "{{path}}", r.URL.Path)
		}
		for k, v := range reply.Headers {
			w.Header().Set(k, v)
		}
		if reply.Status == 0 {
			reply.Status = 200
		}
		w.WriteHeader(reply.Status)
		if reply.BodyHex != "" {
			b, _ := hex.DecodeString(reply.BodyHex)
			w.Write(b)
		}
		w.Write([]byte(reply.Body))
	})
	if !f.TLS && f.Cert == nil && f.TLSMin == "" {
		srv := httptest.NewServer(h)
		return srv, srv.Client()
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // legacy-TLS probes fail handshakes on purpose
	srv.TLS = &tls.Config{}
	switch f.TLSMin {
	case "":
	case "1.0":
		srv.TLS.MinVersion = tls.VersionTLS10
	default:
		t.Fatalf("tls_min %q: only 1.0 is supported", f.TLSMin)
	}
	if f.Cert == nil {
		srv.StartTLS()
		return srv, srv.Client()
	}
	cert, leaf := testCert(t, time.Duration(f.Cert.ExpiresInDays)*24*time.Hour)
	srv.TLS.Certificates = []tls.Certificate{cert}
	srv.StartTLS()
	roots := x509.NewCertPool()
	if !f.Cert.Untrusted {
		roots.AddCert(leaf)
	}
	// Skip verification so expired or untrusted sites can still be scanned,
	// as with --insecure; the probe verifies against roots itself.
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: true}}
	return srv, &http.Client{Transport: tr}
}

// testCert makes a self-signed certificate for 127.0.0.1 that expires in ttl.
func testCert(t *testing.T, ttl time.Duration) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf
}

func TestCheckFixtures(t *testing.T) {
	all, err := LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		t.Run(c.ID, func(t *testing.T) {
			name := strings.TrimSuffix(c.File, ".yaml") + "_test.yaml"
			data, err := fs.ReadFile(checks.FS, name)
			if err != nil {
				t.Fatalf("missing fixture %s: every check needs positive and negative cases", name)
			}
			var fx fixtureFile
			dec := yaml.NewDecoder(strings.NewReader(string(data)))
			dec.KnownFields(true)
			if err := dec.Decode(&fx); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(fx.Positive) == 0 || len(fx.Negative) == 0 {
				t.Fatalf("%s: needs at least one positive and one negative case", name)
			}
			for _, fc := range fx.Positive {
				got := runFixture(t, c, fc)
				if len(got) == 0 {
					t.Errorf("positive %q: no finding", fc.Name)
				}
				for _, f := range got {
					if fc.Secrets && len(f.Evidence.Secrets) == 0 {
						t.Errorf("positive %q: expected masked secrets, found none", fc.Name)
					}
				}
			}
			for _, fc := range fx.Negative {
				if got := runFixture(t, c, fc); len(got) != 0 {
					t.Errorf("negative %q: unexpected finding on %s: %v", fc.Name, got[0].Path, got[0].Evidence.Matched)
				}
			}
		})
	}
}

func runFixture(t *testing.T, c *Check, fc fixtureCase) []Finding {
	t.Helper()
	srv, client := fc.server(t)
	defer srv.Close()
	s := New([]*Check{c}, Options{UserAgent: "rhythm-tuner/test", HTTPClient: client})
	res, err := s.Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatalf("%q: scan: %v", fc.Name, err)
	}
	for _, f := range res.Findings {
		for _, sec := range f.Evidence.Secrets {
			if !strings.Contains(sec.Masked, "•") {
				t.Errorf("%q: secret %v is not masked", fc.Name, sec)
			}
		}
	}
	return res.Findings
}
