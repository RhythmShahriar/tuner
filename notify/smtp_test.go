// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// fakeSMTP is an in-process mail server for one session. It offers
// STARTTLS when tlsCfg is set and records the envelope and message.
type fakeSMTP struct {
	addr   string
	tlsCfg *tls.Config
	got    chan mailSession
}

type mailSession struct {
	auth, from string
	to         []string
	data       string
	tls        bool
}

func startSMTP(t *testing.T, tlsCfg *tls.Config) *fakeSMTP {
	t.Helper()
	l := listen(t)
	s := &fakeSMTP{addr: l.Addr().String(), tlsCfg: tlsCfg, got: make(chan mailSession, 1)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		s.serve(conn)
	}()
	return s
}

func (s *fakeSMTP) serve(conn net.Conn) {
	var sess mailSession
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			ext := []string{"250-fake", "250-AUTH PLAIN"}
			if s.tlsCfg != nil && !sess.tls {
				ext = append(ext, "250-STARTTLS")
			}
			ext[len(ext)-1] = "250 " + ext[len(ext)-1][4:]
			for _, e := range ext {
				_ = tp.PrintfLine("%s", e)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, s.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			sess.tls = true
			tp = textproto.NewConn(tc)
		case "AUTH":
			b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(arg, "PLAIN "))
			sess.auth = string(b)
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			sess.from = arg
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			sess.to = append(sess.to, arg)
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go")
			lines, _ := tp.ReadDotLines()
			sess.data = strings.Join(lines, "\n")
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			s.got <- sess
			return
		default:
			_ = tp.PrintfLine("502 no")
		}
	}
}

// dialTo sends every SMTP connection to addr, so a URL can name a host
// that isn't loopback while the test stays on this machine.
func dialTo(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// selfSigned makes a certificate for mail.example.test.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.test"},
		DNSNames: []string{"mail.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

func TestEmailOnLoopback(t *testing.T) {
	srv := startSMTP(t, nil)
	n, err := Parse("smtp://"+srv.addr+"?to=ops@agency.test,boss@agency.test&from=Tuner+<tuner@agency.test>", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n.String() != "smtp://"+srv.addr {
		t.Errorf("String() = %q", n.String())
	}
	if err := n.Send(context.Background(), Build(newFindings(), "last-week.json", engine.High, "1.2.3")); err != nil {
		t.Fatal(err)
	}
	got := <-srv.got
	if got.from != "FROM:<tuner@agency.test>" || strings.Join(got.to, " ") != "TO:<ops@agency.test> TO:<boss@agency.test>" {
		t.Errorf("envelope: %+v", got)
	}
	for _, want := range []string{
		"Subject: Tuner: 2 new findings (1 critical, 1 high) on 2 sites",
		"To: ops@agency.test, boss@agency.test",
		"Content-Type: text/plain; charset=utf-8",
		"[CRITICAL] .env with AKIA•••••�]0;PWNED� - https://a.test/.env",
		"Sent by rhythm-tuner 1.2.3.",
	} {
		if !strings.Contains(got.data, want) {
			t.Errorf("message lacks %q:\n%s", want, got.data)
		}
	}
	clean(t, []byte(got.data))
}

func TestEmailNeedsTLSOffLoopback(t *testing.T) {
	// No STARTTLS on a remote host: refused before any login or message.
	srv := startSMTP(t, nil)
	n, err := Parse("smtp://me@mail.example.test?to=a@b.test&from=t@b.test", Options{SMTPPassword: "hunter2", Dial: dialTo(srv.addr)})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), Build(newFindings(), "", engine.High, ""))
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Errorf("err = %v", err)
	}

	// With STARTTLS the password goes over TLS.
	cfg, pool := selfSigned(t)
	srv = startSMTP(t, cfg)
	n, err = Parse("smtp://me@mail.example.test?to=a@b.test&from=t@b.test",
		Options{SMTPPassword: "hunter2", Dial: dialTo(srv.addr), TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Build(newFindings(), "", engine.High, "")); err != nil {
		t.Fatal(err)
	}
	got := <-srv.got
	if !got.tls || got.auth != "\x00me\x00hunter2" || !strings.Contains(got.data, "Subject: Tuner: 2 findings") {
		t.Errorf("session: %+v", got)
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	cfg, pool := selfSigned(t)
	l := listen(t)
	tl := tls.NewListener(l, cfg)
	t.Cleanup(func() { _ = tl.Close() })
	s := &fakeSMTP{got: make(chan mailSession, 1)}
	go func() {
		conn, err := tl.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		s.serve(conn)
	}()
	n, err := Parse("smtps://mail.example.test?to=a@b.test&from=t@b.test",
		Options{Dial: dialTo(l.Addr().String()), TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Build(newFindings(), "", engine.High, "")); err != nil {
		t.Fatal(err)
	}
	if got := <-s.got; !strings.Contains(got.data, "[HIGH] gallery") {
		t.Errorf("data:\n%s", got.data)
	}
}
