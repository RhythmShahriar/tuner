// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// mailer sends a plain-text email over SMTP.
type mailer struct {
	addr     string // host:port
	host     string
	implicit bool // smtps: TLS from the first byte
	user     string
	password string
	from     string
	to       []string
	shown    string
	o        Options
}

// newMailer checks an smtp:// or smtps:// URL. The password must come from
// TUNER_SMTP_PASSWORD: a URL ends up in shell history and CI logs.
func newMailer(u *url.URL, o Options, shown string) (*mailer, error) {
	m := &mailer{host: u.Hostname(), implicit: strings.EqualFold(u.Scheme, "smtps"), shown: shown, o: o}
	port := u.Port()
	if port == "" {
		port = "587"
		if m.implicit {
			port = "465"
		}
	}
	m.addr = net.JoinHostPort(m.host, port)
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			return nil, fmt.Errorf("%s: put the SMTP password in TUNER_SMTP_PASSWORD, not in the URL", shown)
		}
		m.user = u.User.Username()
		m.password = o.SMTPPassword
		if m.password == "" {
			return nil, fmt.Errorf("%s: set TUNER_SMTP_PASSWORD to the password for the SMTP user", shown)
		}
	}
	q := u.Query()
	from, err := mail.ParseAddress(q.Get("from"))
	if err != nil {
		return nil, fmt.Errorf("%s: from=: want one email address", shown)
	}
	m.from = from.Address
	for _, part := range q["to"] {
		list, err := mail.ParseAddressList(part)
		if err != nil {
			return nil, fmt.Errorf("%s: to=: want email addresses separated by commas", shown)
		}
		for _, a := range list {
			m.to = append(m.to, a.Address)
		}
	}
	if len(m.to) == 0 {
		return nil, fmt.Errorf("%s: no to= address", shown)
	}
	return m, nil
}

// String is the URL as shown to the user.
func (m *mailer) String() string { return m.shown }

// Send delivers msg over TLS, failing rather than sending in the clear.
func (m *mailer) Send(ctx context.Context, msg Message) error {
	dial := m.o.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", m.addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	if m.implicit {
		conn = tls.Client(conn, m.tlsConfig())
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if err := m.secure(c); err != nil {
		return err
	}
	if m.user != "" {
		// PlainAuth itself refuses to send the password over a
		// connection without TLS unless the server is on this machine.
		if err := c.Auth(smtp.PlainAuth("", m.user, m.password, m.host)); err != nil {
			return fmt.Errorf("SMTP login failed: %w", err)
		}
	}
	if err := c.Mail(m.from); err != nil {
		return err
	}
	for _, to := range m.to {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(m.compose(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// secure upgrades the connection with STARTTLS. Findings name a client's
// weak spots, so they never cross the network in clear text: a server
// that doesn't offer STARTTLS is refused unless it is on this machine.
func (m *mailer) secure(c *smtp.Client) error {
	if m.implicit {
		return nil
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		return c.StartTLS(m.tlsConfig())
	}
	if loopback(m.host) {
		return nil
	}
	return errors.New("the mail server does not offer STARTTLS; Tuner sends mail only over TLS (or use smtps://)")
}

// tlsConfig is the TLS setup for the mail server: TLS 1.2 or later,
// verified against its host name.
func (m *mailer) tlsConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if m.o.TLSConfig != nil {
		cfg = m.o.TLSConfig.Clone()
	}
	cfg.ServerName = m.host
	return cfg
}

// compose builds the email. Every header value went through SafeText,
// which removes CR and LF, so nothing a site says can add a header.
func (m *mailer) compose(msg Message) []byte {
	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", m.from)
	header("To", strings.Join(m.to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Summary))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(msg.Text(func(s string) string { return s }), "\n", "\r\n"))
	b.WriteString("\r\nSent by rhythm-tuner " + msg.Version + ".\r\n")
	return []byte(b.String())
}
