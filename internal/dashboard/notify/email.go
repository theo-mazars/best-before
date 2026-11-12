package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTP security modes.
const (
	smtpSTARTTLS = "starttls"
	smtpTLS      = "tls"
	smtpNone     = "none" // only to this machine
)

var emailType = &Type{
	Name:  "email",
	Label: "Email",
	Help:  "Email through an SMTP server. Emails include the HTML and plain text versions of every message.",
	Fields: []Field{
		{Name: "host", Label: "SMTP server", Required: true, Help: "e.g. smtp.example.org"},
		{Name: "port", Label: "Port", Default: "587", Help: "Usually 587 with STARTTLS, 465 with TLS."},
		{Name: "security", Label: "Security", Options: []string{smtpSTARTTLS, smtpTLS, smtpNone}, Help: "The server's certificate is always checked. none is only allowed for a relay on this machine (localhost)."},
		{Name: "username", Label: "Username", Help: "Optional."},
		{Name: "password", Label: "Password", Secret: true, Help: "Optional. Stored encrypted."},
		{Name: "from", Label: "From", Required: true, Help: "e.g. Best Before <bestbefore@example.org>"},
		{Name: "to", Label: "To", Required: true, Help: "One or more addresses, separated by commas."},
	},
	Digest: true,
	build:  newEmail,
}

type email struct {
	host, port, security string
	username, password   string
	from                 *mail.Address
	to                   []*mail.Address
}

func newEmail(v Values) (Sender, error) {
	e := &email{host: v["host"], port: v["port"], security: v["security"], username: v["username"], password: v["password"]}
	if p, err := strconv.Atoi(e.port); err != nil || p < 1 || p > 65535 {
		return nil, errors.New("Port must be a number from 1 to 65535")
	}
	if e.security == smtpNone && !isLocalhost(e.host) {
		return nil, errors.New("Security none is only allowed for an SMTP server on this machine (localhost): emails list every vulnerable package")
	}
	var err error
	if e.from, err = mail.ParseAddress(v["from"]); err != nil {
		return nil, fmt.Errorf("From is not an email address: %w", err)
	}
	if e.to, err = mail.ParseAddressList(v["to"]); err != nil || len(e.to) == 0 {
		return nil, errors.New("To must be one or more email addresses, separated by commas")
	}
	return e, nil
}

func isLocalhost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (e *email) Send(ctx context.Context, m *Message) error {
	msg, err := e.compose(m, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	addr := net.JoinHostPort(e.host, e.port)
	tlsConfig := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{}
	var conn net.Conn
	if e.security == smtpTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if e.security == smtpSTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server does not offer STARTTLS; choose security tls if it uses port 465")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if e.username != "" {
		// PlainAuth refuses to send the password without TLS, but to localhost.
		if err := c.Auth(smtp.PlainAuth("", e.username, e.password, e.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.from.Address); err != nil {
		return err
	}
	for _, to := range e.to {
		if err := c.Rcpt(to.Address); err != nil {
			return fmt.Errorf("%s: %w", to.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// compose writes the message, with plain text and HTML versions.
func (e *email) compose(m *Message, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	to := make([]string, len(e.to))
	for i, a := range e.to {
		to[i] = a.String()
	}
	text := m.Text()
	if m.URL != "" {
		text += "\n\nOpen in Best Before: " + m.URL
	}
	html, err := m.HTML()
	if err != nil {
		return nil, err
	}
	header := [][2]string{
		{"From", e.from.String()},
		{"To", strings.Join(to, ", ")},
		// Q-encoding also encodes any line break, so the subject cannot add headers.
		{"Subject", mime.QEncoding.Encode("utf-8", Clean(m.Title))},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + strings.ToLower(rand.Text()) + "@bestbefore>"},
		{"Auto-Submitted", "auto-generated"},
		{"MIME-Version", "1.0"},
	}
	for _, h := range header {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}

	mw := multipart.NewWriter(&b)
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary())
	for _, part := range []struct{ kind, body string }{{"text/plain", text}, {"text/html", html}} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.kind + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		if err := writeQP(w, part.body); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeQP(w interface{ Write([]byte) (int, error) }, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(strings.ReplaceAll(s, "\n", "\r\n"))); err != nil {
		return err
	}
	return qp.Close()
}
