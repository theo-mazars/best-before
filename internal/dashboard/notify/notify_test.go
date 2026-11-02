package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// capture is a service that records what it receives.
type capture struct {
	srv    *httptest.Server
	bodies chan map[string]any
	header chan http.Header
	status int
}

func newCapture(t *testing.T, tls bool) *capture {
	t.Helper()
	c := &capture{bodies: make(chan map[string]any, 10), header: make(chan http.Header, 10), status: http.StatusOK}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		c.bodies <- body
		c.header <- r.Header
		w.WriteHeader(c.status)
		io.WriteString(w, "reply\nwith a line break")
	})
	if tls {
		c.srv = httptest.NewTLSServer(h)
		// The test server's certificate, checked like any other.
		saved := httpClient
		client := c.srv.Client()
		client.CheckRedirect = saved.CheckRedirect
		httpClient = client
		t.Cleanup(func() { httpClient = saved })
	} else {
		c.srv = httptest.NewServer(h)
	}
	t.Cleanup(c.srv.Close)
	return c
}

func send(t *testing.T, typ string, v Values, m *Message) error {
	t.Helper()
	s, err := TypeByName(typ).New(v)
	if err != nil {
		t.Fatal(err)
	}
	return s.Send(context.Background(), m)
}

var hostileMessage = &Message{
	Event: EventEmergency,
	Title: "Emergency on web-01",
	Text:  "CVE-2026-0001 in [click](https://evil.example) @everyone <!channel> *bold* & more",
	URL:   "https://dashboard.example.vpn/servers/abc",
}

func TestValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		typ  string
		v    Values
		want string
	}{
		"missing topic":         {"ntfy", Values{}, "Topic is required"},
		"ntfy over ftp":         {"ntfy", Values{"server": "ftp://ntfy.example", "topic": "t"}, "https://"},
		"discord over http":     {"discord", Values{"webhook_url": "http://discord.com/api/webhooks/1/x"}, "must be an https:// URL"},
		"slack missing":         {"slack", Values{}, "Webhook URL is required"},
		"plain SMTP over a LAN": {"email", Values{"host": "10.0.0.5", "security": "none", "from": "a@example.org", "to": "b@example.org"}, "only allowed for an SMTP server on this machine"},
		"unknown security":      {"email", Values{"host": "smtp.example.org", "security": "ssl", "from": "a@example.org", "to": "b@example.org"}, "must be one of"},
		"bad port":              {"email", Values{"host": "smtp.example.org", "port": "99999", "from": "a@example.org", "to": "b@example.org"}, "Port"},
		"bad recipient":         {"email", Values{"host": "smtp.example.org", "from": "a@example.org", "to": "nobody"}, "To must be"},
		"line break":            {"ntfy", Values{"topic": "a\nb"}, "control characters"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := TypeByName(tc.typ).New(tc.v)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want %q", err, tc.want)
			}
		})
	}

	// Defaults fill what is left empty.
	if _, err := TypeByName("email").New(Values{"host": "smtp.example.org", "from": "Best Before <a@example.org>", "to": "b@example.org, c@example.org"}); err != nil {
		t.Errorf("email with defaults: %v", err)
	}
	if _, err := TypeByName("email").New(Values{"host": "localhost", "security": "none", "from": "a@example.org", "to": "b@example.org"}); err != nil {
		t.Errorf("plain SMTP to localhost: %v", err)
	}
}

func TestSplit(t *testing.T) {
	settings, secrets := TypeByName("ntfy").Split(Values{"server": "https://ntfy.sh", "topic": "t", "token": "tk_secret"})
	if secrets["token"] != "tk_secret" || settings["token"] != "" || settings["topic"] != "t" || len(secrets) != 1 {
		t.Errorf("settings %v, secrets %v", settings, secrets)
	}
}

func TestNtfy(t *testing.T) {
	c := newCapture(t, false)
	if err := send(t, "ntfy", Values{"server": c.srv.URL + "/", "topic": "bb-alerts", "token": "tk_1"}, hostileMessage); err != nil {
		t.Fatal(err)
	}
	body, h := <-c.bodies, <-c.header
	if body["topic"] != "bb-alerts" || body["title"] != "Emergency on web-01" || body["priority"] != 5.0 ||
		body["click"] != hostileMessage.URL || body["message"] != hostileMessage.Text {
		t.Errorf("body: %v", body)
	}
	if h.Get("Authorization") != "Bearer tk_1" {
		t.Errorf("Authorization: %q", h.Get("Authorization"))
	}

	// The digest does not ring.
	send(t, "ntfy", Values{"server": c.srv.URL, "topic": "t"}, &Message{Event: EventDigest, Title: "Digest", Text: "x"})
	if body, h := <-c.bodies, <-c.header; body["priority"] != 3.0 || h.Get("Authorization") != "" {
		t.Errorf("digest: %v %v", body, h)
	}
}

func TestDiscord(t *testing.T) {
	c := newCapture(t, true)
	if err := send(t, "discord", Values{"webhook_url": c.srv.URL + "/api/webhooks/1/secret"}, hostileMessage); err != nil {
		t.Fatal(err)
	}
	body := <-c.bodies
	content, _ := body["content"].(string)
	if !strings.HasPrefix(content, "**Emergency on web-01**\n") || !strings.HasSuffix(content, "\n"+hostileMessage.URL) {
		t.Errorf("content: %q", content)
	}
	for _, bad := range []string{"[click](", "@everyone", "*bold*"} {
		if strings.Contains(content, bad) {
			t.Errorf("content keeps %q: %q", bad, content)
		}
	}
	if m, _ := body["allowed_mentions"].(map[string]any); m == nil || len(m["parse"].([]any)) != 0 {
		t.Errorf("allowed_mentions: %v", body["allowed_mentions"])
	}

	long := &Message{Title: "t", Text: strings.Repeat("CVE-2026-0001 in openssl\n", 200)}
	send(t, "discord", Values{"webhook_url": c.srv.URL}, long)
	if content := (<-c.bodies)["content"].(string); len(content) > 2000 || !strings.HasSuffix(content, "more on the dashboard.") {
		t.Errorf("long message: %d bytes, ends %q", len(content), content[len(content)-30:])
	}
}

func TestSlack(t *testing.T) {
	c := newCapture(t, true)
	if err := send(t, "slack", Values{"webhook_url": c.srv.URL + "/services/T/B/x"}, hostileMessage); err != nil {
		t.Fatal(err)
	}
	text := (<-c.bodies)["text"].(string)
	if !strings.Contains(text, "&lt;!channel&gt; *bold* &amp; more") || !strings.HasSuffix(text, "<"+hostileMessage.URL+">") {
		t.Errorf("text: %q", text)
	}
}

func TestWebhook(t *testing.T) {
	c := newCapture(t, false)
	m := *hostileMessage
	m.Details = map[string]any{"server": map[string]string{"hostname": "web-01"}}
	if err := send(t, "webhook", Values{"url": c.srv.URL + "/hook?token=x", "authorization": "Bearer abc"}, &m); err != nil {
		t.Fatal(err)
	}
	body, h := <-c.bodies, <-c.header
	if body["event"] != "emergency" || body["text"] != m.Text || body["url"] != m.URL || body["sent_at"] == "" ||
		body["details"].(map[string]any)["server"].(map[string]any)["hostname"] != "web-01" {
		t.Errorf("body: %v", body)
	}
	if h.Get("Authorization") != "Bearer abc" {
		t.Errorf("Authorization: %q", h.Get("Authorization"))
	}
}

func TestFailuresAreReported(t *testing.T) {
	c := newCapture(t, false)
	c.status = http.StatusForbidden
	err := send(t, "webhook", Values{"url": c.srv.URL + "/hook/supersecret"}, hostileMessage)
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "\n") {
		t.Errorf("got %v", err)
	}

	// The secret part of a URL stays out of errors, and so out of logs.
	c.srv.Close()
	err = send(t, "webhook", Values{"url": c.srv.URL + "/hook/supersecret"}, hostileMessage)
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Errorf("got %v", err)
	}

	// Redirects are not followed.
	redirect := httptest.NewServer(http.RedirectHandler("https://elsewhere.example", http.StatusFound))
	defer redirect.Close()
	if err := send(t, "webhook", Values{"url": redirect.URL}, hostileMessage); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("redirect: %v", err)
	}
}

func TestClean(t *testing.T) {
	if got := Clean("web-01\nSubject: forged\r\x00\u2028x"); got != "web-01 Subject: forged   x" {
		t.Errorf("got %q", got)
	}
}

// fakeSMTP accepts one message on localhost, without TLS.
func fakeSMTP(t *testing.T) (port string, got chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		say := func(s string) { io.WriteString(conn, s+"\r\n") }
		say("220 fake ESMTP")
		var transcript strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			transcript.WriteString(strings.TrimSpace(line) + "\n")
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH"):
				say("235 ok")
			case strings.HasPrefix(cmd, "DATA"):
				say("354 go on")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					transcript.WriteString(l)
				}
				say("250 queued")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				got <- transcript.String()
				return
			default:
				say("250 ok")
			}
		}
	}()
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, got
}

func TestEmail(t *testing.T) {
	port, got := fakeSMTP(t)
	m := &Message{
		Event: EventDigest,
		Title: "Digest for web-01\r\nBcc: victim@example.org",
		Text:  "Plain text, with = and été.",
		HTML:  "<p>HTML</p>",
		URL:   "https://dashboard.example.vpn",
	}
	v := Values{"host": "127.0.0.1", "port": port, "security": "none", "username": "bb", "password": "pw",
		"from": "Best Before <bb@example.org>", "to": "ops@example.org, Sam <sam@example.org>"}
	if err := send(t, "email", v, m); err != nil {
		t.Fatal(err)
	}
	transcript := <-got
	for _, want := range []string{
		"MAIL FROM:<bb@example.org>", "RCPT TO:<ops@example.org>", "RCPT TO:<sam@example.org>",
		`From: "Best Before" <bb@example.org>`, "Auto-Submitted: auto-generated",
		"Content-Type: multipart/alternative", "Content-Type: text/plain; charset=utf-8", "Content-Type: text/html; charset=utf-8",
		"Plain text, with =3D and =C3=A9t=C3=A9.", "https://dashboard.example.vpn",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("message lacks %q:\n%s", want, transcript)
		}
	}
	if strings.Contains(transcript, "\nBcc:") {
		t.Errorf("subject added a header:\n%s", transcript)
	}
	for _, line := range strings.Split(transcript, "\n") {
		if subject, ok := strings.CutPrefix(line, "Subject: "); ok {
			decoded, err := new(mime.WordDecoder).DecodeHeader(strings.TrimSpace(subject))
			if err != nil || decoded != "Digest for web-01  Bcc: victim@example.org" {
				t.Errorf("subject %q decodes to %q (%v)", subject, decoded, err)
			}
		}
	}
}

func TestTruncate(t *testing.T) {
	s := strings.Repeat("é", 100)
	got := truncate(s, 51)
	if len(got) > 51 || !strings.HasSuffix(got, "more on the dashboard.") || !strings.HasPrefix(got, "é") {
		t.Errorf("got %q", got)
	}
	if truncate("short", 10) != "short" {
		t.Error("short text changed")
	}
}
