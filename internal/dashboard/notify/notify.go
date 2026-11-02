// Package notify sends alerts and digests: by email, to ntfy, Discord or
// Slack, or as JSON to any webhook.
//
// Each kind of channel is described by its fields, from which the dashboard
// builds its settings form; adding a kind means adding a Type.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Events, which say why a message is sent.
const (
	EventEmergency = "emergency"
	EventReminder  = "reminder"  // an emergency still open
	EventStale     = "stale"     // a server stopped reporting
	EventRecovered = "recovered" // a stale server reports again
	EventDigest    = "digest"
	EventTest      = "test"
)

// Message is one notification. Title and Text are plain text: each channel
// escapes them for its own format.
type Message struct {
	Event string
	Title string
	Text  string
	// HTML is an alternative to Text for email; empty for plain text only.
	HTML string
	// URL is the dashboard page to open, if public_url is set.
	URL string
	// Details are sent to webhooks as they are, encoded as JSON.
	Details any
}

// Urgent messages ask for attention now; ntfy rings for them.
func (m *Message) Urgent() bool {
	return m.Event == EventEmergency || m.Event == EventReminder || m.Event == EventStale
}

// Sender delivers messages through one channel.
type Sender interface {
	Send(ctx context.Context, m *Message) error
}

// Field is one setting of a kind of channel.
type Field struct {
	Name  string
	Label string
	Help  string
	// Secret fields are stored encrypted and never shown again.
	Secret   bool
	Required bool
	Default  string
	// Options, if any, are the only values allowed; the first is the default
	// unless Default says otherwise.
	Options []string
}

// Type is a kind of channel.
type Type struct {
	Name   string
	Label  string
	Help   string
	Fields []Field
	// Digest says whether the weekly digest can be sent this way.
	Digest bool
	build  func(v Values) (Sender, error)
}

// Values are a channel's settings and secrets, by field name.
type Values map[string]string

// Types lists every kind of channel, in the order the settings page offers
// them.
var Types = []*Type{emailType, ntfyType, discordType, slackType, webhookType}

func TypeByName(name string) *Type {
	for _, t := range Types {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// New checks a channel's values and returns its sender. Missing values take
// their field's default.
func (t *Type) New(v Values) (Sender, error) {
	v = t.withDefaults(v)
	for _, f := range t.Fields {
		val := v[f.Name]
		if f.Required && val == "" {
			return nil, fmt.Errorf("%s is required", f.Label)
		}
		if len(f.Options) > 0 && !slices.Contains(f.Options, val) {
			return nil, fmt.Errorf("%s must be one of %s", f.Label, strings.Join(f.Options, ", "))
		}
		if len(val) > 2000 || strings.ContainsFunc(val, unicode.IsControl) {
			return nil, fmt.Errorf("%s is too long or contains control characters", f.Label)
		}
	}
	return t.build(v)
}

func (t *Type) withDefaults(v Values) Values {
	out := Values{}
	for _, f := range t.Fields {
		val := strings.TrimSpace(v[f.Name])
		if val == "" && !f.Secret {
			val = f.Default
			if val == "" && len(f.Options) > 0 {
				val = f.Options[0]
			}
		}
		out[f.Name] = val
	}
	return out
}

// Split separates a channel's values into settings and secrets for storage.
func (t *Type) Split(v Values) (settings, secrets Values) {
	settings, secrets = Values{}, Values{}
	for _, f := range t.Fields {
		if f.Secret {
			secrets[f.Name] = v[f.Name]
		} else {
			settings[f.Name] = v[f.Name]
		}
	}
	return settings, secrets
}

// httpClient refuses redirects: a notification goes where it was configured
// to, or fails. Certificates are always checked.
var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not followed")
	},
}

// checkURL accepts https:// URLs, and http:// when plain allows it, for a
// service on a private network.
func checkURL(label, s string, plain bool) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !plain)) {
		if plain {
			return fmt.Errorf("%s must be an https:// URL (or http:// on a private network)", label)
		}
		return fmt.Errorf("%s must be an https:// URL", label)
	}
	return nil
}

// postJSON sends a JSON document and expects a 2xx reply. header is pairs of
// names and values.
func postJSON(ctx context.Context, target string, body any, header ...string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bestbefore")
	for i := 0; i+1 < len(header); i += 2 {
		if header[i+1] != "" {
			req.Header.Set(header[i], header[i+1])
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return redact(err, target)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the service replied %s: %s", resp.Status, Clean(string(reply)))
	}
	return nil
}

// redact keeps a secret URL, such as a Discord webhook, out of errors and
// therefore logs.
func redact(err error, target string) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, perr := url.Parse(target); perr == nil {
			host = u.Host
		}
		return fmt.Errorf("%s %s: %w", uerr.Op, host, uerr.Err)
	}
	return err
}

// Clean makes a value from an agent safe to put on a line of plain text:
// control characters, which could start new lines, become spaces.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}

// truncate shortens s to at most n bytes, at a line if it can, saying that
// there is more.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const more = "\n… more on the dashboard."
	cut := n - len(more)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if i := strings.LastIndexByte(s[:cut], '\n'); i > cut/2 {
		cut = i
	}
	return s[:cut] + more
}
