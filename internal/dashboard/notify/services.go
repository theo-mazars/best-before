package notify

import (
	"context"
	"strings"
	"time"
)

var ntfyType = &Type{
	Name:  "ntfy",
	Label: "ntfy",
	Help:  "Push notifications to your phone through ntfy.sh or your own ntfy server. Emergencies ring at the highest priority.",
	Fields: []Field{
		{Name: "server", Label: "Server", Default: "https://ntfy.sh", Help: "https://, or http:// for a server on your private network."},
		{Name: "topic", Label: "Topic", Required: true, Help: "On ntfy.sh, anyone who knows the topic can read it: pick a long random name, or use an access token."},
		{Name: "token", Label: "Access token", Secret: true, Help: "Optional. Needed for a protected topic."},
	},
	Digest: true,
	build: func(v Values) (Sender, error) {
		if err := checkURL("Server", v["server"], true); err != nil {
			return nil, err
		}
		return &ntfy{server: strings.TrimSuffix(v["server"], "/"), topic: v["topic"], token: v["token"]}, nil
	},
}

type ntfy struct{ server, topic, token string }

// Send publishes as JSON, so that titles need no header encoding.
// https://docs.ntfy.sh/publish/#publish-as-json
func (n *ntfy) Send(ctx context.Context, m *Message) error {
	priority, tags := 3, []string{"information_source"}
	if m.Urgent() {
		priority, tags = 5, []string{"rotating_light"}
	}
	body := map[string]any{
		"topic":    n.topic,
		"title":    m.Title,
		"message":  truncate(m.Text, 4000),
		"priority": priority,
		"tags":     tags,
	}
	if m.URL != "" {
		body["click"] = m.URL
	}
	auth := ""
	if n.token != "" {
		auth = "Bearer " + n.token
	}
	return postJSON(ctx, n.server, body, "Authorization", auth)
}

var discordType = &Type{
	Name:  "discord",
	Label: "Discord",
	Help:  "Messages in a Discord channel, through a webhook: in the channel's settings, Integrations › Webhooks › New Webhook › Copy Webhook URL.",
	Fields: []Field{
		{Name: "webhook_url", Label: "Webhook URL", Secret: true, Required: true, Help: "Anyone with this URL can post to the channel: it is stored encrypted."},
	},
	Digest: true,
	build: func(v Values) (Sender, error) {
		if err := checkURL("Webhook URL", v["webhook_url"], false); err != nil {
			return nil, err
		}
		return &discord{url: v["webhook_url"]}, nil
	},
}

type discord struct{ url string }

// https://discord.com/developers/docs/resources/webhook#execute-webhook
func (d *discord) Send(ctx context.Context, m *Message) error {
	content := "**" + discordEscape(m.Title) + "**\n" + discordEscape(m.Text)
	if m.URL != "" {
		content += "\n" + m.URL
	}
	return postJSON(ctx, d.url, map[string]any{
		"content": truncate(content, 2000),
		// Names from servers must never ping @everyone.
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
}

// discordEscape stops Discord's Markdown from reading formatting, links or
// headings into text that comes from servers.
var discordEscaper = strings.NewReplacer(
	`\`, `\\`, `*`, `\*`, `_`, `\_`, `~`, `\~`, "`", "\\`", `|`, `\|`,
	`>`, `\>`, `<`, `\<`, `[`, `\[`, `]`, `\]`, `(`, `\(`, `)`, `\)`, `#`, `\#`, `@`, "@​",
)

func discordEscape(s string) string { return discordEscaper.Replace(s) }

var slackType = &Type{
	Name:  "slack",
	Label: "Slack",
	Help:  "Messages in a Slack channel, through an incoming webhook: create a Slack app, turn on Incoming Webhooks and add one for the channel.",
	Fields: []Field{
		{Name: "webhook_url", Label: "Webhook URL", Secret: true, Required: true, Help: "Starts with https://hooks.slack.com/services/. Anyone with it can post to the channel: it is stored encrypted."},
	},
	Digest: true,
	build: func(v Values) (Sender, error) {
		if err := checkURL("Webhook URL", v["webhook_url"], false); err != nil {
			return nil, err
		}
		return &slack{url: v["webhook_url"]}, nil
	},
}

type slack struct{ url string }

// https://api.slack.com/messaging/webhooks
func (s *slack) Send(ctx context.Context, m *Message) error {
	text := "*" + slackEscape(m.Title) + "*\n" + slackEscape(m.Text)
	if m.URL != "" {
		text += "\n<" + m.URL + ">"
	}
	return postJSON(ctx, s.url, map[string]any{"text": truncate(text, 3500)})
}

// slackEscape escapes the three characters Slack requires, which also stops
// text from servers from making links or mentions.
// https://api.slack.com/reference/surfaces/formatting#escaping
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace

var webhookType = &Type{
	Name:  "webhook",
	Label: "Webhook",
	Help:  "A JSON POST to any URL, for your own automation. The body has event, title, text, url, sent_at and details.",
	Fields: []Field{
		{Name: "url", Label: "URL", Secret: true, Required: true, Help: "https://, or http:// for a service on your private network. Stored encrypted, as it often holds a token."},
		{Name: "authorization", Label: "Authorization header", Secret: true, Help: "Optional, e.g. Bearer followed by a token."},
	},
	Digest: true,
	build: func(v Values) (Sender, error) {
		if err := checkURL("URL", v["url"], true); err != nil {
			return nil, err
		}
		return &webhook{url: v["url"], authorization: v["authorization"]}, nil
	},
}

type webhook struct{ url, authorization string }

func (w *webhook) Send(ctx context.Context, m *Message) error {
	return postJSON(ctx, w.url, map[string]any{
		"event":   m.Event,
		"title":   m.Title,
		"text":    m.Text,
		"url":     m.URL,
		"sent_at": time.Now().UTC().Format(time.RFC3339),
		"details": m.Details,
	}, "Authorization", w.authorization)
}
