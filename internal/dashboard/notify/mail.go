package notify

import (
	"bytes"
	_ "embed"
	"html/template"
)

//go:embed mail.html
var mailLayout string

var mailTemplate = template.Must(template.New("mail").Funcs(template.FuncMap{
	"severity": severityLabel,
	// sevClass picks the colour of a severity's dot, among the layout's
	// classes.
	"sevClass": func(s string) string {
		switch s {
		case "critical", "high", "medium", "low":
			return s
		}
		return ""
	},
}).Parse(mailLayout))

var eventLabels = map[string]string{
	EventEmergency: "Emergency", EventReminder: "Reminder", EventStale: "Stale",
	EventRecovered: "Reporting again", EventDigest: "Weekly digest", EventTest: "Test",
}

// mailView is what the layout shows of a message.
type mailView struct {
	*Message
	Title  string // cleaned: no line breaks
	Label  string // the kind of message, as a badge
	Danger bool
}

// HTML is the message as an email's HTML part.
func (m *Message) HTML() (string, error) {
	label := eventLabels[m.Event]
	if label == "" {
		label = "Notification"
	}
	var b bytes.Buffer
	v := mailView{Message: m, Title: Clean(m.Title), Label: label, Danger: m.Event == EventEmergency}
	if err := mailTemplate.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}
