package notify

import (
	"fmt"
	"slices"
	"strings"
)

// Section is a part of a message, such as the digest's emergencies. A
// message with one part, such as an emergency, leaves its title empty.
type Section struct {
	Title string
	Note  string
	Tone  string // ToneDanger, ToneWarning, ToneInfo or empty
	// Count is shown next to the title when above zero.
	Count  int
	Groups []Group
}

// Tones colour a section or a message.
const (
	ToneDanger  = "danger"
	ToneWarning = "warning"
	ToneInfo    = "info"
	ToneOK      = "ok"
)

// Group gathers items, usually those of one server.
type Group struct {
	Title string
	URL   string
	Note  string
	Items []Item
}

// Item is one thing to know, such as a vulnerability or an update. All its
// text is plain; each channel escapes it.
type Item struct {
	Title          string // e.g. CVE-2026-1000, or a package
	URL            string // its advisory
	Severity       string // critical … negligible, unknown; empty when none applies
	CVSS           float64
	KnownExploited bool
	Detail         string // e.g. "libc6 2.36-9 → 2.36-9+deb12u7"
	Where          string // e.g. "host", "image node:22-slim"
	Note           string
}

// rank orders items from the most urgent: known exploited first, then by
// severity and score.
func (it *Item) rank() float64 {
	r := map[string]float64{"negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[it.Severity]*10 + it.CVSS
	if it.KnownExploited {
		r += 100
	}
	return r
}

// facts are what is said of an item after its title.
func (it *Item) facts() []string {
	var out []string
	if it.Severity != "" {
		out = append(out, severityLabel(it.Severity))
	}
	if it.CVSS > 0 {
		out = append(out, fmt.Sprintf("CVSS %.1f", it.CVSS))
	}
	if it.KnownExploited {
		out = append(out, "Known exploited")
	}
	return out
}

// detail is the item's second line.
func (it *Item) detail() string {
	var parts []string
	for _, p := range []string{it.Detail, it.Where} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " · ")
}

func severityLabel(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *Section) heading() string {
	if s.Count > 0 {
		return fmt.Sprintf("%s (%d)", s.Title, s.Count)
	}
	return s.Title
}

// tone is the colour of the whole message.
func (m *Message) tone() string {
	switch m.Event {
	case EventEmergency:
		return ToneDanger
	case EventReminder, EventStale:
		return ToneWarning
	case EventRecovered:
		return ToneOK
	}
	return ToneInfo
}

// Text is the message as plain text, for email's text part, ntfy, Slack and
// webhooks.
func (m *Message) Text() string {
	var blocks []string
	if m.Summary != "" {
		blocks = append(blocks, Clean(m.Summary))
	}
	for _, s := range m.Sections {
		var head []string
		if s.Title != "" {
			head = append(head, strings.ToUpper(Clean(s.heading())))
		}
		if s.Note != "" {
			head = append(head, Clean(s.Note))
		}
		if len(head) > 0 {
			blocks = append(blocks, strings.Join(head, "\n"))
		}
		for _, g := range s.Groups {
			var lines []string
			if g.Title != "" {
				title := Clean(g.Title)
				if g.Note != "" {
					title += " · " + Clean(g.Note)
				}
				lines = append(lines, title)
				if g.URL != "" {
					lines = append(lines, g.URL)
				}
			}
			for _, it := range g.Items {
				lines = append(lines, it.textLines()...)
			}
			if len(lines) > 0 {
				blocks = append(blocks, strings.Join(lines, "\n"))
			}
		}
	}
	if m.Footer != "" {
		blocks = append(blocks, Clean(m.Footer))
	}
	return strings.Join(blocks, "\n\n")
}

// textLines writes an item as a bullet, with its details indented below.
// An item without a severity, such as an update, takes one line.
func (it *Item) textLines() []string {
	if it.Severity == "" {
		line := "- " + Clean(it.Title)
		if d := it.detail(); d != "" {
			line += " " + Clean(d)
		}
		return []string{line}
	}
	lines := []string{"- " + Clean(strings.Join(append([]string{it.Title}, it.facts()...), " · "))}
	if d := it.detail(); d != "" {
		lines = append(lines, "  "+Clean(d))
	}
	if it.Note != "" {
		lines = append(lines, "  "+Clean(it.Note))
	}
	return lines
}

// SortItems puts the most urgent items first, keeping the order of equals.
func SortItems(items []Item) {
	slices.SortStableFunc(items, func(a, b Item) int {
		ra, rb := a.rank(), b.rank()
		switch {
		case ra > rb:
			return -1
		case ra < rb:
			return 1
		}
		return 0
	})
}
