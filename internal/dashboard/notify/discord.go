package notify

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type discord struct{ url string }

// Discord's limits, counted in characters, with a margin for emoji that
// count twice.
// https://discord.com/developers/docs/resources/message#embed-object-embed-limits
const (
	discordTotal       = 5800 // 6000 across every embed of a message
	discordDescription = 4000 // 4096
	discordTitle       = 256
	discordMaxEmbeds   = 10
	// discordReserve keeps room for each section still to come.
	discordReserve = 150
)

// DiscordEmbed is one block of a Discord message.
type DiscordEmbed struct {
	Title       string         `json:"title,omitempty"`
	URL         string         `json:"url,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Footer      *discordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

// https://discord.com/developers/docs/resources/webhook#execute-webhook
func (d *discord) Send(ctx context.Context, m *Message) error {
	return postJSON(ctx, d.url, map[string]any{
		"embeds": DiscordEmbeds(m, time.Now()),
		// Names from servers must never ping @everyone.
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
}

// DiscordEmbeds lays a message out as Discord embeds: the first one with its
// title and summary, then one per titled section. What does not fit is left
// to the dashboard, keeping the most urgent items.
func DiscordEmbeds(m *Message, now time.Time) []DiscordEmbed {
	main := DiscordEmbed{
		Title: cut(Clean(m.Title), discordTitle),
		URL:   safeLink(m.URL),
		Color: discordColour(m.tone()),
	}
	footer := "Best Before"
	if m.Footer != "" {
		footer = cut(Clean(m.Footer), 500) + " · Best Before"
	}
	summary := ""
	if m.Summary != "" {
		summary = discordEscape(Clean(m.Summary))
	}
	var titled []Section
	var untitled []Section
	for _, s := range m.Sections {
		if s.Title == "" {
			untitled = append(untitled, s)
		} else {
			titled = append(titled, s)
		}
	}
	titled = titled[:min(len(titled), discordMaxEmbeds-1)]

	left := discordTotal - runes(main.Title) - runes(footer) - runes(summary)
	for _, s := range titled {
		left -= runes(s.heading())
	}
	more := len(untitled) + len(titled)
	body := func(s *Section, room int) string {
		more--
		room = min(room, left-more*discordReserve, discordDescription)
		text := discordSection(s, room, m.URL)
		left -= runes(text)
		return text
	}

	parts := []string{}
	if summary != "" {
		parts = append(parts, summary)
	}
	for i := range untitled {
		parts = append(parts, body(&untitled[i], discordDescription-runes(strings.Join(parts, "\n\n"))-2))
	}
	main.Description = strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), "\n\n")
	embeds := []DiscordEmbed{main}
	for i := range titled {
		s := &titled[i]
		embeds = append(embeds, DiscordEmbed{
			Title:       cut(Clean(s.heading()), discordTitle),
			Description: body(s, discordDescription),
			Color:       discordColour(s.Tone),
		})
	}
	last := &embeds[len(embeds)-1]
	last.Footer = &discordFooter{Text: footer}
	last.Timestamp = now.UTC().Format(time.RFC3339)
	return embeds
}

// discordSection writes a section in at most room characters. When its
// items do not all fit, the most urgent are kept, in their order, and a
// last line says how many more there are.
func discordSection(s *Section, room int, more string) string {
	type entry struct {
		group, item int // item -1 for a group without items
		text        string
		rank        float64
	}
	var entries []entry
	headers := make([]string, len(s.Groups))
	for gi, g := range s.Groups {
		headers[gi] = discordGroup(&g)
		if len(g.Items) == 0 {
			entries = append(entries, entry{group: gi, item: -1, rank: 1e9})
		}
		for ii := range g.Items {
			it := &g.Items[ii]
			entries = append(entries, entry{group: gi, item: ii, text: discordItem(it), rank: it.rank()})
		}
	}
	note := ""
	if s.Note != "" {
		note = "-# " + discordEscape(Clean(s.Note))
	}

	// Pick from the most urgent while they fit, keeping room to say how
	// many are left out.
	order := make([]int, len(entries))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		switch ra, rb := entries[a].rank, entries[b].rank; {
		case ra > rb:
			return -1
		case ra < rb:
			return 1
		}
		return 0
	})
	const moreRoom = 60
	used := runes(note) + 1
	chosen := make([]bool, len(entries))
	shownGroup := make([]bool, len(s.Groups))
	omitted := 0
	for _, i := range order {
		e := entries[i]
		cost := runes(e.text) + 1
		if !shownGroup[e.group] && headers[e.group] != "" {
			cost += runes(headers[e.group]) + 2
		}
		if used+cost > room-moreRoom {
			if e.item >= 0 {
				omitted++
			}
			continue
		}
		used += cost
		chosen[i] = true
		shownGroup[e.group] = true
	}

	var b strings.Builder
	if note != "" {
		b.WriteString(note)
	}
	for gi := range s.Groups {
		if !shownGroup[gi] {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
			if headers[gi] != "" {
				b.WriteString("\n")
			}
		}
		if headers[gi] != "" {
			b.WriteString(headers[gi])
		}
		for i, e := range entries {
			if chosen[i] && e.group == gi && e.item >= 0 {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				b.WriteString(e.text)
			}
		}
	}
	if omitted > 0 {
		line := fmt.Sprintf("… and %d more", omitted)
		if link := safeLink(more); link != "" {
			line = "[" + line + " on the dashboard](" + link + ")"
		} else {
			line += " on the dashboard"
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(line)
	}
	return b.String()
}

func discordGroup(g *Group) string {
	if g.Title == "" {
		return ""
	}
	title := "**" + discordEscape(Clean(g.Title)) + "**"
	if link := safeLink(g.URL); link != "" {
		title = "**[" + discordEscape(Clean(g.Title)) + "](" + link + ")**"
	}
	if g.Note != "" {
		title += " · " + discordEscape(Clean(g.Note))
	}
	return title
}

var discordDots = map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

// discordItem writes an item on one line, with its details in small print
// below.
func discordItem(it *Item) string {
	title := discordEscape(Clean(it.Title))
	if link := safeLink(it.URL); link != "" {
		title = "[" + title + "](" + link + ")"
	}
	if it.Severity == "" {
		// An update: one line is enough.
		line := "• **" + title + "**"
		if d := it.detail(); d != "" {
			line += " " + discordEscape(Clean(d))
		}
		return line
	}
	dot, ok := discordDots[it.Severity]
	if !ok {
		dot = "⚪"
	}
	line := dot + " **" + title + "** · " + severityLabel(it.Severity)
	if it.CVSS > 0 {
		line += fmt.Sprintf(" · CVSS %.1f", it.CVSS)
	}
	if it.KnownExploited {
		line += " · **Known exploited**"
	}
	if d := it.detail(); d != "" {
		line += "\n-# " + discordEscape(Clean(d))
	}
	if it.Note != "" {
		line += "\n-# " + discordEscape(Clean(it.Note))
	}
	return line
}

// safeLink returns u if it can be put in a Markdown link as it is, or "".
func safeLink(u string) string {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" ||
		strings.ContainsAny(u, " \t\n()<>[]") {
		return ""
	}
	return u
}

func discordColour(tone string) int {
	n, _ := strconv.ParseInt(strings.TrimPrefix(toneColour(tone), "#"), 16, 32)
	return int(n)
}

func runes(s string) int { return utf8.RuneCountInString(s) }

// cut shortens s to n characters, with an ellipsis.
func cut(s string, n int) string {
	if runes(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// The colours of each tone, as embeds show them on their left edge.
var toneColours = map[string]string{
	ToneDanger: "#dc2626", ToneWarning: "#d97706", ToneInfo: "#2563eb", ToneOK: "#16a34a",
}

func toneColour(t string) string {
	if c, ok := toneColours[t]; ok {
		return c
	}
	return "#3f3f46"
}
