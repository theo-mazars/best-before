package dashboard

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/theo-mazars/best-before/internal/dashboard/notify"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
)

// sealer encrypts the secrets of notification channels, such as an SMTP
// password or a Discord webhook URL, before they reach the database. The key
// comes from identity.key, so a copy of the database alone does not reveal
// them; whoever has the whole data directory does.
type sealer struct{ aead cipher.AEAD }

const sealVersion = 1

func newSealer(key *protocol.DashboardKey) *sealer {
	k := key.SecretsKey()
	aead, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		panic(err) // only for a key of the wrong size
	}
	return &sealer{aead: aead}
}

// seal encrypts a channel's secrets, bound to its ID so that they cannot be
// moved to another channel.
func (s *sealer) seal(channelID string, v notify.Values) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+chacha20poly1305.NonceSizeX, 1+chacha20poly1305.NonceSizeX+len(plain)+s.aead.Overhead())
	out[0] = sealVersion
	rand.Read(out[1:])
	return s.aead.Seal(out, out[1:], plain, sealData(channelID)), nil
}

func (s *sealer) open(channelID string, data []byte) (notify.Values, error) {
	if len(data) < 1+chacha20poly1305.NonceSizeX || data[0] != sealVersion {
		return nil, errors.New("malformed secrets")
	}
	nonce, sealed := data[1:1+chacha20poly1305.NonceSizeX], data[1+chacha20poly1305.NonceSizeX:]
	plain, err := s.aead.Open(nil, nonce, sealed, sealData(channelID))
	if err != nil {
		return nil, errors.New("its secrets cannot be decrypted: was identity.key replaced? Enter them again")
	}
	var v notify.Values
	return v, json.Unmarshal(plain, &v)
}

func sealData(channelID string) []byte { return []byte("bestbefore channel " + channelID) }

// channel is a stored channel, ready to send, or saying why it cannot.
type channel struct {
	store.Channel
	Type   *notify.Type
	values notify.Values // settings and secrets
	sender notify.Sender
	// Problem says why the channel cannot send.
	Problem string
}

func (s *sealer) channel(c store.Channel) channel {
	ch := channel{Channel: c, Type: notify.TypeByName(c.Type), values: notify.Values{}}
	if ch.Type == nil {
		ch.Problem = "unknown kind of channel " + c.Type
		return ch
	}
	if err := json.Unmarshal(c.Settings, &ch.values); err != nil {
		ch.Problem = "unreadable settings: " + err.Error()
		return ch
	}
	secrets, err := s.open(c.ID, c.Secrets)
	if err != nil {
		ch.Problem = err.Error()
		return ch
	}
	for k, v := range secrets {
		ch.values[k] = v
	}
	if ch.sender, err = ch.Type.New(ch.values); err != nil {
		ch.Problem = err.Error()
	}
	return ch
}

func (s *sealer) channels(ctx context.Context, st *store.Store) ([]channel, error) {
	stored, err := st.Channels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]channel, 0, len(stored))
	for _, c := range stored {
		out = append(out, s.channel(c))
	}
	return out, nil
}

// send delivers a message through every channel chosen by use, and reports
// whether at least one accepted it. Failures are logged; none stops the
// others.
func send(ctx context.Context, chans []channel, use func(*channel) bool, m *notify.Message, log interface {
	Warn(string, ...any)
}) (sent, tried int) {
	for i := range chans {
		c := &chans[i]
		if !use(c) {
			continue
		}
		tried++
		if c.sender == nil {
			log.Warn("notification channel unusable", "channel", c.Name, "problem", c.Problem)
			continue
		}
		if err := c.sender.Send(ctx, m); err != nil {
			log.Warn("notification failed", "channel", c.Name, "event", m.Event, "error", err)
			continue
		}
		sent++
	}
	return sent, tried
}

func jsonObject(v notify.Values) ([]byte, error) {
	if v == nil {
		v = notify.Values{}
	}
	return json.Marshal(v)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
