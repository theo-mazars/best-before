package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/protocol"
)

// retryDelays are the waits before each retry. A retry resends the same
// bytes, which the dashboard recognises if the first attempt was stored; all
// of them fit well within protocol.MaxAge.
var retryDelays = []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute}

type dashboardClient struct {
	baseURL     string
	key         *protocol.DashboardPublicKey
	http        *http.Client
	retryDelays []time.Duration
}

func newClient(baseURL string, key *protocol.DashboardPublicKey, tlsConfig *tls.Config) *dashboardClient {
	return &dashboardClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		key:     key,
		http: &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				Proxy:               nil,
				TLSClientConfig:     tlsConfig,
				TLSHandshakeTimeout: 15 * time.Second,
			},
			// A redirect could point anywhere; the dashboard never sends one.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		retryDelays: retryDelays,
	}
}

// tlsPolicy returns the TLS configuration for an enrolled agent: the pinned
// key of the dashboard's built-in certificate, or else certificate
// authorities (the system's, plus caFile).
func tlsPolicy(pinned []byte, caFile string) (*tls.Config, error) {
	if pinned != nil {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Chain and name checks are replaced by the pin, checked below.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || !bytes.Equal(protocol.TLSKeyHash(cs.PeerCertificates[0]), pinned) {
					return errors.New("the dashboard's TLS key is not the one pinned at enrolment")
				}
				return nil
			},
		}, nil
	}
	roots, err := rootPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

func rootPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no certificate", caFile)
		}
	}
	return pool, nil
}

// send posts a message and returns the dashboard's verified reply. It retries
// when the dashboard cannot be reached or does not give a valid reply, but
// not when it rejects the message.
func (d *dashboardClient) send(ctx context.Context, path string, msg []byte) (*protocol.Reply, error) {
	var lastErr error
	for attempt := 0; attempt <= len(d.retryDelays); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d.retryDelays[attempt-1]):
			}
		}
		reply, err := d.post(ctx, path, msg)
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("could not reach the dashboard after %d attempts: %w", len(d.retryDelays)+1, lastErr)
}

func (d *dashboardClient) post(ctx context.Context, path string, msg []byte) (*protocol.Reply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxReplySize+1))
	if err != nil {
		return nil, err
	}
	reply, err := protocol.VerifyReply(d.key, msg, body)
	if err != nil {
		return nil, fmt.Errorf("HTTP %d, no valid reply: %w", resp.StatusCode, err)
	}
	return reply, nil
}
