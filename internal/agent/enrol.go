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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/protocol"
	"github.com/theo-mazars/best-before/internal/version"
)

type EnrolOptions struct {
	Code       string
	Docker     string
	CAFile     string
	Force      bool
	ConfigPath string
	StateDir   string
	Out        io.Writer
}

// Enrol registers this server with the dashboard named in the code. The
// dashboard's identity is checked against the code before the code's secret
// is sent, and the new key is kept only if the dashboard accepts it.
func Enrol(ctx context.Context, o EnrolOptions) error {
	code, err := protocol.ParseEnrolmentCode(o.Code)
	if err != nil {
		return err
	}
	if err := checkDockerSetting(o.Docker); err != nil {
		return err
	}
	st := state{dir: o.StateDir}
	if st.enrolled() && !o.Force {
		return errors.New("this server is already enrolled; use --force to enrol it again, then revoke the old agent in the dashboard")
	}
	if strings.HasPrefix(code.URL, "http://") {
		fmt.Fprintln(o.Out, "Warning: the dashboard uses plain HTTP. Reports stay encrypted and signed, but which servers report, and when, is visible on the network. Use this for testing only.")
	}

	dashboard, tlsConfig, pinnedTLSKey, err := discover(ctx, code, o.CAFile)
	if err != nil {
		return err
	}

	key, err := protocol.GenerateAgentKey()
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	msg, err := protocol.Seal(key, dashboard, protocol.KindEnrol, 0, time.Now(), protocol.EnrolRequest{
		Secret:       code.Secret[:],
		Hostname:     hostname,
		AgentVersion: version.Version,
	})
	if err != nil {
		return err
	}
	client := newClient(code.URL, dashboard, tlsConfig)
	client.retryDelays = []time.Duration{5 * time.Second}
	reply, err := client.send(ctx, "/api/v1/enrol", msg)
	if err != nil {
		return err
	}
	if reply.Status != protocol.Accepted {
		return fmt.Errorf("the dashboard refused the enrolment: %s", reply.Reason)
	}

	if err := st.saveKey(key); err != nil {
		return fmt.Errorf("enrolled, but saving the key failed (revoke this agent in the dashboard and enrol again): %w", err)
	}
	cfg := &Config{DashboardURL: code.URL, DashboardKey: dashboard, DashboardTLSKey: pinnedTLSKey, CAFile: o.CAFile, Docker: o.Docker}
	if err := cfg.write(o.ConfigPath); err != nil {
		return fmt.Errorf("enrolled, but writing %s failed: %w", o.ConfigPath, err)
	}
	fmt.Fprintf(o.Out, "Enrolled %s with %s.\nConfiguration written to %s.\n", hostname, code.URL, o.ConfigPath)
	return nil
}

// discover fetches the dashboard's identity and checks it against the code.
// It returns the TLS configuration to use from now on, and the TLS key to pin
// if the dashboard vouches for its own self-signed certificate.
func discover(ctx context.Context, code *protocol.EnrolmentCode, caFile string) (*protocol.DashboardPublicKey, *tls.Config, []byte, error) {
	// The certificate is only recorded here; it is judged once the identity
	// document says which key to expect. Nothing secret is sent before then.
	var peer []*x509.Certificate
	probe := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			peer = cs.PeerCertificates
			return nil
		},
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSClientConfig: probe},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(code.URL, "/")+"/api/v1/identity", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not reach the dashboard: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxReplySize+1))
	if err != nil {
		return nil, nil, nil, err
	}
	dashboard, statedTLSKey, err := protocol.VerifyIdentity(body, code.Fingerprint)
	if err != nil {
		return nil, nil, nil, err
	}

	if strings.HasPrefix(code.URL, "http://") {
		return dashboard, nil, nil, nil
	}
	if len(peer) == 0 {
		return nil, nil, nil, errors.New("the dashboard presented no TLS certificate")
	}
	if statedTLSKey != nil && bytes.Equal(protocol.TLSKeyHash(peer[0]), statedTLSKey) {
		cfg, err := tlsPolicy(statedTLSKey, "")
		return dashboard, cfg, statedTLSKey, err
	}

	roots, err := rootPool(caFile)
	if err != nil {
		return nil, nil, nil, err
	}
	u, _ := url.Parse(code.URL)
	intermediates := x509.NewCertPool()
	for _, c := range peer[1:] {
		intermediates.AddCert(c)
	}
	if _, err := peer[0].Verify(x509.VerifyOptions{DNSName: u.Hostname(), Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, nil, nil, fmt.Errorf("the dashboard's TLS certificate is neither the one it vouches for nor valid under a trusted certificate authority (use --ca-file for a private CA): %w", err)
	}
	cfg, err := tlsPolicy(nil, caFile)
	return dashboard, cfg, nil, err
}
