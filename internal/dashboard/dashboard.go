// Package dashboard implements bestbefore, the central service. It receives
// signed reports from agents, stores them in SQLite, matches inventories
// against vulnerability data (Grype, CISA KEV, endoflife.date, Ubuntu
// security data), serves the web UI and sends alerts and digests.
//
// Every agent report is untrusted input.
package dashboard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/theo-mazars/best-before/internal/config"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
	"github.com/theo-mazars/best-before/internal/protocol"
)

const DefaultConfigPath = "/etc/bestbefore/dashboard.conf"

const (
	TLSBuiltin = "builtin" // self-signed, generated in the data directory
	TLSFiles   = "files"
	TLSOff     = "off" // loopback only, behind a reverse proxy
)

type Config struct {
	Listen     string
	PublicURL  string
	DataDir    string
	TLS        string
	TLSCert    string
	TLSKey     string
	StaleAfter time.Duration
}

func LoadConfig(path string) (Config, error) {
	v, err := config.Load(path,
		"listen", "public_url", "data_dir", "tls", "tls_cert", "tls_key", "stale_after")
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Listen:    v.Get("listen", "127.0.0.1:8443"),
		PublicURL: v.Get("public_url", ""),
		DataDir:   v.Get("data_dir", "/var/lib/bestbefore"),
		TLS:       v.Get("tls", TLSBuiltin),
		TLSCert:   v.Get("tls_cert", ""),
		TLSKey:    v.Get("tls_key", ""),
	}
	if c.StaleAfter, err = time.ParseDuration(v.Get("stale_after", "48h")); err != nil || c.StaleAfter <= 0 {
		return Config{}, fmt.Errorf("%s: stale_after must be a duration such as 48h", path)
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) validate() error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.PublicURL != "" {
		if u, err := url.Parse(c.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("public_url must be an https:// URL")
		}
	}
	switch c.TLS {
	case TLSBuiltin:
	case TLSFiles:
		if c.TLSCert == "" || c.TLSKey == "" {
			return errors.New("tls = files needs tls_cert and tls_key")
		}
	case TLSOff:
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("tls = off is only allowed on a loopback address, behind a reverse proxy on the same machine")
		}
	default:
		return fmt.Errorf("tls must be %s, %s or %s", TLSBuiltin, TLSFiles, TLSOff)
	}
	return nil
}

func Run(ctx context.Context, c Config, log *slog.Logger) error {
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return err
	}
	key, err := loadOrCreateIdentity(filepath.Join(c.DataDir, "identity.key"))
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, filepath.Join(c.DataDir, "bestbefore.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	tlsConfig, builtinCert, err := c.tlsConfig()
	if err != nil {
		return err
	}
	identity, err := protocol.NewIdentity(key, builtinCert)
	if err != nil {
		return err
	}

	in := &ingest{
		store:    st,
		key:      key,
		identity: identity,
		log:      log,
		now:      time.Now,
		perIP:    newRateLimiter(30, 2*time.Second, time.Now),
		perAgent: newRateLimiter(10, time.Minute, time.Now),
	}
	ui, err := newWeb(st, key, c, log, time.Now)
	if err != nil {
		return err
	}
	go ui.cleanSessions(ctx)

	mux := http.NewServeMux()
	in.routes(mux)
	ui.routes(mux)

	srv := &http.Server{
		Addr:              c.Listen,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("dashboard listening", "address", c.Listen, "tls", c.TLS,
			"fingerprint", fmt.Sprintf("%x", key.Public().Fingerprint()))
		if tlsConfig != nil {
			errc <- srv.ListenAndServeTLS("", "")
		} else {
			errc <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// tlsConfig also returns the builtin certificate, which the identity
// document vouches for.
func (c Config) tlsConfig() (*tls.Config, *x509.Certificate, error) {
	var cert tls.Certificate
	var err error
	switch c.TLS {
	case TLSOff:
		return nil, nil, nil
	case TLSFiles:
		cert, err = tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	case TLSBuiltin:
		cert, err = builtinCertificate(c.DataDir, c.PublicURL)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("TLS certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if c.TLS == TLSBuiltin {
		return cfg, cert.Leaf, nil
	}
	return cfg, nil, nil
}

func loadOrCreateIdentity(path string) (*protocol.DashboardKey, error) {
	data, err := readPrivateFile(path)
	if err == nil {
		return protocol.ParseDashboardKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := protocol.GenerateDashboardKey()
	if err != nil {
		return nil, err
	}
	data, err = key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := writePrivateFile(path, data); err != nil {
		return nil, err
	}
	return key, nil
}

// readPrivateFile refuses, like SSH, a file other users can read.
func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %v); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return os.ReadFile(path)
}

func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
