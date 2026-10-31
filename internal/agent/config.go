package agent

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/theo-mazars/best-before/internal/config"
	"github.com/theo-mazars/best-before/internal/protocol"
)

const (
	DefaultConfigPath = "/etc/bestbefore/agent.conf"
	DefaultStateDir   = "/var/lib/bestbefore-agent"
)

//go:embed agent.conf
var ExampleConfig string

var configKeys = []string{"dashboard_url", "dashboard_key", "dashboard_tls_key", "ca_file", "docker"}

const (
	DockerAuto = "auto"
	DockerOff  = "off"
)

type Config struct {
	DashboardURL string
	DashboardKey *protocol.DashboardPublicKey
	// DashboardTLSKey is nil when the certificate is checked against CAs.
	DashboardTLSKey []byte
	CAFile          string
	Docker          string
}

func LoadConfig(path string) (*Config, error) {
	v, err := config.Load(path, configKeys...)
	if err != nil {
		return nil, err
	}
	c := &Config{
		DashboardURL: v.Get("dashboard_url", ""),
		CAFile:       v.Get("ca_file", ""),
		Docker:       v.Get("docker", DockerAuto),
	}
	if c.DashboardURL == "" || v.Get("dashboard_key", "") == "" {
		return nil, fmt.Errorf("%s: not enrolled; run bestbefore-agent enrol with a code from the dashboard", path)
	}
	if u, err := url.Parse(c.DashboardURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%s: dashboard_url must be an https:// URL", path)
	}
	if c.DashboardKey, err = protocol.ParseDashboardPublicKey([]byte(v.Get("dashboard_key", ""))); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s := v.Get("dashboard_tls_key", ""); s != "" {
		if c.DashboardTLSKey, err = protocol.DecodeTLSKeyHash(s); err != nil {
			return nil, fmt.Errorf("%s: dashboard_tls_key: %w", path, err)
		}
	}
	if err := checkDockerSetting(c.Docker); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func checkDockerSetting(s string) error {
	switch {
	case s == DockerAuto, s == DockerOff, strings.HasPrefix(s, "unix:///"), strings.HasPrefix(s, "tcp://"):
		return nil
	}
	return errors.New("docker must be tcp://host:port, off, auto or unix:///path")
}

// write saves the configuration, replacing any previous one atomically.
func (c *Config) write(path string) error {
	tlsKey := ""
	if c.DashboardTLSKey != nil {
		tlsKey = protocol.EncodeTLSKeyHash(c.DashboardTLSKey)
	}
	content := fmt.Sprintf(`# Written by bestbefore-agent enrol. See bestbefore-agent config example
# for what each setting means.

dashboard_url = %s
dashboard_key = %s
dashboard_tls_key = %s
docker = %s
`, c.DashboardURL, c.DashboardKey, tlsKey, c.Docker)
	if c.CAFile != "" {
		content += "ca_file = " + c.CAFile + "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SetDocker changes the docker setting of an enrolled agent.
func SetDocker(path, setting string) error {
	if err := checkDockerSetting(setting); err != nil {
		return err
	}
	c, err := LoadConfig(path)
	if err != nil {
		return err
	}
	c.Docker = setting
	return c.write(path)
}
