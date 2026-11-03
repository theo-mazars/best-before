// Package agent implements bestbefore-agent, which runs on each monitored
// server. It collects a read-only inventory of the host (APT packages, reboot
// status) and its running Docker containers, signs it, pushes it to the
// dashboard over HTTPS, and exits.
//
// The agent must never open a listening socket, call a Docker API endpoint
// other than its five reads, or treat anything in the dashboard's reply as an instruction.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/theo-mazars/best-before/internal/agent/docker"
	"github.com/theo-mazars/best-before/internal/agent/host"
	"github.com/theo-mazars/best-before/internal/protocol"
	"github.com/theo-mazars/best-before/internal/report"
	"github.com/theo-mazars/best-before/internal/version"
)

type Options struct {
	// DryRun prints the report to Out instead of sending it, and works
	// without enrolment.
	DryRun bool
	// DockerHost overrides the docker setting of the configuration.
	DockerHost string
	ConfigPath string
	StateDir   string
	Out        io.Writer
}

// Run collects one report and sends it.
func Run(ctx context.Context, o Options) error {
	if o.DryRun {
		dockerSetting := DockerAuto
		if cfg, err := LoadConfig(o.ConfigPath); err == nil {
			dockerSetting = cfg.Docker
		}
		// No cache: a dry run shows what is read now, and leaves no trace.
		r, err := collect(ctx, override(dockerSetting, o.DockerHost), nil)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(o.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}

	cfg, err := LoadConfig(o.ConfigPath)
	if err != nil {
		return err
	}
	st := state{dir: o.StateDir}
	key, err := st.loadKey()
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("not enrolled: no agent key in " + o.StateDir)
	}
	if err != nil {
		return err
	}
	tlsConfig, err := tlsPolicy(cfg.DashboardTLSKey, cfg.CAFile)
	if err != nil {
		return err
	}

	images := st.images()
	r, err := collect(ctx, override(cfg.Docker, o.DockerHost), images)
	if err != nil {
		return err
	}
	if r.Docker != nil && r.Docker.Available {
		images.keepOnly(r.Docker.Images)
	}
	seq, err := st.nextSequence()
	if err != nil {
		return err
	}
	msg, err := protocol.Seal(key, cfg.DashboardKey, protocol.KindReport, seq, time.Now(), r)
	if err != nil {
		return err
	}
	reply, err := newClient(cfg.DashboardURL, cfg.DashboardKey, tlsConfig).send(ctx, "/api/v1/reports", msg)
	if err != nil {
		return err
	}
	if reply.Status != protocol.Accepted {
		return fmt.Errorf("the dashboard rejected the report: %s", reply.Reason)
	}
	fmt.Fprintf(o.Out, "Report %d accepted by %s.\n", seq, cfg.DashboardURL)
	return nil
}

func override(setting, host string) string {
	if host != "" {
		return host
	}
	return setting
}

func collect(ctx context.Context, dockerSetting string, cache docker.Cache) (*report.Report, error) {
	d, err := collectDocker(ctx, dockerSetting, cache)
	if err != nil {
		return nil, err
	}
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		AgentVersion:  version.Version,
		GeneratedAt:   time.Now().UTC(),
		Host:          host.Collect(ctx, host.DefaultPaths),
		Docker:        d,
	}, nil
}

// Replaced in tests, so that results do not depend on the test machine.
var (
	dockerPresent     = docker.Present
	dockerDefaultHost = docker.DefaultHost
)

// collectDocker returns nil when Docker is off, or absent with the default
// socket setting. An explicit host must be reachable, or the failure is
// reported.
func collectDocker(ctx context.Context, setting string, cache docker.Cache) (*report.Docker, error) {
	host := setting
	switch setting {
	case DockerOff:
		return nil, nil
	case DockerAuto, "":
		if !dockerPresent() {
			return nil, nil
		}
		host = dockerDefaultHost
	}
	client, err := docker.NewClient(host)
	if err != nil {
		return nil, err
	}
	d := docker.Collect(ctx, client, cache)
	switch {
	case d.Available:
	case setting != host:
		d.Error += "; Docker is installed but the agent cannot read its socket. Either set up a socket proxy and run: bestbefore-agent configure docker tcp://host:port, or give the agent the socket with: bestbefore-agent configure docker " + host + " (or: off)"
	case strings.HasPrefix(host, "unix://") && strings.Contains(d.Error, "permission denied"):
		d.Error += "; the agent's user, " + ServiceUser + ", must be in the socket's group: see bestbefore-agent configure docker " + host
	}
	return &d, nil
}
