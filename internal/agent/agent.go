// Package agent implements bestbefore-agent, which runs on each monitored
// server. It collects a read-only inventory of the host (APT packages, reboot
// status) and its running Docker containers, signs it, pushes it to the
// dashboard over HTTPS, and exits.
//
// The agent must never open a listening socket, call a non-GET Docker API
// endpoint, or treat anything in the dashboard's reply as an instruction.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/theo-mazars/best-before/internal/agent/docker"
	"github.com/theo-mazars/best-before/internal/agent/host"
	"github.com/theo-mazars/best-before/internal/report"
	"github.com/theo-mazars/best-before/internal/version"
)

// Options configures one run.
type Options struct {
	// DryRun prints the report to Out instead of sending it.
	DryRun bool
	// DockerHost is "unix:///path" or "tcp://host:port". When empty, the
	// default socket is used if Docker is present, and Docker is left out of
	// the report if it is not.
	DockerHost string
	Out        io.Writer
}

// Run performs one collection and sends one report.
func Run(ctx context.Context, opts Options) error {
	if !opts.DryRun {
		return errors.New("sending reports is not implemented yet; use --dry-run")
	}

	d, err := collectDocker(ctx, opts.DockerHost)
	if err != nil {
		return err
	}

	r := report.Report{
		SchemaVersion: report.SchemaVersion,
		AgentVersion:  version.Version,
		GeneratedAt:   time.Now().UTC(),
		Host:          host.Collect(ctx, host.DefaultPaths),
		Docker:        d,
	}

	enc := json.NewEncoder(opts.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Replaced in tests, so that results do not depend on the test machine.
var (
	dockerPresent     = docker.Present
	dockerDefaultHost = docker.DefaultHost
)

// collectDocker returns nil on a server without Docker, unless the owner
// configured a Docker host: then any failure to read it must be reported.
func collectDocker(ctx context.Context, host string) (*report.Docker, error) {
	if host == "" {
		if !dockerPresent() {
			return nil, nil
		}
		host = dockerDefaultHost
	}
	client, err := docker.NewClient(host)
	if err != nil {
		return nil, err
	}
	d := docker.Collect(ctx, client)
	return &d, nil
}
