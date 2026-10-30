// Command bestbefore-agent is the Best Before agent, run on each monitored
// server. See package agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/theo-mazars/best-before/internal/agent"
	"github.com/theo-mazars/best-before/internal/agent/docker"
	"github.com/theo-mazars/best-before/internal/version"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "bestbefore-agent: Best Before agent. Collects a read-only inventory of this server and pushes it to the dashboard.")
		fmt.Fprintln(os.Stderr, "\nUsage: bestbefore-agent [flags]")
		flag.PrintDefaults()
	}
	showVersion := flag.Bool("version", false, "print the version and exit")
	dryRun := flag.Bool("dry-run", false, "print the report as JSON to stdout instead of sending it")
	dockerHost := flag.String("docker-host", os.Getenv("DOCKER_HOST"), "Docker API address: unix:///path/to/docker.sock or tcp://host:port (e.g. a socket proxy).\nDefaults to $DOCKER_HOST, then "+docker.DefaultHost+" if Docker is installed")
	flag.Parse()

	if *showVersion {
		fmt.Println("bestbefore-agent", version.Version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := agent.Run(ctx, agent.Options{
		DryRun:     *dryRun,
		DockerHost: *dockerHost,
		Out:        os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "bestbefore-agent:", err)
		os.Exit(1)
	}
}
