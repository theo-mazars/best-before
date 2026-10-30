// Command bestbefore-agent is the Best Before agent, run on each monitored
// server. See package agent.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/theo-mazars/best-before/internal/agent"
	"github.com/theo-mazars/best-before/internal/agent/docker"
	"github.com/theo-mazars/best-before/internal/version"
)

const usage = `bestbefore-agent: Best Before agent. Collects a read-only inventory of this server and pushes it to the dashboard.

Usage:
  bestbefore-agent                      collect and send one report
  bestbefore-agent --dry-run            print the report instead of sending it
  bestbefore-agent enrol CODE           enrol this server with the code from the dashboard
  bestbefore-agent config example       print a commented configuration file
  bestbefore-agent --version

Options:
  --config path        configuration file (default /etc/bestbefore/agent.conf)
  --state-dir path     key and sequence number (default /var/lib/bestbefore-agent)
  --docker-host addr   override the docker setting: unix:///path or tcp://host:port

Enrolment options:
  --docker setting     socket, off, unix:///path or tcp://host:port; asked if omitted
  --ca-file path       certificate authority of a reverse proxy using a private CA
  --force              enrol again, with a new key
`

func main() {
	args := os.Args[1:]
	if len(args) == 2 && args[0] == "config" && args[1] == "example" {
		fmt.Print(agent.ExampleConfig)
		return
	}
	command := ""
	if len(args) > 0 && args[0] == "enrol" {
		command, args = "enrol", args[1:]
	}

	fs := flag.NewFlagSet("bestbefore-agent", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	showVersion := fs.Bool("version", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	configPath := fs.String("config", agent.DefaultConfigPath, "")
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "")
	dockerHost := fs.String("docker-host", os.Getenv("DOCKER_HOST"), "")
	dockerSetting := fs.String("docker", "", "")
	caFile := fs.String("ca-file", "", "")
	force := fs.Bool("force", false, "")
	positional := parseInterspersed(fs, args)

	if *showVersion {
		fmt.Println("bestbefore-agent", version.Version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch {
	case command == "enrol" && len(positional) == 1:
		setting := *dockerSetting
		if setting == "" {
			setting, err = askDocker()
		}
		if err == nil {
			err = agent.Enrol(ctx, agent.EnrolOptions{
				Code: positional[0], Docker: setting, CAFile: *caFile, Force: *force,
				ConfigPath: *configPath, StateDir: *stateDir, Out: os.Stdout,
			})
		}
	case command == "" && len(positional) == 0:
		err = agent.Run(ctx, agent.Options{
			DryRun: *dryRun, DockerHost: *dockerHost,
			ConfigPath: *configPath, StateDir: *stateDir, Out: os.Stdout,
		})
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bestbefore-agent:", err)
		os.Exit(1)
	}
}

// parseInterspersed accepts options before and after arguments, as in
// "enrol CODE --docker off", which the flag package alone does not.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// askDocker asks how to read Docker, on servers that have it.
func askDocker() (string, error) {
	if !docker.Present() {
		return agent.DockerSocket, nil
	}
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("Docker is installed: pass --docker socket, off or tcp://host:port")
	}
	fmt.Print(`Docker is installed on this server. Reading it requires access to the Docker
socket, which is equivalent to root, whatever the agent does with it.

  1) Read the Docker socket
  2) Use a socket proxy that only allows read endpoints (recommended)
  3) Don't scan Docker

Choice: `)
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		switch strings.TrimSpace(in.Text()) {
		case "1":
			return agent.DockerSocket, nil
		case "2":
			fmt.Print("Proxy address (tcp://host:port): ")
			if in.Scan() && strings.HasPrefix(strings.TrimSpace(in.Text()), "tcp://") {
				return strings.TrimSpace(in.Text()), nil
			}
			return "", errors.New("the proxy address must start with tcp://")
		case "3":
			return agent.DockerOff, nil
		}
		fmt.Print("Choice (1, 2 or 3): ")
	}
	return "", errors.New("no choice made")
}
