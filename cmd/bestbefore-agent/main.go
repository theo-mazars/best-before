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
  bestbefore-agent configure docker X   change Docker access: tcp://host:port, off or auto
  bestbefore-agent config example       print a commented configuration file
  bestbefore-agent --version

Options:
  --config path        configuration file (default /etc/bestbefore/agent.conf)
  --state-dir path     key and sequence number (default /var/lib/bestbefore-agent)
  --docker-host addr   override the docker setting: unix:///path or tcp://host:port

Enrolment options:
  --docker setting     tcp://host:port (socket proxy), off or auto; asked if omitted
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
	switch {
	case len(args) > 0 && args[0] == "enrol":
		command, args = "enrol", args[1:]
	case len(args) > 1 && args[0] == "configure" && args[1] == "docker":
		command, args = "configure docker", args[2:]
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
	case command == "configure docker" && len(positional) == 1:
		if err = agent.SetDocker(*configPath, positional[0]); err == nil {
			fmt.Printf("Docker access set to %s. It applies from the next report.\n", positional[0])
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

// askDocker asks how to read Docker, on servers that have it. The agent's
// service is never given the Docker socket, so the choice is a socket proxy
// or nothing.
func askDocker() (string, error) {
	if !docker.Present() {
		return agent.DockerAuto, nil
	}
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("Docker is installed: pass --docker tcp://host:port (a socket proxy) or --docker off")
	}
	fmt.Print(`Docker is installed on this server. The agent reads it through a socket proxy
that only allows read endpoints: access to the Docker socket itself is
equivalent to root, so the agent is never given it. See the README for a
ready-made proxy configuration.

  1) Use a socket proxy
  2) Don't scan Docker (change it later with: bestbefore-agent configure docker)

Choice: `)
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		switch strings.TrimSpace(in.Text()) {
		case "1":
			fmt.Print("Proxy address [tcp://127.0.0.1:2375]: ")
			if !in.Scan() {
				return "", errors.New("no address entered")
			}
			addr := strings.TrimSpace(in.Text())
			if addr == "" {
				addr = "tcp://127.0.0.1:2375"
			}
			if !strings.HasPrefix(addr, "tcp://") {
				return "", errors.New("the proxy address must start with tcp://")
			}
			return addr, nil
		case "2":
			return agent.DockerOff, nil
		}
		fmt.Print("Choice (1 or 2): ")
	}
	return "", errors.New("no choice made")
}
