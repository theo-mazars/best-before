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
  bestbefore-agent configure docker X   change Docker access: tcp://host:port, unix:///path,
                                        off or auto
  bestbefore-agent configure dashboard URL
                                        use a new address of the same dashboard
  bestbefore-agent config example       print a commented configuration file
  bestbefore-agent --version

Options:
  --config path        configuration file (default /etc/bestbefore/agent.conf)
  --state-dir path     key and sequence number (default /var/lib/bestbefore-agent)
  --docker-host addr   override the docker setting: unix:///path or tcp://host:port

Enrolment options:
  --docker setting     tcp://host:port (socket proxy), unix:///path (socket), off or
                       auto; asked if omitted
  --ca-file path       certificate authority of a reverse proxy using a private CA
                       (also with configure dashboard)
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
	case len(args) > 1 && args[0] == "configure" && (args[1] == "docker" || args[1] == "dashboard"):
		command, args = "configure "+args[1], args[2:]
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
		if err == nil {
			fmt.Print(agent.DockerAccessNote(agent.DockerAuto, setting))
		}
	case command == "configure docker" && len(positional) == 1:
		var previous string
		if previous, err = agent.SetDocker(*configPath, positional[0]); err == nil {
			fmt.Printf("Docker access set to %s. It applies from the next report.\n", positional[0])
			fmt.Print(agent.DockerAccessNote(previous, positional[0]))
		}
	case command == "configure dashboard" && len(positional) == 1:
		if err = agent.MoveDashboard(ctx, *configPath, positional[0], *caFile, os.Stdout); err == nil {
			fmt.Printf("Reports now go to %s.\n", positional[0])
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

// askDocker asks how to read Docker, on servers that have it: through a
// socket proxy, through the socket, which is root-equivalent, or not at all.
func askDocker() (string, error) {
	if !docker.Present() {
		return agent.DockerAuto, nil
	}
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("Docker is installed: pass --docker tcp://host:port (a socket proxy), --docker " + docker.DefaultHost + " (the socket) or --docker off")
	}
	fmt.Print(`Docker is installed on this server. The agent only ever sends five read
requests to Docker, and can reach it in one of two ways:

  1) Through a socket proxy that allows only those requests (recommended;
     docs/agent.md has a ready-made one)
  2) Through the Docker socket: simpler, but whoever can open the socket is
     effectively root, so you will need to add the agent's user to its group
  3) Don't scan Docker (change it later with: bestbefore-agent configure docker)

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
			fmt.Printf("Socket [%s]: ", docker.DefaultHost)
			if !in.Scan() {
				return "", errors.New("no socket entered")
			}
			addr := strings.TrimSpace(in.Text())
			if addr == "" {
				addr = docker.DefaultHost
			}
			if !strings.HasPrefix(addr, "unix:///") {
				return "", errors.New("the socket must start with unix:///")
			}
			return addr, nil
		case "3":
			return agent.DockerOff, nil
		}
		fmt.Print("Choice (1, 2 or 3): ")
	}
	return "", errors.New("no choice made")
}
