// Command bestbefore is the Best Before dashboard. See package dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/theo-mazars/best-before/internal/dashboard"
	"github.com/theo-mazars/best-before/internal/version"
)

const usage = `bestbefore: Best Before dashboard. Receives agent reports, matches vulnerabilities and serves the web UI.

Usage:
  bestbefore [--config path]                        run the dashboard
  bestbefore config example                         print a commented configuration file
  bestbefore --version

Users (each command also takes --config path):
  bestbefore user list
  bestbefore user add --email address --role admin|user
  bestbefore user set-role --email address --role admin|user
  bestbefore user reset-password --email address
  bestbefore user reset-totp --email address
  bestbefore user delete --email address [--yes]

Any change to a user ends their sessions. The last admin cannot be demoted
or deleted.
`

func main() {
	if len(os.Args) > 2 && os.Args[1] == "user" {
		os.Exit(user(os.Args[2], os.Args[3:]))
	}
	if len(os.Args) == 3 && os.Args[1] == "config" && os.Args[2] == "example" {
		fmt.Print(dashboard.ExampleConfig)
		return
	}

	fs := flag.NewFlagSet("bestbefore", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	showVersion := fs.Bool("version", false, "print the version and exit")
	configPath := fs.String("config", dashboard.DefaultConfigPath, "configuration file")
	fs.Parse(os.Args[1:])
	if fs.NArg() > 0 {
		fs.Usage()
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println("bestbefore", version.Version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := dashboard.LoadConfig(*configPath)
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = dashboard.Run(ctx, cfg, log)
		stop()
	}
	if err != nil {
		log.Error("bestbefore stopped", "error", err)
		os.Exit(1)
	}
}

func user(command string, args []string) int {
	fs := flag.NewFlagSet("bestbefore user "+command, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configPath := fs.String("config", dashboard.DefaultConfigPath, "configuration file")
	email := fs.String("email", "", "email address")
	role := fs.String("role", "", "admin or user")
	yes := fs.Bool("yes", false, "delete without asking for confirmation")
	fs.Parse(args)

	needs := map[string][]string{
		"list":           nil,
		"add":            {"email", "role"},
		"set-role":       {"email", "role"},
		"reset-password": {"email"},
		"reset-totp":     {"email"},
		"delete":         {"email"},
	}
	required, known := needs[command]
	given := map[string]bool{"email": *email != "", "role": *role != ""}
	ok := known && fs.NArg() == 0
	for _, f := range required {
		ok = ok && given[f]
	}
	if !ok {
		fs.Usage()
		return 2
	}

	cfg, err := dashboard.LoadConfig(*configPath)
	if err == nil {
		cli := &dashboard.UserCLI{Config: cfg, In: os.Stdin, Out: os.Stdout}
		ctx := context.Background()
		switch command {
		case "list":
			err = cli.List(ctx)
		case "add":
			err = cli.Add(ctx, *email, *role)
		case "set-role":
			err = cli.SetRole(ctx, *email, *role)
		case "reset-password":
			err = cli.ResetPassword(ctx, *email)
		case "reset-totp":
			err = cli.ResetTOTP(ctx, *email)
		case "delete":
			err = cli.Delete(ctx, *email, *yes)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bestbefore:", err)
		return 1
	}
	return 0
}
