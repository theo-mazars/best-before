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

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "bestbefore: Best Before dashboard. Receives agent reports, matches vulnerabilities and serves the web UI.")
		fmt.Fprintln(os.Stderr, "\nUsage: bestbefore [flags]")
		flag.PrintDefaults()
	}
	showVersion := flag.Bool("version", false, "print the version and exit")
	configPath := flag.String("config", dashboard.DefaultConfigPath, "configuration file")
	flag.Parse()

	if *showVersion {
		fmt.Println("bestbefore", version.Version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, log); err != nil {
		log.Error("bestbefore stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := dashboard.LoadConfig(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return dashboard.Run(ctx, cfg, log)
}
