// Command bestbefore-agent is the Best Before agent, run on each monitored
// server. See package agent.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/theo-mazars/best-before/internal/agent"
	"github.com/theo-mazars/best-before/internal/version"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "bestbefore-agent: Best Before agent. Collects a read-only inventory of this server and pushes it to the dashboard.")
		fmt.Fprintln(os.Stderr, "\nUsage: bestbefore-agent [flags]")
		flag.PrintDefaults()
	}
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("bestbefore-agent", version.Version)
		return
	}

	if err := agent.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "bestbefore-agent:", err)
		os.Exit(1)
	}
}
