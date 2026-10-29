// Command bestbefore is the Best Before dashboard. See package dashboard.
package main

import (
	"flag"
	"fmt"
	"os"

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
	flag.Parse()

	if *showVersion {
		fmt.Println("bestbefore", version.Version)
		return
	}

	if err := dashboard.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "bestbefore:", err)
		os.Exit(1)
	}
}
