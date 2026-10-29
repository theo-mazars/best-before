// Package dashboard implements bestbefore, the central service. It receives
// signed reports from agents, stores them in SQLite, matches inventories
// against vulnerability data (Grype, CISA KEV, endoflife.date, Ubuntu
// security data), serves the web UI and sends alerts and digests.
//
// Every agent report is untrusted input.
package dashboard

import "errors"

// Run starts the dashboard and blocks until it stops.
func Run() error {
	return errors.New("the dashboard is not implemented yet")
}
