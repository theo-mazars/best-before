// Package agent implements bestbefore-agent, which runs on each monitored
// server. It collects a read-only inventory of the host (APT packages, reboot
// status) and its running Docker containers, signs it, pushes it to the
// dashboard over HTTPS, and exits.
//
// The agent must never open a listening socket, call a non-GET Docker API
// endpoint, or treat anything in the dashboard's reply as an instruction.
package agent

import "errors"

// Run performs one collection and sends one report.
func Run() error {
	return errors.New("collection is not implemented yet")
}
