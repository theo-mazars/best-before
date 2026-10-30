package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerSection(t *testing.T) {
	unreachable := "unix://" + filepath.Join(t.TempDir(), "docker.sock")

	tests := []struct {
		name          string
		present       bool
		host          string
		wantSection   bool
		wantAvailable bool
	}{
		// The common case: no Docker on the server, so nothing to say.
		{name: "not installed", present: false, wantSection: false},
		// Installed but unreadable (daemon stopped, no permission): a problem.
		{name: "installed but unreachable", present: true, wantSection: true, wantAvailable: false},
		// The owner configured a host, so failing to reach it is a problem
		// even if nothing on this server looks like Docker.
		{name: "configured but unreachable", present: false, host: unreachable, wantSection: true, wantAvailable: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func(present func() bool, host string) {
				dockerPresent, dockerDefaultHost = present, host
			}(dockerPresent, dockerDefaultHost)
			dockerPresent = func() bool { return tt.present }
			dockerDefaultHost = unreachable

			var out bytes.Buffer
			if err := Run(context.Background(), Options{DryRun: true, DockerHost: tt.host, Out: &out}); err != nil {
				t.Fatal(err)
			}
			var r map[string]json.RawMessage
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err)
			}

			raw, ok := r["docker"]
			if ok != tt.wantSection {
				t.Fatalf("docker section present: %v, want %v", ok, tt.wantSection)
			}
			if !ok {
				return
			}
			var d struct {
				Available bool
				Error     string
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			if d.Available != tt.wantAvailable || d.Error == "" {
				t.Errorf("available %v, error %q", d.Available, d.Error)
			}
			// Only the automatic setting points to a proxy: an explicit
			// host was chosen by the owner.
			if hint := strings.Contains(d.Error, "socket proxy"); hint != (tt.host == "") {
				t.Errorf("proxy hint %v in %q", hint, d.Error)
			}
		})
	}
}
