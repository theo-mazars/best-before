package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/theo-mazars/best-before/internal/protocol"
)

func TestSequenceSurvivesRestarts(t *testing.T) {
	st := state{dir: t.TempDir()}
	for want := uint64(1); want <= 3; want++ {
		got, err := (state{dir: st.dir}).nextSequence()
		if err != nil || got != want {
			t.Fatalf("got %d, %v; want %d", got, err, want)
		}
	}
	key, _ := protocol.GenerateAgentKey()
	if err := st.saveKey(key); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.nextSequence(); got != 1 {
		t.Errorf("a new key must start a new sequence, got %d", got)
	}

	os.WriteFile(st.seqPath(), []byte("garbage"), 0o600)
	if _, err := st.nextSequence(); err == nil {
		t.Error("damaged sequence file accepted")
	}
}

func TestAgentKeyMustBePrivate(t *testing.T) {
	st := state{dir: t.TempDir()}
	key, _ := protocol.GenerateAgentKey()
	st.saveKey(key)
	os.Chmod(st.keyPath(), 0o644)
	if _, err := st.loadKey(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("readable key accepted: %v", err)
	}
}

func TestAgentConfig(t *testing.T) {
	for _, key := range configKeys {
		if !regexp.MustCompile(`(?m)^#` + key + ` =`).MatchString(ExampleConfig) {
			t.Errorf("setting %q is missing from agent.conf", key)
		}
	}
	path := filepath.Join(t.TempDir(), "agent.conf")
	os.WriteFile(path, []byte(ExampleConfig), 0o644)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("unenrolled config: %v", err)
	}

	d, _ := protocol.GenerateDashboardKey()
	for name, docker := range map[string]string{"bad docker": "maybe", "http docker": "http://x"} {
		os.WriteFile(path, []byte("dashboard_url = https://d.test\ndashboard_key = "+d.Public().String()+"\ndocker = "+docker+"\n"), 0o644)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSetDocker(t *testing.T) {
	d, _ := protocol.GenerateDashboardKey()
	path := filepath.Join(t.TempDir(), "agent.conf")
	cfg := &Config{DashboardURL: "https://d.test", DashboardKey: d.Public(), DashboardTLSKey: make([]byte, 32), Docker: DockerAuto}
	if err := cfg.write(path); err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"tcp://127.0.0.1:2375", DockerOff, DockerAuto} {
		if err := SetDocker(path, setting); err != nil {
			t.Fatal(err)
		}
		got, err := LoadConfig(path)
		if err != nil || got.Docker != setting || !got.DashboardKey.Equal(d.Public()) || got.DashboardTLSKey == nil {
			t.Errorf("after setting %s: %+v, %v", setting, got, err)
		}
	}
	if err := SetDocker(path, "socket"); err == nil {
		t.Error("invalid setting accepted")
	}
}
