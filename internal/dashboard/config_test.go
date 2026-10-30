package dashboard

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The example must document every setting, and load to the defaults.
func TestExampleConfig(t *testing.T) {
	for _, key := range configKeys {
		if !regexp.MustCompile(`(?m)^#` + key + ` = `).MatchString(ExampleConfig) {
			t.Errorf("setting %q is missing from dashboard.conf", key)
		}
	}

	path := filepath.Join(t.TempDir(), "dashboard.conf")
	os.WriteFile(path, []byte(ExampleConfig), 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Listen: "127.0.0.1:8443", DataDir: "/var/lib/bestbefore", TLS: TLSBuiltin, StaleAfter: 48 * time.Hour}
	if c != want {
		t.Errorf("example loads as %+v, want the defaults %+v", c, want)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, content := range map[string]string{
		"tls off on a public address": "listen = 0.0.0.0:8443\ntls = off\n",
		"files without paths":         "tls = files\n",
		"public url without scheme":   "public_url = dashboard.vpn\n",
		"bad duration":                "stale_after = two days\n",
		"typo":                        "lisen = 127.0.0.1:8443\n",
	} {
		path := filepath.Join(t.TempDir(), "dashboard.conf")
		os.WriteFile(path, []byte(content), 0o600)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSetupURL(t *testing.T) {
	for want, c := range map[string]Config{
		"https://dashboard.vpn:8443/setup": {PublicURL: "https://dashboard.vpn:8443/", Listen: "0.0.0.0:8443"},
		"https://<this host>:8443/setup":   {Listen: "0.0.0.0:8443"},
		"https://127.0.0.1:8443/setup":     {Listen: "127.0.0.1:8443"},
		"http://127.0.0.1:8080/setup":      {Listen: "127.0.0.1:8080", TLS: TLSOff},
		"https://[::1]:8443/setup":         {Listen: "[::1]:8443"},
	} {
		if got := setupURL(c); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}
