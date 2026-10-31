package config

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	v, err := Parse(strings.NewReader(`
# comment
listen = 127.0.0.1:8443   # inline comment
public_url=https://dashboard.vpn/path#not-a-comment
empty =
`), "listen", "public_url", "empty", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if v["listen"] != "127.0.0.1:8443" || v["public_url"] != "https://dashboard.vpn/path#not-a-comment" {
		t.Errorf("values: %v", v)
	}
	if v.Get("empty", "default") != "default" || v.Get("unused", "default") != "default" {
		t.Error("defaults not applied")
	}
}

func TestParseErrors(t *testing.T) {
	for name, input := range map[string]string{
		"unknown key":  "lsiten = :8443\n",
		"repeated key": "listen = a\nlisten = b\n",
		"no equals":    "listen\n",
		"no key":       "= value\n",
	} {
		if _, err := Parse(strings.NewReader(input), "listen"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
