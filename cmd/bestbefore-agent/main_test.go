package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestOptionsAfterArguments(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	docker := fs.String("docker", "", "")
	force := fs.Bool("force", false, "")

	positional := parseInterspersed(fs, []string{"bb1_code", "--docker", "off", "--force"})
	if !reflect.DeepEqual(positional, []string{"bb1_code"}) || *docker != "off" || !*force {
		t.Errorf("positional %v, docker %q, force %v", positional, *docker, *force)
	}
}
