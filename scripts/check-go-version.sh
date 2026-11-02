#!/bin/sh
# Checks that the dashboard image is built with the Go version go.mod asks
# for, as the release packages are, so that both builds give the same binary.
set -eu

cd "$(dirname "$0")/.."

want=$(sed -n 's/^toolchain go//p' go.mod)
got=$(sed -n 's/^FROM golang:\([0-9.]*\)-.*/\1/p' packaging/docker/Dockerfile)

if [ -z "$want" ] || [ "$want" != "$got" ]; then
	echo "go.mod uses Go ${want:-?} but packaging/docker/Dockerfile uses Go ${got:-?}" >&2
	exit 1
fi
