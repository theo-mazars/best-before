#!/bin/sh
# Checks that the dashboard image builds the web interface with the Node
# version ui/.nvmrc asks for, as local builds and CI do.
set -eu

cd "$(dirname "$0")/.."

want=$(cat ui/.nvmrc)
got=$(sed -n 's/^FROM node:\([0-9.]*\)-.*/\1/p' packaging/docker/Dockerfile)

if [ -z "$want" ] || [ "$want" != "$got" ]; then
	echo "ui/.nvmrc uses Node ${want:-?} but packaging/docker/Dockerfile uses Node ${got:-?}" >&2
	exit 1
fi
