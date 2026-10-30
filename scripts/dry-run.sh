#!/bin/sh
# Builds bestbefore-agent for Linux and runs `--dry-run` on a system with APT.
# Works from Linux or macOS.
#
#   scripts/dry-run.sh                     here if this machine has APT, otherwise in a container
#   scripts/dry-run.sh --native            here (Ubuntu or Debian)
#   scripts/dry-run.sh --container         in an Ubuntu container, with Docker or Podman
#   scripts/dry-run.sh --ssh user@server   on a server: copies the agent over, runs it, deletes it
#
# Arguments after -- are passed to the agent, for example:
#
#   scripts/dry-run.sh --ssh me@server -- --docker-host tcp://127.0.0.1:2375
#
# Container mode prefers Docker, then Podman; set CONTAINER_ENGINE to choose.
# It mounts your container engine's socket into the container, which gives
# the agent root-equivalent access to that engine: development machines only.
set -eu

# Pinned by digest. `make check-pins` reports when the tag has a newer build.
UBUNTU_IMAGE="ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"

die() {
	echo "dry-run: $*" >&2
	exit 1
}

usage() {
	sed -n '2,16s/^# \{0,1\}//p' "$0" >&2
	exit "$1"
}

mode=auto
target=
while [ $# -gt 0 ]; do
	case $1 in
	--native | --container) mode=${1#--}; shift ;;
	--ssh)
		[ $# -ge 2 ] || usage 1
		mode=ssh target=$2
		shift 2
		;;
	--) shift; break ;;
	-h | --help) usage 0 ;;
	*) usage 1 ;;
	esac
done

cd "$(dirname "$0")/.."

# goarch maps `uname -m` output to a Go architecture.
goarch() {
	case $1 in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture: $1" ;;
	esac
}

# build compiles the agent for linux/$1 and sets $agent to its path.
build() {
	make --no-print-directory build-agent-linux LINUX_ARCH="$1" >&2
	agent="bin/linux-$1/bestbefore-agent"
}

has_apt() {
	[ "$(uname -s)" = Linux ] && command -v apt-get >/dev/null 2>&1
}

container_engine() {
	for engine in ${CONTAINER_ENGINE:-docker podman}; do
		if command -v "$engine" >/dev/null 2>&1; then
			echo "$engine"
			return 0
		fi
	done
	return 1
}

# quote prints its arguments single-quoted, for a remote shell.
quote() {
	for arg in "$@"; do
		printf "'%s' " "$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")"
	done
}

if [ "$mode" = auto ]; then
	if has_apt; then
		mode=native
	elif container_engine >/dev/null; then
		mode=container
	else
		die "this machine has no APT, and neither Docker nor Podman is installed.
Install one of them, or run the agent on an Ubuntu server: $0 --ssh user@server"
	fi
fi

case $mode in
native)
	has_apt || die "--native needs Linux with APT (Ubuntu or Debian)"
	build "$(goarch "$(uname -m)")"
	exec "$agent" --dry-run "$@"
	;;

ssh)
	build "$(goarch "$(ssh "$target" uname -m)")"
	remote_dir=$(ssh "$target" mktemp -d)
	[ -n "$remote_dir" ] || die "could not create a temporary directory on $target"
	trap 'ssh "$target" rm -rf "$remote_dir"' EXIT
	scp -q "$agent" "$target:$remote_dir/bestbefore-agent"
	# The agent runs as your SSH user. Without access to the Docker socket
	# (usually membership of the docker group), the report says so in
	# docker.error instead of listing containers.
	ssh "$target" "$remote_dir/bestbefore-agent" --dry-run "$(quote "$@")"
	;;

container)
	engine=$(container_engine) || die "--container needs Docker or Podman"
	build "$(goarch "$("$engine" run --rm "$UBUNTU_IMAGE" uname -m)")"

	case $engine in
	podman)
		socket=$(podman info --format '{{.Host.RemoteSocket.Path}}')
		socket=${socket#unix://}
		;;
	*) socket=/var/run/docker.sock ;;
	esac

	# apt-get update runs in the throwaway container only, because the image
	# ships without package lists. The agent itself never refreshes them.
	"$engine" run --rm \
		--volume "$PWD/$(dirname "$agent"):/opt/bestbefore:ro" \
		--volume "$socket:/var/run/docker.sock" \
		"$UBUNTU_IMAGE" \
		sh -c 'apt-get update -qq >/dev/null && /opt/bestbefore/bestbefore-agent --dry-run "$@"' -- "$@"
	;;
esac
