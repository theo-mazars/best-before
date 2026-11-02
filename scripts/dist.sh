#!/bin/sh
# Builds a release into dist/release, as the release workflow does:
#
#   scripts/dist.sh v0.1.0
#
# - the agent's .deb for amd64 and arm64, with an SBOM of each binary;
# - the source archive, from which the dashboard image is built, with an
#   SBOM of the dashboard that it builds;
# - SHA256SUMS over all of them.
#
# Signing happens in the release workflow only. Builds are reproducible: the
# same commit and version give the same binaries and packages wherever they
# are built. Needs Go, git and shasum; nfpm and Syft are pinned in
# tools/go.mod.
set -eu

version=${1:-}
if ! printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'; then
	echo "usage: $0 vMAJOR.MINOR.PATCH[-PRERELEASE], e.g. v0.1.0 or v0.1.0-rc.1" >&2
	exit 2
fi

cd "$(dirname "$0")/.."
root=$(pwd)

if [ -n "$(git status --porcelain)" ]; then
	echo "warning: uncommitted changes; the packages will not match the commit" >&2
fi

build=$root/dist/build
out=$root/dist/release
rm -rf "$build" "$out"
mkdir -p "$build" "$out"

# Every date in the outputs is the commit's. nfpm reads SOURCE_DATE_EPOCH for
# its own files, and takes the others' from the files themselves.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
stamp=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M.%S)

ldflags="-s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=$version"
gobuild() {
	CGO_ENABLED=0 GOOS=linux GOARCH=$1 go build -trimpath -ldflags "$ldflags" -o "$2" "$3"
}
(
	cd tools
	syft=github.com/anchore/syft
	go build -o "$build/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm
	go build -ldflags "-X main.version=$(go list -m -f '{{.Version}}' $syft)" \
		-o "$build/syft" $syft/cmd/syft
)
sbom() {
	SYFT_CHECK_FOR_APP_UPDATE=false "$build/syft" scan "file:$1" --quiet \
		--source-name "$2" --source-version "$version" -o "spdx-json=$3"
}

# The copyright file Debian expects: the agent's licence, and the Go standard
# library's, which is compiled into it. The agent has no other dependency.
{
	cat <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Best Before
Source: https://github.com/theo-mazars/best-before

Files: *
Copyright: 2026 Theo Mazars
License: AGPL-3.0-only
Comment: /usr/bin/bestbefore-agent also contains the Go standard library,
 Copyright 2009 The Go Authors, under the BSD-3-Clause licence below.

License: AGPL-3.0-only
EOF
	sed -e 's/^$/./' -e 's/^/ /' LICENSE
	echo
	echo "License: BSD-3-Clause"
	sed -e 's/^$/./' -e 's/^/ /' "$(go env GOROOT)/LICENSE"
} >"$build/copyright"

for arch in amd64 arm64; do
	dir=$build/linux-$arch
	mkdir -p "$dir"
	gobuild "$arch" "$dir/bestbefore-agent" ./cmd/bestbefore-agent
	cp "$build/copyright" packaging/systemd/bestbefore-agent.service \
		packaging/systemd/bestbefore-agent.timer \
		packaging/deb/bestbefore-agent.sysusers "$dir/"
	TZ=UTC touch -t "$stamp" "$dir"/*

	# Named after the tag: Debian writes 0.1.0-rc.1 as 0.1.0~rc.1 inside
	# the package, but GitHub renames release files containing "~".
	deb=bestbefore-agent_${version#v}_$arch.deb
	DEB_ARCH=$arch BUILD_DIR=$dir VERSION=$version \
		"$build/nfpm" package --config packaging/deb/nfpm.yaml \
		--packager deb --target "$out/$deb" >/dev/null
	sbom "$dir/bestbefore-agent" bestbefore-agent "$out/$deb.spdx.json"
	echo "built $deb"
done

# The source of the release. The dashboard is built from it (see
# packaging/docker/Dockerfile); its SBOM lists what that build compiles in.
src=best-before-$version
git archive --format=tar.gz --prefix="$src/" -o "$out/$src.tar.gz" HEAD
gobuild amd64 "$build/bestbefore" ./cmd/bestbefore
sbom "$build/bestbefore" bestbefore "$out/$src.dashboard.spdx.json"
echo "built $src.tar.gz"

(cd "$out" && shasum -a 256 -- * >"$build/SHA256SUMS")
mv "$build/SHA256SUMS" "$out/SHA256SUMS"
echo
cat "$out/SHA256SUMS"
