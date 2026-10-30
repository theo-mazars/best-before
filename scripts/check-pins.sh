#!/bin/sh
# Checks every container image pinned as name:tag@sha256:digest in the
# repository, and reports pins whose tag now points to a newer build.
#
#   scripts/check-pins.sh            report only; exits 1 if a pin is outdated
#   scripts/check-pins.sh --update   rewrite outdated pins in place
#
# Needs only curl and git; Docker is not required. It sends HEAD requests for
# manifests and never downloads an image. Docker Hub does not count HEAD
# requests towards its pull rate limit.
set -eu

ACCEPT="application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json,\
application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json"

update=false
case ${1:-} in
--update) update=true ;;
"") ;;
*) sed -n '2,10s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."

# header prints the value of header $1 from the response headers on stdin.
header() {
	tr -d '\r' | sed -n "s/^$1: *//Ip" | head -n 1
}

# remote_digest prints the digest that tag $2 of image $1 points to now.
remote_digest() {
	name=$1 tag=$2

	# Docker Hub images may omit the registry and the "library/" namespace.
	first=${name%%/*}
	case $name in
	*/*) case $first in *.* | *:* | localhost) registry=$first repo=${name#*/} ;; *) registry=docker.io repo=$name ;; esac ;;
	*) registry=docker.io repo=library/$name ;;
	esac
	[ "$registry" = docker.io ] && registry=registry-1.docker.io

	url="https://$registry/v2/$repo/manifests/$tag"
	headers=$(curl -sSI -H "Accept: $ACCEPT" "$url") || return 1

	# Public images still need an anonymous token on most registries.
	challenge=$(printf '%s\n' "$headers" | header www-authenticate)
	if [ -n "$challenge" ]; then
		realm=$(printf '%s' "$challenge" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')
		service=$(printf '%s' "$challenge" | sed -n 's/.*service="\([^"]*\)".*/\1/p')
		token=$(curl -fsS "$realm?service=$service&scope=repository:$repo:pull" |
			sed -n 's/.*"token" *: *"\([^"]*\)".*/\1/p') || return 1
		headers=$(curl -fsSI -H "Accept: $ACCEPT" -H "Authorization: Bearer $token" "$url") || return 1
	fi

	printf '%s\n' "$headers" | header docker-content-digest
}

pins=$(git grep --untracked -hoE '[a-z0-9][a-z0-9._/-]*(:[0-9]+/[a-z0-9._/-]+)?:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' | sort -u)
[ -n "$pins" ] || { echo "No pinned images found."; exit 0; }

outdated=0 failed=0
for pin in $pins; do
	ref=${pin%@*} pinned=${pin#*@}
	name=${ref%:*} tag=${ref##*:}

	current=$(remote_digest "$name" "$tag") || current=
	if [ -z "$current" ]; then
		echo "?? $ref: could not check the registry"
		failed=$((failed + 1))
	elif [ "$current" = "$pinned" ]; then
		echo "ok $ref"
	else
		outdated=$((outdated + 1))
		echo "!! $ref has a newer build: $current"
		if $update; then
			for file in $(git grep --untracked -l "$pin"); do
				sed "s|$pin|$ref@$current|g" "$file" >"$file.tmp" && cat "$file.tmp" >"$file" && rm "$file.tmp"
				echo "   updated $file"
			done
		fi
	fi
done

[ "$failed" -eq 0 ] || exit 2
$update || [ "$outdated" -eq 0 ] || { echo "Run 'make update-pins' to update them."; exit 1; }
