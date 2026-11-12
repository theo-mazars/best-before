#!/bin/sh
# Looks for known vulnerabilities in the dependencies:
#
# - Go: govulncheck (pinned in tools/go.mod) on the agent and the dashboard,
#   and on the nfpm and Syft that releases are built with;
# - npm: npm audit on the web interface's lockfile.
#
# It needs network access for the vulnerability databases, so it is not part
# of make check: run it before a release. Findings accepted in
# docs/releases.md (Accepted vulnerabilities) are listed here, are reported,
# and do not fail it; any other finding does.
set -eu

accepted_go="GO-2026-6905"
accepted_npm="GHSA-gcqx-w48m-w2h4"

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

(
	cd tools
	go build -o "$tmp/govulncheck" golang.org/x/vuln/cmd/govulncheck
	go build -o "$tmp/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm
	go build -o "$tmp/syft" github.com/anchore/syft/cmd/syft
)

# check prints IDs one per line on stdin, marking the accepted ones, and
# fails on the others.
check() {
	label=$1 accepted=$2 bad=0
	while read -r id; do
		[ -n "$id" ] || continue
		case " $accepted " in
		*" $id "*) echo "   accepted: $id" ;;
		*) echo "!! $label: $id" && bad=1 ;;
		esac
	done
	return $bad
}

# govuln runs govulncheck and checks the vulnerabilities the code calls.
# It exits 3 when it finds some; anything else but 0 is an error.
govuln() {
	label=$1
	shift
	echo "== Go: $label"
	status=0
	"$tmp/govulncheck" "$@" >"$tmp/out" 2>&1 || status=$?
	if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
		cat "$tmp/out" >&2
		failed=1
		return
	fi
	sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9-]*\).*/\1/p' "$tmp/out" | sort -u |
		check "$label" "$accepted_go" || { cat "$tmp/out"; failed=1; }
}

govuln "agent and dashboard" ./...
govuln "nfpm" -mode=binary "$tmp/nfpm"
govuln "syft" -mode=binary "$tmp/syft"

echo "== npm: web interface"
# npm audit exits 1 whenever it finds something: read its report instead.
(cd ui && npm audit --json) >"$tmp/npm.json" 2>"$tmp/npm.err" || true
if ! node -e '
	const a = JSON.parse(require("fs").readFileSync(process.argv[1]));
	if (!a.vulnerabilities) process.exit(1);
	const ids = new Set();
	for (const v of Object.values(a.vulnerabilities))
		for (const via of v.via)
			if (typeof via === "object") ids.add(via.url.replace(/.*\//, ""));
	console.log([...ids].sort().join("\n"));
' "$tmp/npm.json" >"$tmp/npm.ids"; then
	cat "$tmp/npm.err" "$tmp/npm.json" >&2
	failed=1
elif ! check "npm" "$accepted_npm" <"$tmp/npm.ids"; then
	(cd ui && npm audit) || true
	failed=1
fi

if [ "$failed" -ne 0 ]; then
	echo "New vulnerabilities: update the dependency, or record why it is accepted in docs/releases.md and in this script." >&2
	exit 1
fi
echo "No vulnerabilities besides the accepted ones."
