# Best Before

> Know what's gone off on your servers.

**Best Before** is a read-only, self-hosted security monitor for small Ubuntu + Docker fleets. It answers two questions in one dashboard:

1. Which host packages (APT) need updating, and which of those are security fixes?
2. Which running Docker images contain packages with known vulnerabilities (CVEs): in their operating system, or in the runtimes they install outside the package manager (Node, Python, Java…)?

You get a weekly digest, and an immediate alert when something urgent appears.

> [!WARNING]
> Best Before is at an early stage. Agents report their host and images, and the dashboard finds their known vulnerabilities. Alerts and digests are still to come.

## How it works

```
  Server A ── agent ──┐
  Server B ── agent ──┼──(HTTPS, push only, signed reports)──▶ Dashboard ──▶ Email / ntfy / webhook
  Server C ── agent ──┘                                          │
                                                             SQLite + web UI (VPN only)
```

- **`bestbefore-agent`** runs on each server from a systemd timer, collects an inventory, sends one report and exits. It never listens on the network and never changes anything on the server.
- **`bestbefore`** is the dashboard, a container with an embedded web UI and a single SQLite file. It checks reports against the [Grype](https://github.com/anchore/grype) vulnerability database, which it downloads and keeps current, and counts only vulnerabilities that have a fix.

Best Before watches the system, not your applications: the programs inside an image and their dependencies (npm, pip, Go modules…) are their developers' responsibility, and tools such as Dependabot already cover them in their repositories.

**Run the dashboard on a VPN or private network only. Never expose it to the internet.** It holds a complete map of every vulnerable package on every server.

### Security model

- **Agents push; the dashboard never connects to a server.** Agents open no port. The dashboard's only outbound connection is to download vulnerability data, with certificates always checked.
- **Enrolment is a one-time code** created in the dashboard and pasted on the server. It carries the dashboard's identity, so the agent checks who it talks to before sending anything, then pins it.
- **Reports are encrypted to the dashboard and signed by the agent**, with replay protection, independently of TLS: a reverse proxy only ever sees ciphertext. The dashboard treats every report as untrusted input.
- **The dashboard can only answer "accepted" or "rejected".** It cannot send instructions, configuration or updates to agents.
- **Docker is read through a socket proxy** allowing only the agent's read requests, never through the socket itself.
- **Logins need a password and an authenticator app.**

## Guides

- [Running the dashboard](docs/dashboard.md): starting it, the first admin, users, the vulnerability database, backups.
- [Running the agent](docs/agent.md): installing, enrolling, Docker access, the systemd service.

## Development

Building and testing need only Go (see `go.mod` for the version), on Linux or macOS.

```sh
make build   # binaries in ./bin
make check   # formatting, vet and tests: run this before pushing
make image   # the dashboard's container image
```

CI on GitHub Actions runs only when triggered by hand, so `make check` is the main safeguard.

### Trying the agent

The agent collects from APT, so it needs Ubuntu or Debian to run for real. `scripts/dry-run.sh` builds it for Linux and runs `--dry-run` wherever you have APT:

```sh
make dry-run                             # here on Ubuntu/Debian, otherwise in a container
scripts/dry-run.sh --container           # in an Ubuntu container (Docker or Podman)
scripts/dry-run.sh --ssh user@server     # on a server: copied over, run, then deleted
```

Container mode mounts your container engine's socket, which is root-equivalent: use it on a development machine only.

### Pinned images

Container images used in this repository are pinned by tag and digest (`ubuntu:24.04@sha256:…`), so a build never silently changes underneath us. Tags are rebuilt regularly, so the pins need refreshing:

```sh
make check-pins    # lists pins whose tag has a newer build (needs only curl)
make update-pins   # rewrites them
```

Run `make check-pins` when you start working on a change, and commit any update on its own.

### Repository layout

| Path | Contents |
|---|---|
| `cmd/` | Entry points of `bestbefore-agent` and `bestbefore` |
| `internal/agent/` | Agent: enrolment, sending reports; `host/` and `docker/` collect, `pkgdb/` reads package databases (dpkg, apk, RPM) |
| `internal/dashboard/` | Dashboard: report ingestion, web UI, users; `store/` holds the SQLite schema, `vulns/` matches inventories with Grype |
| `internal/protocol/` | How agents and the dashboard trust each other: keys, enrolment codes, signed messages |
| `internal/report/` | Report schema shared by both |
| `internal/config/` | The `key = value` configuration format |
| `packaging/` | Dashboard image, agent systemd units, Docker socket proxy |
| `docs/` | Guides for operators |
| `scripts/` | Development tools |

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

To be decided before the first public release.
