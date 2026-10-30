# Best Before

> Know what's gone off on your servers.

**Best Before** is a read-only, self-hosted security monitor for small Ubuntu + Docker fleets. It answers three questions in one dashboard:

1. Which host packages (APT) need updating, and which of those are security fixes?
2. Which running Docker images contain known vulnerabilities (CVEs)?
3. Which running images are out of date: a newer tag exists, or the image ships an end-of-life runtime?

You get a weekly digest, and an immediate alert when something urgent appears.

> [!WARNING]
> Best Before is at a very early stage and is not usable yet.

## How it works

```
  Server A ── agent ──┐
  Server B ── agent ──┼──(HTTPS, push only, signed reports)──▶ Dashboard ──▶ Email / ntfy / webhook
  Server C ── agent ──┘                                          │
                                                             SQLite + web UI (VPN only)
```

- **`bestbefore-agent`** runs on each server from a systemd timer, collects an inventory, sends one signed report and exits. It never listens on a socket and never changes anything on the server.
- **`bestbefore`** is the dashboard: a single binary with an embedded web UI and a single SQLite file. It matches inventories against vulnerability data and sends notifications.

**Run the dashboard on a VPN or private network only. Never expose it to the internet.** It holds a complete map of every vulnerable package on every server.

## The agent

### See exactly what leaves your server

```sh
bestbefore-agent --dry-run
```

prints the full report as JSON and sends nothing. It contains:

- **Host:** OS, kernel, hostname, uptime, whether a reboot is required, every installed package (with its source package), and the packages that can be upgraded, with security updates flagged.
- **Docker:** running containers (name, image as written, image ID, Compose project and service) and, for each image, its registry digests.

Anything the agent could not collect is listed in the report (`host.errors`, `docker.available` / `docker.error`), so a gap is never mistaken for a clean server.

Servers without Docker are perfectly normal: the report simply has no `docker` section, and nothing about Docker appears anywhere. If Docker *is* installed but the agent cannot read it (daemon stopped, missing permission), that is reported as a problem, because containers may be running unseen.

The agent does not run `apt-get update`. It reads the package lists your system already keeps current (Ubuntu's `apt-daily` timer does this by default) and records how recent they are in `host.apt.lists_published_at`.

### Docker access

> [!IMPORTANT]
> **Access to the Docker socket is equivalent to root on the host**, whatever the agent does with it.

The agent only ever sends `GET` requests to the Docker API, and tests fail the build if that changes. It never pulls images or touches containers. That limits what *our code* does, not what a process holding the socket *could* do, so we recommend putting the agent behind a socket proxy that only allows the read endpoints it needs, and pointing it there:

```sh
bestbefore-agent --docker-host tcp://127.0.0.1:2375 --dry-run
```

`--docker-host` defaults to `$DOCKER_HOST`, then to `unix:///var/run/docker.sock` if Docker is installed.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/bestbefore-agent/` | Entry point of the agent binary |
| `cmd/bestbefore/` | Entry point of the dashboard binary |
| `internal/agent/` | Agent logic: collection, signing, push |
| `internal/agent/host/` | Host and APT collection |
| `internal/agent/docker/` | Read-only Docker API client |
| `internal/report/` | Report schema shared by agent and dashboard |
| `internal/dashboard/` | Dashboard logic: ingestion, matching, web UI, alerts |
| `internal/version/` | Build metadata shared by both |

## Building

Requires Go (see `go.mod` for the version).

```sh
make build   # binaries in ./bin
make check   # formatting, vet and tests: run this before pushing
```

CI on GitHub Actions runs only when triggered by hand, so `make check` is the main safeguard.

### Pinned images

Container images used in this repository are pinned by tag and digest (`ubuntu:24.04@sha256:…`), so a build never silently changes underneath us. Tags such as `ubuntu:24.04` are rebuilt regularly, so the pins need refreshing:

```sh
make check-pins    # lists pins whose tag has a newer build (needs only curl)
make update-pins   # rewrites them
```

Run `make check-pins` when you start working on a change, and commit any update on its own.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

To be decided before the first public release.
