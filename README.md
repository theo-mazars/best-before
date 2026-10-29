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

## Repository layout

| Path | Contents |
|---|---|
| `cmd/bestbefore-agent/` | Entry point of the agent binary |
| `cmd/bestbefore/` | Entry point of the dashboard binary |
| `internal/agent/` | Agent logic: collection, signing, push |
| `internal/dashboard/` | Dashboard logic: ingestion, matching, web UI, alerts |
| `internal/version/` | Build metadata shared by both |

## Building

Requires Go (see `go.mod` for the version).

```sh
make build   # binaries in ./bin
make check   # formatting, vet and tests: run this before pushing
```

CI on GitHub Actions runs only when triggered by hand, so `make check` is the main safeguard.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

To be decided before the first public release.
