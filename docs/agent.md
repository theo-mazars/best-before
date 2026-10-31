# Running the agent

The agent runs on each Ubuntu server, once a day, from a systemd timer. It
collects a read-only inventory, sends one signed and encrypted report to the
dashboard, and exits. It never listens on the network and never changes
anything on the server.

## Installing

A `.deb` package will come with the first release. Until then, build the agent
from a checkout for the server's architecture (`amd64` or `arm64`):

```sh
make build-linux LINUX_ARCH=amd64
```

then, on the server:

```sh
sudo install -m 0755 bin/linux-amd64/bestbefore-agent /usr/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin bestbefore-agent
sudo install -m 0644 packaging/systemd/bestbefore-agent.service \
  packaging/systemd/bestbefore-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

## Enrolling

In the dashboard, **Agents › Add a server** creates a one-time code, valid for
an hour. On the server:

```sh
sudo bestbefore-agent enrol bb1_…
sudo systemctl enable --now bestbefore-agent.timer
sudo systemctl start bestbefore-agent.service    # first report now, not tomorrow
```

The code tells the agent where the dashboard is and how to recognise it: the
agent checks the dashboard's identity before sending anything, and pins it.
The server then appears on the Agents page.

For unattended installs (Ansible, cloud-init), pass the Docker choice
explicitly, as there is no one to ask:

```sh
bestbefore-agent enrol bb1_… --docker tcp://127.0.0.1:2375    # or --docker off
```

If the dashboard is behind a reverse proxy using a private certificate
authority, add `--ca-file /path/to/ca.pem`.

## What it sends

```sh
bestbefore-agent --dry-run
```

prints the full report as JSON and sends nothing:

- **Host:** OS, kernel, hostname, uptime, whether a reboot is required, every
  installed package with its source package, and the packages that can be
  upgraded, with security updates flagged.
- **Docker:** running containers (name, image as written, image ID, Compose
  project and service) and, for each image, its registry digests.

Anything the agent could not collect is listed in the report, so a gap is
never mistaken for a clean server. Servers without Docker simply have no Docker
section.

The agent does not run `apt-get update`: it reads the package lists Ubuntu's
`apt-daily` timer keeps current, and reports how recent they are.

## Docker

> [!IMPORTANT]
> **Access to the Docker socket is equivalent to root on the host**, whatever
> the agent does with it. The agent's service is therefore never given the
> socket: it reads Docker through a socket proxy that allows only its read
> requests.

The agent only ever sends `GET` requests to Docker, and tests fail the build if
that changes. The proxy enforces it outside the agent as well.

[`packaging/socket-proxy/compose.yaml`](../packaging/socket-proxy/compose.yaml)
runs [wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy)
with exactly the four requests the agent makes: no container logs, no file
downloads, no writes. It listens on the host's `127.0.0.1` only, so other
containers cannot reach it.

```sh
cd packaging/socket-proxy
DOCKER_GID=$(getent group docker | cut -d: -f3) docker compose up -d
sudo bestbefore-agent configure docker tcp://127.0.0.1:2375
```

To change your mind later, in either direction:

```sh
sudo bestbefore-agent configure docker off     # stop looking at Docker
sudo bestbefore-agent configure docker auto    # report if Docker appears
```

With `auto`, a server without Docker reports nothing about it, and a server
where Docker appears later reports that it needs a proxy.

## The service

The service runs as its own user with no privileges, a read-only view of the
system except its state directory, and filtered system calls; systemd itself
stops it from listening on the network. `systemd-analyze security
bestbefore-agent.service` rates it 1.2 on a scale where lower is safer.

```sh
systemctl list-timers bestbefore-agent.timer    # next run
journalctl -u bestbefore-agent                  # what happened
```

The timer runs daily, spread over an hour across servers, and catches up at
boot if the server was off.

## Files

| Path | Contents |
|---|---|
| `/etc/bestbefore/agent.conf` | Written by `enrol`. `bestbefore-agent config example` explains every setting. |
| `/var/lib/bestbefore-agent/agent.key` | The agent's private key. It never leaves the server. |
| `/var/lib/bestbefore-agent/sequence` | The number of the last report, against replays. |

## Re-enrolling and removing

To enrol a server again with a new key, revoke the old agent on the Agents
page, then:

```sh
sudo bestbefore-agent enrol bb1_… --force
```

To remove the agent, disable the timer and delete its files, then revoke it on
the Agents page:

```sh
sudo systemctl disable --now bestbefore-agent.timer
sudo rm -r /etc/bestbefore/agent.conf /var/lib/bestbefore-agent
```
