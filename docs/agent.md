# Running the agent

The agent runs on each Ubuntu server, once a day, from a systemd timer. It
collects a read-only inventory, sends one signed and encrypted report to the
dashboard, and exits. It never listens on the network and never changes
anything on the server.

## Installing

The agent supports Ubuntu 22.04 or later, on `amd64` or `arm64`
(`dpkg --print-architecture` tells you which). Download its `.deb` from the
[latest release](https://github.com/theo-mazars/best-before/releases), check
it as described in [Releases](releases.md#verifying-a-release), copy it to the
server, then:

```sh
sudo apt install ./bestbefore-agent_0.1.0_amd64.deb
```

The package installs the agent, its systemd service and timer, and a
`bestbefore-agent` system user, and starts the daily timer. Until the agent is
enrolled, its runs are skipped. To update, install the new version's package
the same way; enrolment and settings are kept.

To build the package yourself instead, see
[Reproducing a release](releases.md#reproducing-a-release).

## Enrolling

In the dashboard, **Agents › Add a server** creates a one-time code, valid for
an hour. On the server:

```sh
sudo bestbefore-agent enrol bb1_…
sudo systemctl start bestbefore-agent.service    # first report now, not tomorrow
```

The code tells the agent where the dashboard is and how to recognise it: the
agent checks the dashboard's identity before sending anything, and pins it.
The server then appears on the Agents page.

For unattended installs (Ansible, cloud-init), pass the Docker choice
explicitly, as there is no one to ask:

```sh
bestbefore-agent enrol bb1_… --docker tcp://127.0.0.1:2375    # a socket proxy
bestbefore-agent enrol bb1_… --docker unix:///var/run/docker.sock    # the socket
bestbefore-agent enrol bb1_… --docker off
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
  project and service) and, for each image, its registry digests, its
  operating system and the packages its package manager installed, as for the
  host: name, version, architecture, source package. The agent reads the
  records of `dpkg` (Debian, Ubuntu, distroless), `apk` (Alpine) and `rpm`
  (Red Hat, Rocky, Alma, Oracle Linux, Amazon Linux, Fedora, SUSE), in all
  three of RPM's database formats, with its own small readers.
  Also each image's environment variables named `*_VERSION`, such as
  `NODE_VERSION=22.23.4`: official images set them for software installed
  without the package manager (Node, Python, PHP, Java, Redis, PostgreSQL…).
  No other environment variable is read, as they may hold secrets. The
  programs inside an image are not analysed: they are their developers'
  responsibility.

Anything the agent could not collect is listed in the report, so a gap is
never mistaken for a clean server. Servers without Docker simply have no Docker
section.

The agent does not run `apt-get update`: it reads the package lists Ubuntu's
`apt-daily` timer keeps current, and reports how recent they are.

## Docker

The agent only ever reads from Docker. It sends exactly five requests, all
`GET`: the engine's version, the running containers, each container's details,
each image's details, and each image's export. Its HTTP client refuses
anything else, including `GET` requests that are not reads, such as attaching
to a container, and tests fail the build if that changes.

To read an image's packages, the agent exports the image through the API, as
`docker save` does, and reads the archive as it streams past. It keeps only
the package lists and os-release, never writes the image to disk, and never
pulls anything. Each image is read once and remembered by its ID in the
agent's state directory, so the first run takes longest.

The agent can reach Docker in two ways. Choose one at enrolment, or later with
`bestbefore-agent configure docker`.

> [!IMPORTANT]
> **Access to the Docker socket is equivalent to root on the host**, whatever
> the agent does with it: anything running as the agent's user could use the
> socket for more than the agent does. A socket proxy keeps that access out of
> the agent's hands, and enforces the five requests outside the agent as well.

### Through a socket proxy (recommended)

[`packaging/socket-proxy/compose.yaml`](../packaging/socket-proxy/compose.yaml)
runs [wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy)
with exactly the five requests the agent makes: no container logs, no files
from running containers, no writes. It listens on the host's `127.0.0.1` only,
so other containers cannot reach it.

```sh
cd packaging/socket-proxy
DOCKER_GID=$(getent group docker | cut -d: -f3) docker compose up -d
sudo bestbefore-agent configure docker tcp://127.0.0.1:2375
```

### Through the Docker socket

Without a proxy, the agent reads the socket directly. Its service runs as the
unprivileged `bestbefore-agent` user, which cannot open the socket until you
add it to the socket's group, `docker` on a standard install:

```sh
sudo bestbefore-agent configure docker unix:///var/run/docker.sock
sudo usermod -aG docker bestbefore-agent
```

`configure` prints the right group for your socket, and never changes groups
itself. The membership applies from the next run, without restarting anything,
and is the only privilege the agent gets: the service keeps its other
restrictions. A socket owned by the root group is not supported; use a proxy.

To take the access back, switch to a proxy or `off`, then remove the user from
the group (`configure` reminds you):

```sh
sudo gpasswd -d bestbefore-agent docker
```

If Docker is uninstalled and its group deleted, the membership disappears with
it and the agent keeps running.

### Changing your mind

In either direction:

```sh
sudo bestbefore-agent configure docker off     # stop looking at Docker
sudo bestbefore-agent configure docker auto    # report if Docker appears
```

With `auto`, a server without Docker reports nothing about it, and a server
where Docker appears later reads the default socket if the agent's user has
been given it, or reports that it needs a proxy or the socket.

## The service

The service runs as its own user with no privileges (unless you give it the
Docker socket's group, see [Docker](#docker)), a read-only view of the
system except its state directory, and filtered system calls; systemd itself
stops it from listening on the network. `systemd-analyze security
bestbefore-agent.service` rates it 1.2 on a scale where lower is safer.

```sh
systemctl list-timers bestbefore-agent.timer    # next run
journalctl -u bestbefore-agent                  # what happened
```

The timer runs daily, spread over an hour across servers, and catches up at
boot if the server was off. To pause reports without removing the agent:

```sh
sudo systemctl disable --now bestbefore-agent.timer    # enable --now to resume
```

Upgrades and reinstallation never turn the timer on or off: a timer you
disable stays disabled. Only a new installation, or one after `apt purge`,
enables it. Version 0.1.0 left it disabled until enabled by hand, and
upgrading keeps it that way: if `systemctl is-enabled bestbefore-agent.timer`
says `disabled`, enable it as above.

## Files

| Path | Contents |
|---|---|
| `/etc/bestbefore/agent.conf` | Written by `enrol`. `bestbefore-agent config example` explains every setting. |
| `/var/lib/bestbefore-agent/agent.key` | The agent's private key. It never leaves the server. |
| `/var/lib/bestbefore-agent/sequence` | The number of the last report, against replays. |

## When the dashboard moves

If the dashboard gets a new address, or moves behind a reverse proxy, change
its `public_url`, then on each server:

```sh
sudo bestbefore-agent configure dashboard https://new-address.example.vpn
```

The agent accepts the new address only if the dashboard there proves it holds
the identity pinned at enrolment, then checks and pins its TLS again, as at
enrolment: add `--ca-file` for a reverse proxy using a private certificate
authority. Until a server is updated, its reports fail, and the dashboard
shows it as stale.

## Re-enrolling and removing

To enrol a server again with a new key, revoke the old agent on the Agents
page, then:

```sh
sudo bestbefore-agent enrol bb1_… --force
```

To remove the agent, purge its package, then revoke it on the Agents page:

```sh
sudo apt purge bestbefore-agent
```

Purging deletes the enrolment and the agent's private key. `apt remove` keeps
them and the timer's state, so reinstalling picks up where it left off.
