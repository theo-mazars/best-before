# Running the dashboard

The dashboard is the one place agents report to. It runs as a container and
keeps everything in a single volume.

> [!WARNING]
> **Run the dashboard on a VPN or private network only. Never expose it to the
> internet.** It holds a complete map of every vulnerable package on every
> server.

## Image

Images are not published yet; they will be, signed, with the first release.
Until then, build one from a checkout. The Dockerfile compiles the dashboard
from source, so Docker is all you need:

```sh
make image        # prints the tag, e.g. bestbefore:v0.1.0
```

### On Dokploy

Only do this if Dokploy's domains are reachable from your VPN alone: the
dashboard must never be on the internet.

Create an application from this repository with the **Dockerfile** build type:

| Field | Value |
|---|---|
| Dockerfile Path | `packaging/docker/Dockerfile` |
| Docker Context Path | `.` |
| Docker Build Stage | *(empty)* |

Optionally, set `VERSION=…` in **Environment › Build Time Arguments**; the
version is otherwise `dev`. The Dockerfile only uses classic features, so it
builds with or without BuildKit.

In **Advanced › Volumes/Mounts**, add a **Volume Mount** for
`/var/lib/bestbefore`, and a **File Mount** at
`/etc/bestbefore/dashboard.conf` with this content:

```ini
listen = 0.0.0.0:8443
public_url = http://bestbefore.example.vpn
data_dir = /var/lib/bestbefore
# Traefik talks plain HTTP to the dashboard and forwards the client's address.
tls = proxy
trusted_proxies = 10.0.1.0/24
```

- **`trusted_proxies`** is the subnet of Dokploy's network, where Traefik
  runs: `docker network inspect dokploy-network --format '{{(index .IPAM.Config 0).Subnet}}'`.
  Only Traefik may then tell the dashboard who the visitor is, which keeps login
  rate limits per visitor and logs accurate.
- **`public_url`** is the domain agents use. With plain `http://` on a VPN, the
  dashboard and agents print a warning: reports stay encrypted and signed, but
  which servers report, and when, is visible on the network. If the domain has
  HTTPS, use `https://`; agents check its certificate against certificate
  authorities, or the one given with `--ca-file` when enrolling.

In **Domains**, set the **Container Port** to `8443`. The dashboard prints
its setup code in the application's logs on first start.

## Configuration

Write a configuration file, starting from the commented example, which shows
every setting at its default:

```sh
docker run --rm bestbefore:<version> config example > dashboard.conf
```

In a container, keep `listen = 0.0.0.0:8443` and choose where the dashboard is
reachable when publishing the port. You must set `public_url`, the address
agents use to reach the dashboard:

```ini
listen = 0.0.0.0:8443
public_url = https://dashboard.example.vpn:8443
data_dir = /var/lib/bestbefore
```

## Starting it

```sh
docker run -d --name bestbefore --restart unless-stopped \
  -p 10.8.0.1:8443:8443 \
  -v "$PWD/dashboard.conf:/etc/bestbefore/dashboard.conf:ro" \
  -v bestbefore-data:/var/lib/bestbefore \
  bestbefore:<version>
```

Replace `10.8.0.1` with the dashboard host's address on your VPN. Publishing
on `0.0.0.0` would expose it on every network the host is on.

The dashboard serves HTTPS with its own self-signed certificate (`tls =
builtin`). Agents pin it when they enrol, so there is nothing to set up for
them; your browser warns about it once. To use your own certificate, see the
`tls` setting in the example configuration.

## Creating the first admin

At first start, the dashboard prints a setup code in its log:

```sh
docker logs bestbefore
```

```
level=WARN msg="no admin yet: open https://dashboard.example.vpn:8443/setup and enter this setup code" setup_code=QLVU-FJ6A-UMB3-VQWQ
```

Open that page, enter the code, your email address and a password, and add the
dashboard to an authenticator app. Only someone who can read the logs can
complete setup, and the page disappears once an admin exists.

Every login needs the password and a code from the authenticator app.

## Managing users

Users are managed from the command line inside the container. Every change ends
the user's sessions, and the last admin cannot be demoted or deleted.

```sh
alias bb='docker exec -it bestbefore bestbefore'
bb user list
bb user add --email someone@example.org --role admin   # or --role user
bb user set-role --email someone@example.org --role user
bb user reset-password --email someone@example.org
bb user reset-totp --email someone@example.org        # lost authenticator
bb user delete --email someone@example.org
```

## Adding servers

In the dashboard, **Agents › Add a server** shows a one-time command to run on
the server. See [the agent's documentation](agent.md).

A server is shown as **stale** when it has not reported for `stale_after`
(48 hours by default): silence is a problem, never a clean server.

## Backups

Everything is in the `bestbefore-data` volume. Back it up regularly, and above
all `identity.key`: without it, every server has to be enrolled again.

```sh
docker stop bestbefore
docker run --rm -v bestbefore-data:/data:ro -v "$PWD:/backup" \
  ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 \
  tar -czf /backup/bestbefore-backup.tar.gz -C /data .
docker start bestbefore
```

The archive contains the dashboard's private keys: store it as carefully as
the dashboard itself.

When an update changes the database, the dashboard keeps a copy of the
previous version next to it (`bestbefore.db.before-….bak`).
