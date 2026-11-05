# Running the dashboard

The dashboard is the one place agents report to. It runs as a container and
keeps everything in a single volume.

> [!WARNING]
> **Run the dashboard on a VPN or private network only. Never expose it to the
> internet.** It holds a complete map of every vulnerable package on every
> server.

## Image

No image is published: you build it from the release's source, which takes a
few minutes and needs only Docker. The Dockerfile compiles the dashboard in a
pinned Go image and copies it alone into a minimal, non-root base image.

Download the release's `best-before-<version>.tar.gz`, `SHA256SUMS` and
`SHA256SUMS.sigstore.json`, and check them as described in
[Releases](releases.md#verifying-a-release). Then, replacing `v0.1.0` with the
version:

```sh
tar -xzf best-before-v0.1.0.tar.gz
cd best-before-v0.1.0
docker build -f packaging/docker/Dockerfile --build-arg VERSION=v0.1.0 -t bestbefore:v0.1.0 .
```

`best-before-v0.1.0.dashboard.spdx.json`, in the release, lists every module
compiled into the dashboard. From a git checkout, `make image` does the same
build, with the version from git.

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

Agents keep the address they enrolled with. If `public_url` changes later,
tell each server, as described in
[the agent's documentation](agent.md#when-the-dashboard-moves).

## Starting it

```sh
docker run -d --name bestbefore --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 10.8.0.1:8443:8443 \
  -v "$PWD/dashboard.conf:/etc/bestbefore/dashboard.conf:ro" \
  -v bestbefore-data:/var/lib/bestbefore \
  bestbefore:<version>
```

Replace `10.8.0.1` with the dashboard host's address on your VPN. Publishing
on `0.0.0.0` would expose it on every network the host is on.

The dashboard needs no privileges and writes only to its volume, so the
container runs read-only, without capabilities, and cannot gain any.

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

## Vulnerability database

The dashboard checks every report against the
[Grype](https://github.com/anchore/grype) vulnerability database, which it
downloads from `grype.anchore.io` and keeps in `data_dir/vulnerability-db`:

- The first start downloads about **200 MB**, which unpacks to about **3.5
  GB**. Allow **8 GB** free in the volume: during an update, the old and new
  databases briefly coexist.
- The dashboard looks for a newer database every 6 hours (Anchore publishes
  one a day). After each update, it checks every server's latest report again,
  so a vulnerability published today is found in a report sent last week.
- It needs outbound HTTPS to `grype.anchore.io`, and trusted CA certificates
  (included in the image; install `ca-certificates` if you run the binary
  directly). Behind a proxy that inspects HTTPS, set `SSL_CERT_FILE` to a
  bundle that includes the proxy's CA. The dashboard still never connects to
  your servers.
- If updates keep failing, the database is refused once it is more than 5 days
  old, and servers are shown as **not checked yet** rather than clean.

Host and image packages are checked against their distribution's own security
data (Ubuntu, Debian, Alpine, Red Hat and its rebuilds, Oracle Linux, Amazon
Linux, SUSE Linux Enterprise…), which knows about backported fixes. When the
database has no data for an image's distribution (openSUSE Leap, for
example), the image is shown as **not checked**, never as clean. Software
found through `*_VERSION` variables (Node, Python, Redis…) is checked by version
against the NVD, which is noisier; Go (`GOLANG_VERSION`) is checked against
Go's own vulnerability data. The programs inside images are not analysed:
they are their developers' responsibility.

Each image on a server's page says what was checked: how many packages, of
which system, and which runtimes. An image with nothing Best Before can read,
such as a single static program built `FROM scratch`, says **nothing to
check** rather than passing for clean; it does not change the server's
status. A runtime whose variable gives no precise version (`REDIS_VERSION=7`)
is listed as not checked.

Each server has one status, for what there is to do now:

- **Critical:** an open vulnerability worth an emergency alert, as set under
  **What is worth sending** (by default: known exploited, or CVSS 9.0 or
  more, with a fix available). The status and the alerts follow the same rule.
- **Needs attention:** security updates to install, a reboot required, or a
  gap: a report with errors, or an image that could not be checked.
- **OK:** nothing to do now. Other vulnerabilities, such as a medium one with
  no update offered yet, still show in the counts but do not change it.
- **Stale**, **Waiting** and **Not checked**: no recent report, none yet, or
  not checked against the vulnerability database yet. While the latest report
  waits to be checked, the server's page shows the previous vulnerabilities,
  dimmed, with a note.

Vulnerabilities without a fix are listed on the server's page, greyed out and
marked **No fix yet**; they count once a fix is published.

A vulnerability counts once on the host, and once in each image, whatever the
number of packages it is in there: openssl and libssl3, or the packages of
one kernel, are built from the same source and fixed together. It counts as
its most urgent package: if one of them has a fix, it has one. The server's
page still lists it under each package, which is what gets updated.

## Alerts and digest

Under **Settings**, add one or more notification channels: **email** (SMTP),
**ntfy**, **Discord**, **Slack** or a **webhook** (a JSON POST, for your own
automation). Each one can receive emergencies, the weekly digest, or both,
and has a **Send test notification** button.

**Emergencies** are sent as soon as they are found, once per server and
vulnerability. By default, an emergency is a vulnerability **with a fix
available** that is **known to be exploited** (on CISA's KEV catalogue), or
has a **CVSS score of 9.0 or more**. Vulnerabilities without a fix are never
sent; when a fix is published, they count like any other.

While one stays open, a reminder is sent every 7 days. It closes by itself
once a report no longer has it. A server that stops reporting is also sent at
once, and again when it reports.

The **weekly digest** is sent on Monday at 08:00 UTC by default. It lists, in
this order: emergencies still open, stale servers, APT security updates
waiting on each server, vulnerabilities with a fix (medium or worse)
found since the previous digest, and accepted risks that have expired since
then or expire within a week. With nothing to list, it says all is clear,
so you know the dashboard is alive. Emails include HTML and plain text
versions.

What counts as noise is yours to decide, under **Settings › What is worth
sending**:

- whether being known exploited makes an emergency, and from which CVSS
  score (or none);
- how often open emergencies are repeated;
- the digest's day, time and time zone, or no digest;
- which sections it has, the lowest severity of the new vulnerabilities it
  lists, and whether it is sent when all is clear.

**Send the digest now** sends one at once, without moving the next.

Alerts found while no channel takes them are not sent later, once one is
added: the dashboard shows them. When every channel fails, the dashboard tries
again 15 minutes later and logs why.

The KEV catalogue comes with the vulnerability database, which includes it and
is updated daily: there is nothing more to download.

A few things to know:

- Email needs an SMTP server with STARTTLS (usually port 587) or TLS (465),
  and its certificate is always checked. Plain SMTP (`none`) is only accepted
  for a relay on the dashboard's own machine: emails list every vulnerable
  package.
- ntfy and webhooks accept `http://` for a service on your private network;
  Discord and Slack need `https://`.
- On ntfy.sh, anyone who knows a topic can read it: choose a long random topic,
  or protect it with an access token.
- Passwords, tokens and webhook URLs are stored encrypted, with a key derived
  from `identity.key`. A copy of the database alone does not reveal them;
  someone with the whole data directory can. If `identity.key` is replaced,
  enter them again.
- Set `public_url` for notifications to link to the dashboard.

## Accepted risks and your threshold

Some vulnerabilities do not matter on your servers: the vulnerable feature is
off, or the service is only reachable over your VPN. Expand its package on a
server's page, click **Accept** next to it, say why, and choose until when (90
days by default, a year at most). Until then, it:

- does not count towards the server's status;
- raises no emergency, and closes one already open;
- is left out of the digest, until its expiry is a week away.

It stays listed on the server's page, greyed out and marked **Accepted until**
its expiry, with the reason and who accepted it in its tooltip, and can be
changed or withdrawn there.
On expiry it counts again: if it is an emergency, it is sent at once, and the
next digest lists it. An acceptance covers one vulnerability on one server's
host, or on one of its images: in every package affected there, but nowhere
else. When the image is updated, it is a new image, and is checked afresh.

Under **Settings › Your pages**, each user chooses the lowest severity their
pages show (low by default). Less severe vulnerabilities are still checked and
listed on each server's page, greyed out and marked **Below threshold**, but do
not count towards its status. Vulnerabilities known to be exploited, and those of
unknown severity, are always shown. This only changes what you see:
emergencies and the digest follow **What is worth sending**.

## Old kernels

A kernel package installed but not running, for example
`linux-image-6.8.0-50-generic` on a server running `6.8.0-60-generic`, cannot
be attacked until the server boots it. Its vulnerabilities are listed greyed
out and marked **Not running**, and a note on the server's page names the
old kernels installed. They count towards nothing: no status, no emergency,
no digest. After a reboot into that kernel, they count like any other.
`apt autoremove` removes old kernels.

A newer kernel, installed but waiting for a reboot, is treated the same way,
and the note says so: until the reboot, the running kernel's vulnerabilities
are the ones that count, and the server usually shows a reboot as required.

## Backups

Everything is in the `bestbefore-data` volume. Back it up regularly, and above
all `identity.key`: without it, every server has to be enrolled again. Leave
out the vulnerability database: it is large, and downloaded again if missing.

```sh
docker stop bestbefore
docker run --rm -v bestbefore-data:/data:ro -v "$PWD:/backup" \
  ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 \
  tar -czf /backup/bestbefore-backup.tar.gz --exclude=./vulnerability-db -C /data .
docker start bestbefore
```

The archive contains the dashboard's private keys: store it as carefully as
the dashboard itself.

When an update changes the database, the dashboard keeps a copy of the
previous version next to it (`bestbefore.db.before-….bak`).
