# Releases

Each release has one version, shared by the agent and the dashboard, and is
built, signed and published by the [release workflow](../.github/workflows/release.yml)
on GitHub Actions from a version tag. Nothing is built or signed on anyone's
own machine.

## What a release contains

| File | What it is |
|---|---|
| `bestbefore-agent_<version>_amd64.deb`, `…_arm64.deb` | The agent, for Ubuntu 22.04 or later. See [Running the agent](agent.md). |
| `….deb.spdx.json` | SBOM of the agent in each package: what is compiled into it (the Go standard library, nothing else). |
| `best-before-<version>.tar.gz` | The source. The dashboard is built from it, as a container image: see [Running the dashboard](dashboard.md#image). |
| `best-before-<version>.dashboard.spdx.json` | SBOM of the dashboard built from that source: every Go module compiled into it. |
| `best-before-<version>.ui.spdx.json` | SBOM of the dashboard's web interface: the npm packages it bundles and what they depend on, from `ui/package-lock.json`. Build tools they name as peers, such as Vite, are listed too. |
| `SHA256SUMS` | Checksums of all the files above. |
| `SHA256SUMS.sigstore.json` | Signature of `SHA256SUMS`, made by the release workflow with [Sigstore](https://www.sigstore.dev/). |

Every file also has a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
recording which workflow run, commit and tag produced it.

Versions follow [semantic versioning](https://semver.org/). Until 1.0.0, a
minor version may change the configuration, the database or the protocol;
the release notes say when.

## Verifying a release

Check what you download before installing it, on your workstation, with
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/). Put
the files of the release in one folder, then, replacing `v0.1.0` with the
version:

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/theo-mazars/best-before/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS    # shasum -a 256 --ignore-missing -c SHA256SUMS on macOS
```

The first command proves that `SHA256SUMS` was signed by this repository's
release workflow, running for that tag; the second, that your files are the
ones it lists. Both must succeed.

With the [GitHub CLI](https://cli.github.com/), you can check a file's build
provenance instead:

```sh
gh attestation verify bestbefore-agent_0.1.0_amd64.deb \
  --repo theo-mazars/best-before \
  --signer-workflow theo-mazars/best-before/.github/workflows/release.yml
```

Once checked, copy the package to your servers.

## Reproducing a release

Builds are reproducible: from the same tag, anyone gets the same packages and
source archive, byte for byte. You need Go, at the version in `go.mod`, and
git. SBOMs differ, as each records when it was made.

```sh
git clone --branch v0.1.0 https://github.com/theo-mazars/best-before.git
cd best-before
make dist VERSION=v0.1.0
shasum -a 256 dist/release/*.deb dist/release/*.tar.gz    # compare with SHA256SUMS
```

## Making a release

For maintainers.

### Once, in the repository's settings

- **Environments › New environment** `release`: add yourself as a required
  reviewer, and limit deployments to tags matching `v*`. The signing job then
  waits for your approval, and only a version tag can request it.
- **Rules › Rulesets**: a tag ruleset on `v*` that blocks deletion and
  updates, so a published tag can never move to another commit.
- **General › Releases**: enable release immutability, so the files of a
  published release cannot be replaced.

### Each time

1. Make sure `main` holds what you want to release, and that it passes:

   ```sh
   git switch main && git pull
   make check-pins
   make check
   make audit                       # known vulnerabilities in Go and npm dependencies
   make dist VERSION=v0.1.0-rc.1    # optional: the release, built locally, unsigned
   ```

2. Tag the commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "Best Before v0.1.0"
   git push origin v0.1.0
   ```

   A version with a suffix, such as `v0.2.0-rc.1`, becomes a pre-release.

3. In **Actions › Release**, the build job tests and builds, then the release
   job waits for your approval to sign. Approve it.

4. The release is created as a **draft**. Check its files, verify them as
   above, write the release notes, and publish it.

If something is wrong, delete the draft, fix it on `main` and release the
next version (`v0.1.1`, or `v0.1.0-rc.2` for a pre-release). Tags never move
and are never reused, so a version always means the same files.

### Accepted vulnerabilities

`make audit` fails on any known vulnerability in the dependencies, except
those below. Each is accepted because no fixed version exists and the
vulnerable code cannot be reached; remove it from here and from
`scripts/audit.sh` once a fix is released, and add any new one to both.

| ID | Package | Why it is accepted |
|---|---|---|
| [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) | `deepmerge` 4.3.1 (npm), through `@sveltejs/vite-plugin-svelte` | Prototype poisoning when merging attacker-controlled objects. The Svelte plugin only uses it while the web interface is built, to merge our own configuration; it is not in the interface the browser loads. Accepted on 2026-11-12. |
| [GO-2026-6905](https://pkg.go.dev/vuln/GO-2026-6905) | `github.com/blakesmith/ar` (Go), through Syft | A crafted `ar` archive (such as a `.deb`) panics the reader. The dashboard imports it through Syft and Grype but never calls it; the Syft that releases are built with only reads our own binaries and `ui/package-lock.json`. Accepted on 2026-11-12. |
