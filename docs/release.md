# Releases

A release is a tag `v<version>` on `main`. The workflow
[`.github/workflows/release.yml`](../.github/workflows/release.yml) builds it, checks it, attests
its build provenance and publishes it; nobody uploads binaries by hand. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a minor version may break the CLI, the
config files or `/v1` (see [CHANGELOG.md](../CHANGELOG.md)).

## Assets

Every release has the same asset names, with only the version changing, so that a consumer can
pin an asset by URL and SHA-256:

| Asset | What |
|---|---|
| `qb-x86_64-unknown-linux-musl` | the static binary for x86_64 Linux |
| `qb-aarch64-unknown-linux-musl` | the static binary for arm64 Linux |
| `qb-<version>-x86_64-unknown-linux-musl.tar.gz` | a directory `qb-<version>-<target>/` with `qb`, `LICENSE`, `README.md` and `CHANGELOG.md` |
| `qb-<version>-aarch64-unknown-linux-musl.tar.gz` | the same for arm64 |
| `SHA256SUMS` | the SHA-256 of every other asset, in `sha256sum` format |

The URL of an asset is
`https://github.com/pasekahq/quota-balancer/releases/download/v<version>/<asset>`.
Each asset has a build provenance attestation signed through Sigstore and stored with GitHub.
`qb --version` prints the version and the git revision the binary was built from, e.g.
`qb 0.2.0 (0123456789ab)`.

## Verify a release

```sh
gh release download v0.2.0 -R pasekahq/quota-balancer
sha256sum -c SHA256SUMS
gh attestation verify qb-x86_64-unknown-linux-musl -R pasekahq/quota-balancer
chmod +x qb-x86_64-unknown-linux-musl && ./qb-x86_64-unknown-linux-musl --version
```

Without `gh`, download the assets with any HTTP client from the URLs above; `sha256sum -c
--ignore-missing SHA256SUMS` checks only the assets you downloaded.

The binaries are meant to be reproducible: the workflow builds each target twice, from checkouts
at different paths, with paths remapped and `SOURCE_DATE_EPOCH` set to the commit time, and fails
unless both builds are the same bytes. Rebuilding with the same stable Rust release as the
release's log shows (`rustc -V` in the build job) and `ci/release.sh build <target>` should give
the same SHA-256 as the release's bare binary.

## What the workflow checks

Before anything is published, for both targets:

- the tag is `v` followed by `[workspace.package] version` of `Cargo.toml`;
- `cargo build --release --locked --target <target>` on a runner of that architecture
  (`ubuntu-24.04`, `ubuntu-24.04-arm`), the binary static (no program interpreter, no shared
  libraries), its `--version` the version and the commit, and `ci/budgets.sh` green;
- a second build from another path gives the same bytes;
- `CHANGELOG.md` has a section for the version, which becomes the release notes.

Then it attests every asset and creates the release with `gh release create --verify-tag`. A run
by hand (`workflow_dispatch`) or a pull request that touches the release path is a dry run: it
builds, checks and checksums, and a dispatch also attests, but nothing is published.

## Make a release (maintainers)

1. On a branch from `main`, bump `version` in `[workspace.package]` of `Cargo.toml` and run
   `cargo update -w` so that `Cargo.lock` follows.
2. In `CHANGELOG.md`, move the entries of `[Unreleased]` into a new section
   `## [<version>] - <YYYY-MM-DD>` and add its compare link at the bottom.
3. Optionally check the release path locally:
   `ci/release.sh build x86_64-unknown-linux-musl && ci/budgets.sh &&
   ci/release.sh notes <version>`.
4. Open the pull request; the release workflow runs as a dry run on it. Merge when CI is green.
5. Tag the merge commit and push the tag:

   ```sh
   git fetch origin
   git tag -a v<version> -m 'qb <version>' <merge commit>
   git push origin v<version>
   ```

6. Watch the `Release` workflow. If it fails before the release exists, fix the cause in a pull
   request, delete the tag (`git push origin :refs/tags/v<version>` and `git tag -d v<version>`)
   and tag the new merge commit. Once a release is published, never move its tag: publish a new
   patch version instead.
