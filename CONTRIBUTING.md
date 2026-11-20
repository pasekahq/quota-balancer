# Contributing to quota-balancer

Thanks for helping. The organization-wide guide is
[pasekahq/.github CONTRIBUTING](https://github.com/pasekahq/.github/blob/main/CONTRIBUTING.md);
this file adds what is specific to `qb`.

## Before you start
- Bugs and feature ideas: open an issue first. Changes to the wire API or the threat model need an
  ADR in `docs/adr/` before code.
- Security issues: never in public issues, see [SECURITY.md](SECURITY.md).

## Checks
```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check advisories bans licenses sources
```
CI also runs `msrv`, `gitleaks`, size/RSS `budgets` and `systemd-units`. `main` is protected: every
change lands through a pull request with green CI.

## Sign-off (DCO), no CLA
Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` (or `git rebase --signoff main` for commits you already made). The sign-off
must match the commit author. The `dco` check enforces it on pull requests from outside the
maintainer team.

## License
`qb` is licensed under [AGPL-3.0-only](LICENSE). By signing off you certify that you have the
right to submit your contribution under that license, and you license it under the same terms.
