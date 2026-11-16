# Security policy

`qb` sits next to subscription credentials, so security reports are welcome.

- Report privately via GitHub's "Report a vulnerability" (Security tab). Please do not open a
  public issue for a vulnerability.
- Include the version (`qb --version`), the role involved (`qbd`, `qb agent`, CLI) and steps to
  reproduce.

Threat model in short: the daemon holds no vendor secrets and has no network access; only the
agent reads credential files, read-only, briefly, under landlock. See `docs/design.md`.
