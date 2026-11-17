# Security policy

`qb` sits next to subscription credentials, so security reports are welcome.

- Report privately via GitHub's "Report a vulnerability" (Security tab). Please do not open a
  public issue for a vulnerability.
- Include the version (`qb --version`), the role involved (`qbd`, `qb agent`, `qb gateway`, CLI) and steps to
  reproduce.

Threat model in short: the daemon holds no vendor secrets and has no network access. Only the
agent and the optional gateway touch credential files, both under landlock and as the
credential owner: the agent reads them, read-only and briefly; the gateway reads them per
request and writes refreshed OAuth tokens back. See `docs/design.md` and
`docs/adr/0001-model-gateway.md`.
