# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
vulnerability reporting: *Security → Report a vulnerability* on
[alefra93/MCPSonar](https://github.com/alefra93/MCPSonar/security). Include the version or
commit, how to reproduce, and the impact you expect.

You will get an acknowledgement within **5 working days**. Fixes for confirmed issues ship in
a patch release with a changelog entry and, for anything above *low*, a GitHub Security
Advisory crediting you (unless you prefer otherwise). This is a volunteer-maintained
project: there is no bug bounty.

## Supported versions

Only the latest minor release receives security fixes until 1.0. After 1.0, the latest two
minor releases will.

## What MCPSonar is, security-wise

MCPSonar holds **credentials for the MCP servers it watches**, **makes outbound requests** to
URLs people configure, and can **launch processes** (stdio servers). It is designed for a
single trusted operator (one admin account). The table states which side of each boundary
is trusted.

| Boundary | Trusted | Untrusted | Controls |
|---|---|---|---|
| Dashboard / API | the admin (after login) | everyone else on the network; other websites in the admin's browser | login with setup token, server-side sessions, login throttling, CSRF (`Origin` / `Sec-Fetch-Site`) and `Host` checks, security headers, body limits |
| API tokens (CLI, automation) | holders of a token the admin created | everyone else | hashed at rest, shown once, *read* (GET only) or *write* scope, optional expiry, revocable, cannot mint tokens, no cookie (not CSRF-able) |
| Monitored MCP servers | — | their responses, tool definitions, annotations, redirects | outbound policy (metadata / link-local blocked, checked at connect time), credentials kept on their origin, timeouts, pagination limits, tool definitions rendered escaped |
| stdio servers | the command the admin configured | — (it *is* code execution) | no shell, minimal environment, refused over an unauthenticated API |
| Tool probes | tools the admin listed | annotations (`readOnlyHint`, `destructiveHint`) | opt-in only, never call unlisted tools, skip annotated-destructive tools by default |
| Webhooks / Uptime Kuma | their configured URL | redirects | outbound policy, no redirects followed, secrets scrubbed from payload details |
| SQLite file | the host's filesystem permissions | — | credentials in clear (needed to monitor), password and session hashes only |

### What the security findings mean

- **Tool-poisoning lint** results are *heuristic matches* on tool text. A match means
  "a human should read this definition", not "this server is malicious", and no match does
  not mean a server is safe.
- **Tool changes** are *differences from the pinned baseline*. Most are legitimate releases;
  the point is that a person reviews them before agents keep trusting the tool.
- MCPSonar **observes**; it does not sit between your agents and their servers and does not
  block calls. Pair it with a gateway/proxy if you need enforcement.

## Safe deployment checklist

1. Keep the login on. Use `--no-auth` only on `127.0.0.1` or behind a proxy that
   authenticates.
2. Expose it over **HTTPS** through a reverse proxy, keep `--cookie-secure auto` (or
   `always`), and restrict `--allowed-host` to the public name.
3. Read the **setup token** from your own logs; set `MCPSONAR_SETUP_TOKEN` in automated
   deployments.
4. Set `MCPSONAR_METRICS_TOKEN` if `/metrics` is reachable by anyone but your Prometheus.
5. Run the **container image** (unprivileged uid 10001, no capabilities) or a dedicated
   unprivileged user. Monitor untrusted stdio servers from a sandbox, or not at all.
6. On a cloud VM, leave link-local blocked; set `MCPSONAR_BLOCK_PRIVATE_NETWORKS=1` if the
   instance should only reach internet-facing servers.
7. Protect and encrypt **database backups** — they contain credentials. Share configs with
   the redacted export.
8. Pin the GitHub Action to a release tag or commit SHA, never `@main`.

Full option reference: [docs/configuration.md](docs/configuration.md). Findings and fixes from
the latest audit: [docs/engineering-audit.md](docs/engineering-audit.md).
