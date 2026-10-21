# Configuration reference

Everything `mcpsonar run` can be told, where to put it, and the safe choice for each. Options
that carry **secrets** are read from the environment only, so they never appear in `ps`
output or shell history.

## Command line and environment

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--host` | | `127.0.0.1` | Bind address. `0.0.0.0` exposes the dashboard on the network. |
| `--port` | | `8675` | Dashboard / API / `/metrics` port. |
| `--db PATH` | `MCPSONAR_DB` | `./mcpsonar.db` | SQLite database (servers, history, users, sessions). |
| `--retention-days N` | `MCPSONAR_RETENTION_DAYS` | `7` | Drop check history older than N days (`0` keeps everything). |
| `--config FILE` | | — | Seed servers from YAML on first start (only while the DB has no servers). |
| `--no-auth` | | off | No login. Only on localhost or behind an authenticating proxy. |
| `--allowed-host H` (repeatable) | `MCPSONAR_ALLOWED_HOSTS` (comma-separated) | any host with the login on; `localhost`, `127.0.0.1`, `::1` with `--no-auth` | `Host` headers the instance answers to; anything else gets 400. `*.example.com` wildcards work. This is what defeats **DNS rebinding**. |
| `--trusted-origin O` (repeatable) | `MCPSONAR_TRUSTED_ORIGINS` | — | Extra browser origin allowed to make changes, e.g. `https://mcp.example.com` when a reverse proxy rewrites `Host`. |
| `--cookie-secure` | `MCPSONAR_COOKIE_SECURE` | `auto` | `auto` sets `Secure` when the request came over HTTPS; `always` / `never` force it. |
| `--allow-stdio-api` | `MCPSONAR_ALLOW_STDIO_API=1` | off | With `--no-auth`, still allow creating/changing stdio servers over the API. |
| | `MCPSONAR_SETUP_TOKEN` | random, printed in the log | One-time token that the first-admin setup requires. |
| | `MCPSONAR_METRICS_TOKEN` | — (public) | When set, `/metrics` requires `Authorization: Bearer <token>`. |
| | `FORWARDED_ALLOW_IPS` | `127.0.0.1` | (uvicorn) proxies whose `X-Forwarded-For` / `-Proto` are trusted. See *Reverse proxy*. |

### CLI client (remote mode)

| Environment | Default | What it does |
|---|---|---|
| `MCPSONAR_URL` | `http://127.0.0.1:8675` | The instance `status`, `servers`, `check`, `diff` and `history` talk to (`--url` overrides). |
| `MCPSONAR_TOKEN` | — | API token from the dashboard (**API tokens**). *read* tokens: GET only. *write* tokens: also check and change servers. Not needed with `--no-auth`. |

API tokens are stored as SHA-256 hashes and shown once. They can expire, are revoked from
the dashboard, and can't be used to create or list tokens. Prefer *read* tokens for
dashboards, scripts and CI; give *write* only to automation that must trigger checks or
change servers.

### Outbound connection policy

Applies to MCP checks (HTTP and SSE, including every redirect hop) and to webhook / Uptime
Kuma deliveries. Enforced when the TCP connection is opened, against the resolved address:

| Environment | Default | Effect |
|---|---|---|
| — | — | Always blocked: cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), `0.0.0.0`/`::`, multicast, reserved. |
| `MCPSONAR_ALLOW_LINK_LOCAL=1` | off | Allow `169.254.0.0/16` and `fe80::/10` (metadata addresses stay blocked). |
| `MCPSONAR_BLOCK_PRIVATE_NETWORKS=1` | off | Also block loopback, RFC 1918, ULA and CGNAT — for instances that only watch internet servers. |
| `MCPSONAR_OUTBOUND_ALLOW` | — | CIDRs always allowed (the only way to reach a metadata address on purpose). |
| `MCPSONAR_OUTBOUND_DENY` | — | CIDRs always blocked (wins over everything). |

**TLS trust:** HTTPS is verified with the operating-system trust store on Windows and
macOS, so enterprise root CAs installed there are honored. On Linux and in the container the
system CA bundle is used. `SSL_CERT_FILE` / `SSL_CERT_DIR` override both.

Private networks are allowed by default on purpose: watching the MCP servers on your own
network is a primary use case. Requests sent through `HTTP(S)_PROXY` connect to the proxy,
so the proxy must enforce its own destination rules.

## Server configuration (YAML / API)

```yaml
servers:
  my-server:
    url: "https://example.com/mcp"      # http(s) only
    transport: "http"                   # http | sse | stdio
    headers: { Authorization: "Bearer <token>" }
    check_interval_seconds: 60
    tools_to_test:                      # opt-in; nothing is called unless listed here
      - ping
      - name: search
        arguments: { query: "healthcheck" }
        timeout_seconds: 5              # default: latency_down_ms + 5 s
        allow_destructive: false        # default; see "Tool probes"
    thresholds: { latency_degraded_ms: 2000, latency_down_ms: 10000 }
    on_tool_change: "degrade"           # degrade | alert | ignore
    anomaly: { enabled: true, sensitivity: 4.0, degrade: false }
    webhooks:
      - { type: uptime_kuma, push_url: "https://kuma.example.com/api/push/<token>" }
      - { type: generic, url: "https://hooks.example.com/x", "on": [down, degraded] }
```

### Tool probes

- Only tools named in `tools_to_test` are called, one at a time, never inferred from names.
- A probe for a tool the server no longer lists fails **without** calling anything.
- A tool whose annotations say `destructiveHint: true` (and not `readOnlyHint: true`) is
  skipped unless the probe sets `allow_destructive: true`. **Annotations are hints written by
  the server**; the MCP specification says clients must treat them as untrusted. A malicious
  server can label a destructive tool read-only, so the skip is a safety brake for honest
  servers, not a guarantee. Only probe tools that are safe to call repeatedly.
- Each check has an overall time budget (`3 × (latency_down_ms + 5 s)` plus each probe's
  timeout); a server that hangs ends as `down` and the next check runs on schedule.

### stdio servers: the trust boundary

A stdio server is a **command mcpsonar executes** on its host, at every check, with
mcpsonar's user and filesystem permissions. mcpsonar does not use a shell and passes only a
minimal environment (the MCP SDK's allowlist, e.g. `HOME`, `PATH`) plus the `env` you set,
so its own secrets are not inherited. That is still full code execution:

- Only configure stdio servers you would run yourself. `npx -y some-package` downloads and
  runs whatever that package's latest version is; pin versions (`some-package@1.2.3`).
- For untrusted servers, run mcpsonar in the container image (unprivileged user, no
  capabilities) or monitor the server over HTTP from a separate sandbox.
- Without a login (`--no-auth`), stdio servers cannot be added over the API at all unless
  `--allow-stdio-api` is given; seed them from YAML instead.

## Secrets: what is shown, stored and exported

| Where | Credentials (headers, `env`, URL keys/userinfo, webhook URLs) |
|---|---|
| SQLite database | Stored in clear (mcpsonar needs them to monitor). Protect the file. |
| API reads, dashboard | Masked as `********`. Sending a masked value back on edit keeps the stored one. |
| `GET /api/export` | Masked. `?include_secrets=true` for a full export (handle it like a password file). |
| `POST /api/import` | Refuses a masked export with a clear error, instead of storing placeholders. |
| Check details, webhooks, Kuma, logs | Scrubbed of the server's credentials and of bearer tokens / keyed URLs. |
| Passwords / sessions | PBKDF2-SHA256 hashes / SHA-256 of the session token; never reversible. |

Prefer passing tokens through the environment of the process that renders your YAML (e.g.
a secret manager writing the seed file at deploy time) over committing them.

## Backups

The database is the whole state. Back it up with SQLite's online backup, which is safe while
mcpsonar runs:

```bash
sqlite3 /data/mcpsonar.db ".backup '/backups/mcpsonar-$(date +%F).db'"
# Docker: docker compose exec mcpsonar python -c "import sqlite3;s=sqlite3.connect('/data/mcpsonar.db');d=sqlite3.connect('/data/backup.db');s.backup(d)"
```

The backup contains credentials and password hashes: encrypt it and restrict access. To
share a configuration (an issue report, a colleague), use the redacted YAML export.

## Reverse proxy and HTTPS

For anything beyond localhost, terminate TLS in a reverse proxy and keep mcpsonar on
`127.0.0.1` (or an internal Docker network):

```nginx
location / {
    proxy_pass http://127.0.0.1:8675;
    proxy_set_header Host $host;                       # keep the public Host (CSRF check)
    proxy_set_header X-Forwarded-For $remote_addr;     # real client IP (login throttling)
    proxy_set_header X-Forwarded-Proto $scheme;        # Secure cookies
}
```

uvicorn trusts the forwarded headers only from `FORWARDED_ALLOW_IPS` (default `127.0.0.1`).
If the proxy runs elsewhere, set it to the proxy's address — never `*` on a port the
internet can reach. If the proxy cannot keep `Host`, add `--trusted-origin
https://your.public.name`.

## Upgrading from v0.5

- Existing logins end once (sessions moved server-side); sign in again. Passwords keep
  working and are re-hashed at 600k iterations on the next login.
- `GET /api/servers` no longer returns credentials. Scripts that read tokens back from the
  API must keep their own copy.
- `/api/export` is masked by default; add `?include_secrets=true` for the old behavior.
- `--no-auth` instances refuse new stdio servers over the API (`--allow-stdio-api` restores it)
  and answer only to loopback host names (add `--allowed-host`).
- The container runs as uid 10001; the entrypoint fixes the ownership of an existing volume
  automatically.
