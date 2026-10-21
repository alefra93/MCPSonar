# Changelog

All notable changes to MCPSonar. Versions follow [SemVer](https://semver.org/); each release
is a Git tag `vX.Y.Z`, which is also how the GitHub Action is pinned.

## [0.7.0] — 2026-10-21

### Added
- CLI commands `tools`, `risks`, `config validate|show|export`, `doctor` and `version`
  (plus `--version`). They work without a running instance, against a URL, `--stdio` or a
  server name from a YAML file. Every command supports `--format json`, `NO_COLOR` /
  `--no-color`, results on stdout and diagnostics on stderr, and stable exit codes (0/1/2).
  See [docs/cli.md](docs/cli.md).
- A rule registry (`lint.RULES`): every finding's rule ID now has a title, an explanation
  and a remediation.
- **API tokens** for the CLI and automation: created and revoked in the dashboard (new **API
  tokens** dialog). They are scoped *read* (GET only) or *write*, can expire, are stored
  hashed and shown once, and can't manage tokens. They are sent as
  `Authorization: Bearer mcps_…`.
- Remote-mode CLI commands that work against a running instance (`MCPSONAR_URL`,
  `MCPSONAR_TOKEN`), through the same API as the dashboard and never through its database:
  - `status`;
  - `servers list|show`;
  - `check NAME|--all`, run by the instance;
  - `diff NAME`: changes marked pending, SUSPICIOUS or APPROVED; never approves anything;
  - `history NAME --last 24h`: uptime, latency percentiles, baseline, shift, incidents;
  - `servers add|edit|pause|resume|remove`. `--header-from-env` keeps credentials out of
    shell history. `edit` changes only the given options and keeps credentials and probe
    arguments. `remove` asks for confirmation on a terminal and needs `--yes` otherwise.
- `GET /api/servers/{id}/tool-changes` includes the lint `findings` of each new definition.

### Protocol
- **MCP Python SDK 2.x (`mcp>=2.3,<3`) and spec revision 2026-07-28.** One client speaks both
  protocol eras: `server/discover` for 2026-07-28 servers, falling back to `initialize` for
  2024-11-05 … 2025-11-25 servers. Servers that only speak 2026-07-28 used to be reported
  *down*. 5 of the 24 public servers in `examples/popular-servers.yaml` already speak it.
- New validator for 2026-07-28. `spec_version` reports the negotiated revision.
- Unchanged:
  - **Tool fingerprints:** identical to mcp 1.x, with golden values tested and 42/42 tools
    checked on live servers. Stored baselines and lockfiles are re-normalized, so annotation
    keys 2.x no longer represents don't count as changes.
  - **401/403/429 handling:** *auth required*, *credentials rejected*, *rate limited* +
    `Retry-After`.
  - **Latency continuity:** HTTP times only the RPC that succeeded; stdio includes process
    startup, as before. A 401/403/429 on the discover probe ends negotiation at once, so
    protected servers cost one request per check, as before.
- `httpx` is replaced by `httpx2`, the stack mcp 2.x uses, so the outbound policy covers one HTTP
  stack. On Windows and macOS, TLS uses the operating-system trust store, so corporate CAs work
  without extra configuration.
- "down" details now include the HTTP status when there was one (e.g. `(HTTP 503)`).

### Changed
- The dashboard's Tools view, `mcpsonar scan` and the new commands share one inspection
  service. As a result `scan` now has an overall time budget too.
- One-shot commands log only warnings; `run` and `demo` are unchanged.
- `scan` also accepts `--format json`.

### Fixed
- `--stdio` with quoted paths on Windows (e.g. `"C:\Program Files\nodejs\npx.cmd"`): the
  quotes were kept as part of the path, so the command could not be found.

## [0.6.0] — 2026-10-21

Security hardening release. Details, evidence and tests for each item:
[docs/engineering-audit.md](docs/engineering-audit.md). Upgrade notes:
[docs/configuration.md](docs/configuration.md#upgrading-from-v05).

### Security
- **Critical:** blocked a drive-by remote command execution. A page on any website could POST
  YAML to `/api/import` on an `--no-auth` instance (including `mcpsonar demo` and the watch
  compose) and make MCPSonar launch an arbitrary stdio command. State-changing requests from
  other sites or origins are now refused, and with `--no-auth`, stdio servers can't be added
  over the API unless `--allow-stdio-api` is given.
- `Host` allowlist (`--allowed-host`; loopback-only by default with `--no-auth`) against
  DNS rebinding.
- First-admin setup requires a one-time token printed in the log (or
  `MCPSONAR_SETUP_TOKEN`); concurrent setups can no longer create two admins.
- Server-side sessions, revoked on logout and stored as hashes; `Secure` cookie over HTTPS
  (`--cookie-secure`).
- Login throttling; PBKDF2 raised to 600k iterations and moved off the event loop (old hashes
  are upgraded at the next login).
- Credentials (headers, `env`, URL keys and userinfo, webhook and push URLs) are masked in API
  responses, the dashboard and exports, and scrubbed from check details, webhook and Kuma
  messages, logs and `scan` output. Editing a server keeps its stored credentials.
- Outbound policy enforced at connect time: cloud metadata and link-local addresses blocked;
  `MCPSONAR_BLOCK_PRIVATE_NETWORKS`, `MCPSONAR_OUTBOUND_ALLOW` / `_DENY`. Configured headers are
  no longer forwarded on cross-origin redirects; at most 5 redirects.
- Security headers (no framing, CSP, nosniff, no-referrer); 1 MiB body limit; bounded history
  queries; optional `MCPSONAR_METRICS_TOKEN` for `/metrics`; http(s)-only URLs.
- The container runs as an unprivileged user with no capabilities and has a HEALTHCHECK.
- `pyjwt>=2.15` and `certifi>=2026.10.19` (transitive dependencies with known advisories, GHSA-6q48-6c7w-9gw2 for certifi); CI runs `pip-audit`.

### Fixed
- `tools/list` pagination is followed. Only the first page used to be checked, pinned and
  linted.
- A stdio server that never answers can no longer hang its check loop: session read timeouts
  plus an overall check budget.
- Probes never call a tool the server doesn't list, and skip tools annotated destructive
  unless `allow_destructive: true`; new per-probe `timeout_seconds`.
- Duplicate tool names are reported; reordering a schema's `required` list is no longer a
  "tool change".
- Concurrent checks of the same server (Check now + loop) could record tool changes twice.
- Editing a server in the dashboard dropped its probes' arguments.

### Changed
- `GET /api/export` is masked by default (`?include_secrets=true` for a full export); import
  refuses a masked export.
- Everyone signs in once more after upgrading (sessions moved server-side).
- CI runs on Linux, Windows and macOS and smoke-tests the Docker image; Dependabot enabled.

## [0.5.0] — 2026-10-14

First tagged release.

### Added
- **Rug-pull detection**: every server's tool definitions are pinned on first sight; added,
  removed or changed tools are recorded and (by default) keep the server *degraded* until a
  human reviews the diff in the dashboard.
- **Tool-poisoning lint**: hidden Unicode, instruction overrides, fake `<IMPORTANT>` blocks,
  "don't tell the user", credential paths, exfiltration, tool shadowing, suspicious
  parameters.
- **Anomaly detection** with a learned per-server baseline: latency spikes (robust z-score),
  level shifts (change point) and flapping.
- `mcpsonar scan`: one-shot scan with a tool **lockfile** for CI, plus a GitHub Action.
- `mcpsonar demo`: dashboard against four scripted demo servers.
- `examples/popular-servers.yaml` + `docker-compose.watch.yml`: watch 24 hosted MCP servers.
- Validators for MCP spec 2024-11-05, 2025-03-26 and 2025-06-18 (besides 2025-11-25).

### Changed
- OAuth-protected servers (401/403 to an anonymous client) are **up · auth required**
  instead of down; rejected credentials are down; 429 is degraded (rate limited).

### Fixed
- Latency was inflated when several servers were checked at once (a TLS context was rebuilt
  on every check).
- Pinned `mcp>=1.28,<2`: the 2.x SDK is a breaking rewrite and broke every check on a fresh
  install.
- Source files contained literal zero-width and bidi-override characters (in the lint's own
  regex and two test fixtures). They are now written as Unicode escape sequences, and CI
  rejects any invisible character in tracked files.
- ruff pinned to an exact version so CI and local linting agree.
- Pausing, editing or deleting a server while one of its checks was in flight could hang
  forever: the MCP SDK can turn a cancellation into an ordinary error, which was recorded as
  "down" and the check loop kept running. Cancellation is now always propagated.
