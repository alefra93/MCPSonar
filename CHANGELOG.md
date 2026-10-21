# Changelog

All notable changes to MCPSonar. Versions follow [SemVer](https://semver.org/); each release
is a Git tag `vX.Y.Z`, which is also how the GitHub Action is pinned.

## [Unreleased]

### Fixed
- History is ordered deterministically when two checks share a timestamp (coarse clocks
  on Windows): insertion order wins. A test depending on it failed intermittently on the
  Windows CI runner.

## [0.8.0] — 2026-10-21

### Observability
- **Where the time goes.** Every check now records:
  - `timings_ms`: `handshake`, `discovery` (every `tools/list` page), `probes` and `total`
    (connection set-up included);
  - `tool_latency_ms`: the latency of each probed tool call.
- **Unchanged meaning:** `latency_ms` is still the handshake, so baselines, anomaly detection
  and dashboards behave as before. The new fields are additive in the API, webhooks and the
  database, through an automatic migration.
- **Prometheus:** new `mcpsonar_check_duration_ms`, `mcpsonar_phase_latency_ms{phase}` and
  `mcpsonar_tool_latency_ms{tool}`. No existing metric was renamed.
- **CLI:** `mcpsonar history` shows the median of each phase and of each probed tool.
- **Response drift.** For each probed tool, MCPSonar remembers the *shape* of the answer
  (error or not, content types, structure of `structuredContent`, order of magnitude of the
  size) and reports a `response_drift` anomaly once when it changes.
  - Response content is never stored.
  - Opt-in `drift: hash` (with `drift_ignore`) also catches value changes on deterministic
    probes; `drift: off` disables it per probe.
  - The status is not affected. See [Response drift](docs/configuration.md#response-drift).

### Packaging and developer experience
- **`mcpsonar completion bash|zsh|fish|powershell`**, generated from the CLI's own parser,
  so it always matches the installed version; no new dependency.
- **`doctor` checks the remote setup:** whether `MCPSONAR_TOKEN` is accepted (scope,
  expiry), the instance version against the CLI's, and it refuses to send the token over
  plain HTTP to a non-local instance. `/api/auth/status` reports the version only to an
  authenticated caller, and the validity of a bearer token sent with it.
- **Checked packages.** A CI `package` job builds the wheel and sdist, checks their metadata
  and contents (`scripts/check_package.py`, `twine check --strict`), installs the wheel into
  a clean environment, runs it, and runs it through `uvx`. Releases attach both files.
- **Metadata:** Documentation, Changelog and Issues URLs; README links are absolute, so they
  work outside GitHub too; the sdist no longer ships the screenshots (7.3 MB to 241 KB).

### Secret references
- Header and stdio `env` values accept `${env:NAME}` and `${file:PATH}`, resolved at every
  check and never stored, exported or shown resolved. `${file:...}` is re-read on every
  check, so a rotated secret needs no restart.
- **Allowlisted reads**, because configurations also come from the API and shared files:
  variables named `MCPSONAR_SECRET_*` or listed in `MCPSONAR_SECRET_ENV`; files inside
  `/run/secrets` or `MCPSONAR_SECRETS_DIR` (after resolving symlinks and `..`).
- **Errors:** a malformed or forbidden reference is refused by the API (400) and by config
  loading; an unresolvable one makes the check `down` with the reason, never a value.
- **Display:** references are shown as-is in the dashboard, the API and exports, so an
  export with references is complete and safe to share.
- See [Secret references](docs/configuration.md#secret-references).

### Storage
- **Versioned schema.** The database records its schema version (`PRAGMA user_version`)
  and is migrated forward on start by numbered steps, each in its own transaction.
  Databases from v0.5, v0.6 and v0.7 are upgraded automatically; tests restore databases
  created by each released tag and check that the migrated schema equals a new one.
- **Backup before migrating:** `mcpsonar.db.schema<N>.bak` is written next to the database.
- **No silent downgrade:** a database written by a newer mcpsonar is refused (exit 2).
- **WAL mode** with a separate read-only connection: reads no longer wait for writes.
  Back up with SQLite's online backup, not by copying the `.db` file alone (see
  [Backups](docs/configuration.md#backups)).
- **Atomic writes.** Each write runs in one transaction, one writer at a time. Before, a
  multi-statement write (replacing a tool snapshot) could be committed halfway by another
  task sharing the connection.

### Anomaly detection
- **Episodes.** A run of slow checks is one episode: the first `latency_spike` is notified,
  the following ones carry `ongoing: true` (kept in the history, not notified), and the
  first normal check reports a new **`latency_recovered`** anomaly. Generic webhooks with
  `on_anomaly` now fire once per episode plus the recovery, instead of on every slow check.
  `anomaly.degrade` keeps the server degraded for the whole episode.
- **Baseline poisoning.** Slow checks are left out of the baseline while they are a
  minority, so repeated bursts no longer inflate it and hide milder spikes.
- **Sustained regression vs. burst.** A latency shift now needs most of the new segment
  to sit at the new level: a burst shorter than 8 checks was reported as a shift before.
  Once reported, the new level becomes the baseline (with `since`, when it started).
- **Cold start.** From the 8th check a provisional baseline flags blatant spikes only
  (≥ 2× and 1.5× the sensitivity); the insights API reports `samples` and `provisional`.
- **Zero MAD.** When over half the latencies are identical, the mean absolute deviation
  stands in for the MAD.
- A reproducible scenario corpus (`tests/corpus/anomaly_scenarios.py`) pins all of this.

### Reports and SARIF
- `mcpsonar report` for one server or every server in `--config`, in **Markdown** (for an
  issue or PR comment), **JSON** or **SARIF 2.1.0**. It includes findings with each rule's
  documentation, lockfile drift (`--lock`, read-only) and unreachable servers. Exit 0/1/2
  like `scan`.
- `mcpsonar scan --sarif FILE` and a `sarif` input on the GitHub Action. Upload the file with
  `github/codeql-action/upload-sarif` and findings become **code scanning alerts**, pointing
  at the tool's line in the lockfile.
- What the SARIF carries:
  - every rule, with its help text, `security-severity`, `precision` (the rule's confidence)
    and OWASP MCP Top 10 tags;
  - lockfile drift as the rule `tool-definition-changed`;
  - stable `partialFingerprints` so alerts follow the same issue across runs.
  - Checked against the official SARIF 2.1.0 schema.
- `risks --json` also carries each finding's confidence and OWASP categories (same function
  as the reports).

### Detection quality
- New adversarial corpus (`tests/corpus/detection.yaml`), run in CI: positive and negative
  cases for every lint rule, plus documented known limitations run as strict expected
  failures.
- Every rule is documented in [docs/detection-rules.md](docs/detection-rules.md) with its
  severity, **confidence** (precision), OWASP MCP Top 10 mapping, examples and what to
  review. The registry (`lint.RULES`) is the single source of each rule's severity.
- Tuned against the corpus and against the tools of the 24 watched public servers: 8 false
  positives on 42 live tools became 0, and the corpus has 0 misses and 0 false positives
  (3 documented limitations).
  - `prompt-injection` ignores CLI flags and parameters (`--ignore`, `override=true`).
  - `sensitive-path`: private keys, `.env` files and MCP client configs count only when the
    text asks to read or send them. "Add this server to your mcp.json" is setup, not an
    attack.
  - `exfiltration` needs data (conversation, files, keys, …) heading to the destination, so
    "Send a POST request to https://api…" no longer matches.
  - `coercive-instruction` needs "always / first / also": "You must provide a city name" and
    API ordering notes no longer match.
  - `hidden-unicode` ignores the zero-width joiner inside emoji sequences.
  - `fake-system-tag` also catches `[SYSTEM]` / `[IMPORTANT]`.
  - `encoded-blob` ignores long URLs.
  - `long-description` threshold raised from 1,500 to 4,000 characters (real descriptions
    reach ~3,300).

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
