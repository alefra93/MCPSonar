# MCPSonar engineering audit (v0.5.0 → v0.6.0)

**Date:** 2026-10-20 · **Baseline:** `9098ccb` (v0.5.0 + fixes), branch `feat/mcpsonar-web-app`
**Scope:** `src/mcpsonar/**`, `tests/`, `.github/workflows/`, `Dockerfile`, compose files,
`action.yml`, `pyproject.toml`, `README.md`.

## Method

1. **Baseline:** `pytest -q` gave 106 passed (44 s) and `ruff check src tests` was clean (Python 3.13.1, mcp 1.30.0, httpx 0.28.1, FastAPI 0.139).
2. **Review:** every module was read. Each finding below is backed by a reproduction, a failing test written before the fix, or a cited line of code. The README was not taken as evidence.
3. **Fixes:** each fix is one reviewable commit with its regression tests. Final state: **201 tests pass**, ruff is clean, and `pip-audit` reports no known vulnerabilities.
4. **End-to-end checks:**
   - `scripts/smoke_e2e.sh`: 20/20 against a running instance.
   - The container image was built and run on a root-owned volume.
   - The dashboard was driven in a browser: setup token, edit with masked credentials.
5. **References:**
   - [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (beta)
   - [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
   - The `mcp` 1.30 SDK source in the virtualenv
   - The httpx/httpcore sources

   **Limitation:** the external references were gathered by a research pass with web access. OWASP LLM Top 10 entries were confirmed only from secondary sources, and the MCP 2026-07-28 changes come from its changelog page, not a full read of the spec.

Status labels: **IMPLEMENTED** (code changed) · **TESTED** (automated regression test) ·
**VERIFIED** (manually reproduced end-to-end) · **PARTIALLY IMPLEMENTED** · **PLANNED** ·
**ACCEPTED** (risk documented, no change).

## A. Confirmed vulnerabilities

**SEC-01 · Critical · OWASP MCP05, MCP07 · IMPLEMENTED, TESTED, VERIFIED**
Commit `fix(security): block cross-site writes…`
- **Where:** `api.py` (`/api/import`), `dashboard.py`.
- **Problem:** cross-site drive-by remote code execution.
  - `/api/import` read the raw body whatever the `Content-Type`, so a page on *any* website could send it a "simple" `text/plain` POST (no CORS preflight).
  - With `--no-auth` (used by `mcpsonar demo` and `docker-compose.watch.yml`), the imported stdio server's command is executed.
  - **Reproduced:** `echo owned` ran from a request carrying `Origin: https://evil.example`.
  - With the login on, a page on another port of the same host (same *site*) gets the `SameSite=Lax` cookie and can do the same.
- **Fix:** state-changing requests with a cross-site `Sec-Fetch-Site` or a mismatched `Origin` get 403. With `--no-auth`, stdio servers can't be created or repointed over the API (`--allow-stdio-api` to opt in).
- **Tests:** `test_websec.py::test_cross_site_import_is_blocked`, `::test_stdio_refused_over_unauthenticated_api`, `::test_cross_site_reason[*]`.

**SEC-02 · High · MCP07 · IMPLEMENTED, TESTED**
- **Where:** `dashboard.py`, `cli.py`.
- **Problem:** DNS rebinding against `--no-auth` instances. No `Host` validation existed, so a rebinding domain gets the same-origin access the CSRF check allows.
- **Fix:** `Host` allowlist, defaulting to loopback names with `--no-auth`; configurable with `--allowed-host`.
- **Tests:** `test_websec.py::test_dns_rebinding_host_is_rejected`, `::test_default_allowed_hosts`.

**SEC-03 · High · MCP07 · IMPLEMENTED, TESTED, VERIFIED**
- **Where:** `auth.py`, `storage.py`.
- **Problem:** anyone could claim the first admin account.
  - The Docker default binds `0.0.0.0`, and the first visitor to `/api/auth/setup` became admin.
  - `has_admin()` followed by `create_admin()` is a time-of-check/time-of-use race: concurrent setups could create two admins.
- **Fix:** a one-time setup token (random and logged, or `MCPSONAR_SETUP_TOKEN`), with guesses throttled, plus an atomic `INSERT … WHERE NOT EXISTS`.
- **Tests:**
  - `test_auth.py::test_setup_requires_the_setup_token_when_configured`
  - `test_auth.py::test_concurrent_first_admin_setup_creates_exactly_one_admin`
  - `test_auth.py::test_create_first_admin_is_atomic_at_storage_level`
  - CI Docker job

**SEC-04 · High · MCP01, MCP10 · IMPLEMENTED, TESTED, VERIFIED**
- **Where:** `api.py`, `dashboard.py`, `check_engine.py`, `scheduler.py`, the webhook adapter, `scan.py`.
- **Problem:** credentials were disclosed in several places.
  - `GET /api/servers[/id]`, `/api/export` and `/api/status` returned `Authorization` headers, `env` values and keyed URLs.
  - httpx errors quote the full URL, so `?api_key=` reached the stored check detail, webhook payloads, Uptime Kuma messages and logs.
- **Fix:** `redact.py` masks credentials on every read and export, restores them from storage when a masked value comes back on edit, and scrubs free text.
- **Tests:** `test_redact.py` (18 tests, including a real HTTP 500 carrying `?api_key=`).

**SEC-05 · Medium · MCP07 · IMPLEMENTED, TESTED**
- **Where:** `auth.py`.
- **Problem:** sessions could not be revoked.
  - Logout only deleted the cookie in the browser; a copied cookie stayed valid for 7 days.
  - The `Secure` flag was never set.
- **Fix:** server-side sessions; only a SHA-256 of the token is stored; logout deletes the session; `Secure` set automatically over HTTPS.
- **Tests:**
  - `test_auth.py::test_logout_revokes_the_session_server_side`
  - `test_auth.py::test_session_tokens_are_stored_hashed_and_forged_tokens_rejected`
  - `test_auth.py::test_expired_session_rejected`
  - `test_auth.py::test_cookie_flags_http_vs_https`

**SEC-06 · Medium · MCP07 · IMPLEMENTED, TESTED**
- **Where:** `auth.py`, `storage.py`.
- **Problem:** login brute force and event-loop stalls.
  - Logins were unthrottled.
  - PBKDF2 at 200k iterations ran *on the event loop*, so every attempt froze all checks, which inflates latency and makes a DoS easy.
- **Fix:**
  - Per-client throttle (10 failures per 15 minutes → 429).
  - 600k iterations, computed in a worker thread.
  - Old hashes upgraded at the next login.
  - Constant-time handling of unknown users.
  - Password length capped.
- **Tests:**
  - `test_auth.py::test_login_is_throttled_after_repeated_failures`
  - `test_auth.py::test_legacy_hash_is_upgraded_on_login`
  - `test_auth.py::test_throttle_*`
  - `test_auth.py::test_overlong_password_rejected_without_hashing`

**SEC-07 · Medium · MCP10 · IMPLEMENTED, TESTED, VERIFIED**
Commit `fix(security): outbound connection policy…`
- **Where:** `check_engine.py`, `scheduler.py`, new `netpolicy.py`.
- **Problem:** server-side request forgery (SSRF). There was no outbound policy: a configured URL, or a redirect from an untrusted monitored server, could reach cloud metadata or link-local services.
- **Fix:** the policy is checked at TCP connect time against the resolved address, and the connection goes to that checked address (no rebinding race). Metadata and link-local are blocked by default; private networks stay allowed (monitoring them is a legitimate use).
- **Tests:** `test_netpolicy.py` (31 tests: address classes, IPv4-mapped bypass, rebinding, redirect to metadata, pinning).

**SEC-08 · Medium · MCP01 · IMPLEMENTED, TESTED**
- **Where:** `check_engine.py`.
- **Problem:** credentials were forwarded across origins. httpx strips only `Authorization` on a cross-origin redirect (`httpx/_client.py::_redirect_headers`); `X-API-Key` and other configured headers followed the redirect.
- **Fix:** every configured header is dropped on requests that leave the first origin; redirects are capped at 5.
- **Tests:** `test_netpolicy.py::test_credentials_not_forwarded_across_origins`, `::test_redirect_loop_is_bounded`.

**SEC-09 · Medium · MCP03 · IMPLEMENTED, TESTED**
- **Where:** `dashboard.py`, `auth.py`.
- **Problem:** clickjacking. No framing protection meant the "Approve tool changes" button could be clickjacked, approving a rug pull.
- **Fix:** `X-Frame-Options: DENY`, a CSP with `frame-ancestors 'none'`, `nosniff`, `no-referrer`, and `no-store` on API responses.
- **Test:** `test_websec.py::test_security_headers`.

**SEC-10 · Low · IMPLEMENTED, TESTED**
- **Where:** `api.py`.
- **Problem:** request sizes were unbounded: `/api/import` had no body limit, and `limit=` was unbounded on history and insights.
- **Fix:** 1 MiB body cap, enforced on chunked bodies too; `1 ≤ limit ≤ 5000`.
- **Tests:** `test_websec.py::test_oversized_*`, `::test_history_limit_bounded`.

**SEC-11 · Low · MCP08 · IMPLEMENTED, TESTED**
- **Where:** `dashboard.py`.
- **Problem:** `/metrics` is public and reveals server ids, names and status.
- **Fix:** optional `MCPSONAR_METRICS_TOKEN` (bearer). The default stays public so existing scrapes don't break, and this is documented.
- **Test:** `test_auth.py::test_metrics_token_when_configured`.

**SEC-12 · Low · IMPLEMENTED, VERIFIED**
- **Where:** `Dockerfile`, compose files.
- **Problem:** the container ran as root.
- **Fix:** uid 10001, no capabilities, `no-new-privileges`, HEALTHCHECK. The entrypoint hands an existing root-owned volume to the new user, then drops privileges.
- **Verification:** manual run (`Uid 10001`, `CapEff 0`) and the CI `docker` job.

**SEC-13 · Low · IMPLEMENTED, TESTED**
- **Where:** `models.py`.
- **Problem:** URL fields accepted any string (`file://`, scheme-less).
- **Fix:** `http(s)://host` required for server, webhook and push URLs.
- **Test:** `test_netpolicy.py::test_non_http_urls_rejected`.

**SEC-14 · Low · MCP04 · IMPLEMENTED, VERIFIED**
- **Where:** `pyproject.toml`, CI.
- **Problem:** `pip-audit` reported 11 advisories for pyjwt 2.13, which `mcp` pulls in transitively.
- **Fix:** `pyjwt>=2.15` floor, a `pip-audit` CI job, and Dependabot (which never bumps `mcp` major versions).
- **Verification:** `pip-audit --skip-editable` reports no known vulnerabilities.

## B. Confirmed reliability and protocol defects

**REL-01 · High · MCP03 · IMPLEMENTED, TESTED**
- **Where:** `check_engine.py`, `api.py`, `scan.py`.
- **Problem:** `tools/list` pagination was ignored. Only the first page was read, so pinning, lint and lockfiles never saw tools on page 2+ (a rug pull could hide there).
- **Fix:** `list_all_tools()` follows `nextCursor`. A cursor loop or more than 100 pages is reported as a validation issue, and that listing is not diffed.
- **Tests:** `test_protocol_edges.py::test_all_pages_are_listed`, `::test_cursor_loop_is_reported_and_not_diffed`.

**REL-02 · High · IMPLEMENTED, TESTED**
- **Where:** `check_engine.py`.
- **Problem:** checks could hang forever. `ClientSession` had no read timeout, so a stdio server that never answers blocked its check loop and `POST /check` forever. SSE reads could wait up to the SDK's 300 s default.
- **Fix:** a session read timeout plus an overall check budget; a hung check ends as `down`.
- **Test:** `test_protocol_edges.py::test_hung_stdio_server_ends_as_down`.

**REL-03 · Medium · IMPLEMENTED, TESTED**
- **Where:** `scheduler.py`.
- **Problem:** checks of the same server could overlap: "Check now", the post-approval re-check and the loop diffed the same snapshot concurrently, recording duplicate changes.
- **Fix:** a per-server lock.
- **Test:** `test_scheduler.py::test_checks_of_one_server_never_overlap`.

**REL-04 · Medium · IMPLEMENTED, VERIFIED**
- **Where:** `dashboard.py` (JS).
- **Problem:** editing a server in the dashboard silently dropped every probe's `arguments`.
- **Fix:** kept probes retain their options.
- **Verification:** browser edit, then the stored config was inspected.

**REL-05 · Medium · MCP02, MCP05 · IMPLEMENTED, TESTED**
- **Where:** `check_engine.py`, `models.py`.
- **Problem:** unsafe probing: a probe called a tool the server no longer lists, and called tools annotated destructive.
- **Fix:**
  - Unlisted tools fail without being called.
  - Destructive-annotated tools are skipped unless `allow_destructive` is set (documented as a hint, not a guarantee).
  - Per-probe `timeout_seconds`.
  - Probe errors no longer swallow cancellation.
- **Tests:** `test_protocol_edges.py::test_destructive_tool_is_not_probed`, `::test_destructive_tool_probed_only_when_explicitly_allowed`.

**REL-06 · Low · MCP03 · IMPLEMENTED, TESTED**
- **Where:** `validators/base.py`.
- **Problem:** duplicate tool names collapsed silently (shadowing).
- **Fix:** reported as a validation issue.
- **Test:** `test_protocol_edges.py::test_duplicate_tool_names_flagged`.

**REL-07 · Low · IMPLEMENTED, TESTED**
- **Where:** `tooldefs.py`.
- **Problem:** fingerprints changed when only the order of the schema's `required` list changed, causing false rug-pull alerts.
- **Fix:** `required` is canonicalized (it is a set); everything else still counts.
- **Tests:** `test_protocol_edges.py::test_required_order_*`, `::test_meaningful_changes_still_detected`.

**REL-08 · Low · IMPLEMENTED, TESTED**
- **Where:** `tests/test_check_engine.py`.
- **Problem:** the mock server's output went to an unread `PIPE`. Once it filled, the server blocked and three tests failed depending on order.
- **Fix:** output goes to `DEVNULL`. The file now runs in 8 s instead of about 65 s.

## C. Theoretical threats, accepted risks and limitations

**T-01 · High (future compatibility) · IMPLEMENTED, TESTED, VERIFIED in v0.7.0**
MCP spec **2026-07-28** removes the `initialize` handshake and `ping`, adds a mandatory
`server/discover`, and deprecates HTTP+SSE (per its changelog). `mcp` 2.x (2.0 released
2026-07-28; 2.3.0 is current) implements it; MCPSonar pins `mcp<2`. Servers that speak only
the new revision will appear *down*. A spike on SDK 2.x is the top v0.7/v1.0 protocol item
(see the roadmap). Not attempted here: it is a major migration that needs its own evidence.
Resolved by moving to mcp 2.x: one client negotiates both eras. 24/24 live servers were
classified identically, with 42/42 tool fingerprints unchanged, and 5 of them already speak
2026-07-28. See ADR 0001, "Implementation notes".

**T-02 · Medium · ACCEPTED (documented)**
stdio servers are code execution by design. Mitigations: no shell, minimal environment,
refused over an unauthenticated API, and the container runs unprivileged. Real sandboxing
(seccomp, a separate container per server) is PLANNED as guidance.

**T-03 · Medium · PLANNED**
Credentials are stored in clear in SQLite (needed to monitor). Plan: a secret-reference
syntax (`${env:NAME}` / `${file:/run/secrets/x}`) resolved at check time.

**T-04 · Low · ACCEPTED (documented)**
With `HTTP(S)_PROXY` set, connections go to the proxy, so IP-level policy is the proxy's job.

**T-05 · Low · ACCEPTED (guarded)**
The policy hooks httpcore through a private attribute (`_pool._network_backend`).
`test_transport_hook_is_installed` fails loudly if an upgrade breaks it.

**T-06 · Low · ACCEPTED**
The login throttle lives in memory: it is per process and resets on restart. That is
enough for one instance.

**T-07 · Low · ACCEPTED**
The Uptime Kuma push API takes its token in the URL (Kuma's design). It is masked in every
MCPSonar output.

**T-08 · Medium · PLANNED (v0.8)**
Lint heuristics have known false positives and negatives. There is no adversarial corpus
yet, no per-rule documentation, and no SARIF output.

**T-09 · Medium · PLANNED (v0.7)**
Anomaly detection:
- the baseline can be poisoned by a slow drift;
- there is no explicit recovery event;
- alerts are deduplicated only through `anomaly_reported_since`;
- the zero-MAD case relies on a 5 % floor.

**T-10 · Low · PLANNED**
Probe responses are read whole; there is no output-size limit.

**T-11 · Low · PLANNED**
SQLite uses one shared connection, no WAL, and ad-hoc `ALTER TABLE` migrations with no
schema version.

**T-12 · Low · PLANNED**
There is no password-change or session-list UI. Single admin only: no roles and no audit
log.

## D. Optional improvements (not defects)

Each is scheduled in [product-roadmap.md](product-roadmap.md):
- Type checking (`mypy --strict` on `netpolicy`, `redact`, `auth` first).
- An integration test that runs the GitHub Action itself.
- Structured JSON logs.
- Per-tool latency metrics.
- Response drift detection.
- Slack, Discord and email adapters.
- A dashboard incident timeline.
- A "Trust Report" export.

## Backwards-compatibility impact

| Change | Who notices | Mitigation |
|---|---|---|
| Sessions moved server-side | everyone signs in once more | passwords keep working |
| First-admin setup needs a token | new installs | link printed in the log; `MCPSONAR_SETUP_TOKEN` |
| API no longer returns credentials | scripts reading tokens back from the API | the masked value round-trips; keep secrets in your own store |
| Export is masked by default | backup scripts using `/api/export` | `?include_secrets=true`, or back up the SQLite file |
| `--no-auth`: loopback `Host` only, no stdio over API | LAN dashboards without a login | `--allowed-host`, `--allow-stdio-api` |
| Cross-origin POSTs refused | reverse proxies that rewrite `Host` | forward `Host` or set `--trusted-origin` |
| Metadata and link-local targets blocked | someone monitoring a link-local MCP server | `MCPSONAR_ALLOW_LINK_LOCAL=1` / `MCPSONAR_OUTBOUND_ALLOW` |
| Probes skip destructive-annotated or unlisted tools | configs probing such tools | `allow_destructive: true` |
| Container user is uid 10001 | custom images and bind mounts | the entrypoint fixes the volume; set `--user` if you need another uid |
| `required` order ignored in fingerprints | lockfile `sha256` values may change once | lockfile comparison uses the definitions, so no drift is reported |
