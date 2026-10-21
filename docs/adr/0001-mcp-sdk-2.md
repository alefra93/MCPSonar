# ADR 0001 · MCP SDK 2.x and spec revision 2026-07-28

**Status:** Accepted, implemented in v0.7.0 · **Date:** 2026-10-20 · **Audit item:** T-01 ([engineering-audit.md](../engineering-audit.md))
**Spike baseline:** `06ba043` (`feat/mcpsonar-web-app`), mcp 1.30.0 vs mcp 2.3.0 (`mcp-types` 2.3.0,
`httpx2`/`httpcore2` 2.15.1), CPython 3.13, Windows 11. Time-boxed spike: no MCPSonar code was changed.

## Context

MCPSonar speaks MCP only through the official `mcp` SDK, pinned `mcp>=1.28,<2`. Each check opens a
session, runs `initialize`, lists every `tools/list` page, optionally calls probe tools, validates per
spec version and pins tool definitions (rug-pull detection).

Spec revision **2026-07-28** ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)):

- removes the `initialize`/`notifications/initialized` handshake. Every request carries its protocol
  version and client capabilities in `_meta` (SEP-2575);
- adds `server/discover`, which servers MUST implement; clients MAY call it first (SEP-2575);
- removes `ping`, `logging/setLevel` and the `Mcp-Session-Id` header (SEP-2567, SEP-2575);
- requires `Mcp-Method` / `Mcp-Name` headers on Streamable HTTP POSTs (SEP-2243);
- requires `ttlMs` + `cacheScope` on list results (SEP-2549) and `resultType` on every result (SEP-2322);
- moves HTTP+SSE to *Deprecated* (SEP-2596). It stays in the spec for at least the 12-month window.

`mcp` 2.x implements this revision. Its [v1→v2 migration guide](https://py.sdk.modelcontextprotocol.io/migration/)
lists the breaking changes that affect MCPSonar: `httpx`/`httpx-sse` replaced by `httpx2`;
snake_case attributes (`input_schema`, `next_cursor`, `is_error`, `protocol_version`, `server_info`);
`FastMCP` → `MCPServer`; float-second timeouts instead of `timedelta`; `streamable_http_client` yielding
a 2-tuple, and `httpx_client_factory` removed from it; non-2xx HTTP answers raised as `MCPError`
instead of `httpx.HTTPStatusError`. The 1.x line still gets security fixes.

## Evidence (spike)

All servers are local. 1.x servers ran in a 1.x venv, 2.x servers in a 2.x venv. No third-party
endpoint or package was used. "2026-only" is a raw JSON-RPC stdio server written for the spike: it
answers `server/discover`, accepts only `_meta`-enveloped requests, and answers `initialize` with
either `-32601` or `-32022`. The scripts and raw results are kept outside the repo, in the session
notes (`mcp-sdk-2-spike/`).

### Compatibility matrix

| Server (transport) | 1.x `ClientSession.initialize()` (today) | 2.x `ClientSession` + `negotiate_auto` | 2.x `Client(mode="auto")` |
|---|---|---|---|
| `scripts/mock_mcp_server.py`, 1.x FastMCP (stdio) | ✅ 2025-11-25 | ✅ fallback to initialize, 2025-11-25 | ✅ |
| same (Streamable HTTP) | ✅ | ✅ fallback | ✅ |
| same (legacy SSE) | ✅ | ✅ (`sse_client`, `initialize`) | n/a (no SSE target) |
| `tests/fixtures/scripted_server.py pages`, 1.x lowlevel (stdio, 12 tools / 3 pages) | ✅ 12 tools | ✅ 12 tools | ⚠ 5 tools: `Client.list_tools()` returns one page |
| minimal 2.x `MCPServer` (stdio) | ✅ the 2.x server is dual-era | ✅ **discover**, 2026-07-28 | ✅ discover |
| minimal 2.x `MCPServer` (Streamable HTTP) | ✅ dual-era | ✅ discover | ✅ discover |
| 2026-only, `initialize` → `-32601` (stdio) | ❌ `McpError: Method not found` → **down** | ✅ discover | ✅ discover |
| 2026-only, `initialize` → `-32022` (stdio) | ❌ `McpError: Unsupported protocol version` → **down** | ✅ discover | ✅ discover |
| HTTP stub, 401 + `WWW-Authenticate` | `httpx.HTTPStatusError` with status + headers ✅ | ❌ `MCPError(-32603, "Server returned an error response")`: status and headers lost | same |
| HTTP stub, 429 + `Retry-After` | `HTTPStatusError` ✅ | ❌ `MCPError(-32603)` | same |

**One 2.x client talks to both eras.** `mcp.client._probe.negotiate_auto(session)` (the logic behind
`Client(mode="auto")`) sends `server/discover`, falls back to `initialize` on any JSON-RPC error except a
disjoint `-32022`, and leaves either `session.discover_result` or `session.initialize_result` set.
Afterwards `session.protocol_version`, `server_info` and `server_capabilities` work in both eras.

**Today, MCPSonar reports 2026-only servers as down.** This confirms T-01. Servers built on SDK 2.x
still answer `initialize`, so most of the ecosystem keeps working until servers drop the handshake.

### Other observations

- **Fingerprints.** `normalize_tool` (`model_dump(mode="json", by_alias=True)`) emits the same
  camelCase keys under both SDKs. Every tool in the matrix fingerprinted identically under 1.x and 2.x,
  in both eras. Offline parity over 8 wire shapes (plain, annotations, extra top-level key,
  `outputSchema`+`title`, JSON Schema 2020-12 `$defs`/`$ref`, `_meta`/`icons`/`execution`, null
  description) gave the same SHA-256 in 7 of 8 cases. **The exception: unknown keys inside
  `annotations`.** 1.x keeps them; 2.x drops them silently (`{"readOnlyHint": true, "vendorHint": "x"}`
  gives `93d22f…` under 1.x and `de78f3…` under 2.x).
- **List metadata is synthesized.** Against a 2025-era server, the 2.x `ListToolsResult` reports
  `ttl_ms=0` and `cache_scope="private"`. A missing `ttlMs` therefore cannot be detected from the typed
  result.
- **`httpcore2` keeps the hook netpolicy relies on.** `httpx2.AsyncHTTPTransport()._pool` is a
  `httpcore2.AsyncConnectionPool` with `._network_backend`. `httpcore2.AsyncNetworkBackend`,
  `httpcore2.ConnectError` and `httpx2.create_ssl_context` exist. TLS uses the OS trust store
  (`truststore`) instead of certifi.
- **A hung server costs two timeouts.** With `mode="auto"`, `server/discover` times out, then the
  fallback `initialize` times out too (`MCPError -32001 "Request 'initialize' timed out"`). A refused
  connection still escapes as `ExceptionGroup[httpx2.ConnectError]`.
- **Legacy servers answer two RPCs per handshake.** They answer the `server/discover` probe with an
  error, then `initialize`. Latency measured over the "handshake" therefore roughly doubles for
  2025-era servers.
- **A tool error is still a result.** `boom` gives `is_error=True`. An unknown tool name on a 2.x
  server also returns a result instead of raising.
- **Annotations are snake_case.** `annotations.destructive_hint` / `read_only_hint` work as expected.
- **The 1.x fixtures do not import under 2.x.** `scripted_server.py` fails with
  `'Server' object has no attribute 'list_tools'` (the decorator API is gone). `mock_mcp_server.py` and
  `demo.py` fail with `No module named 'mcp.server.fastmcp'`.
- **Option (a) works, but with private hacks.** A 1.x `ClientSession` can skip `initialize` and send
  `server/discover` and `_meta`-enveloped `tools/list`/`tools/call`. This needs a
  `ClientRequest.model_construct` hack, which floods pydantic serialization warnings. Over Streamable
  HTTP, a 2.x server answers **400** unless an httpx request hook adds `Mcp-Method`, `Mcp-Name` and
  `MCP-Protocol-Version`. With the hook it works: discover, 3 tools, `ping` → `pong`.

## Touchpoints and effort (for option c)

| Touchpoint | Change | Effort |
|---|---|---|
| `check_engine._http_client` | `httpx2.AsyncClient`/`Timeout`. Same event-hook API. Add a **response** hook that records the last non-2xx status + `WWW-Authenticate`/`Retry-After`, because 2.x no longer raises `HTTPStatusError` | S + M (½ d) |
| `check_engine._open_session` | Streamable HTTP yields `(read, write)`. `sse_client(httpx_client_factory=…)` must return an httpx2 client. `ClientSession(read_timeout_seconds=float)`. Then run `negotiate_auto`, wrapped in our own module so the private `_probe` import sits in one place | S–M (½ d) |
| `check_engine._run_check` | `session.initialize()` → negotiation. Build one neutral `ServerHandshake(protocol_version, server_info, capabilities, era)` from `initialize_result` or `discover_result`. Time the successful handshake RPC only, not the probe. Raise `check_budget_s` by one request timeout, or cap the probe timeout | M (½–1 d) |
| `_find_http_error` / `_auth_outcome` / 429 path | Re-base on the recorded response status (above) instead of `httpx.HTTPStatusError`. Keep the `auth_required` and `Retry-After` semantics | M (½ d) |
| `list_all_tools` | `page.nextCursor` → `page.next_cursor`. Keep using `ClientSession.list_tools(params=…)`: `Client.list_tools()` returns one page and caches | S |
| `_probe_tools` / `_is_destructive` | `timedelta` → float. `isError` → `is_error`. `destructiveHint`/`readOnlyHint` → snake_case. JSON-RPC errors are now `MCPError`, already caught | S |
| `raise_if_cancelling` / cancellation | 2.x sends `notifications/cancelled` and changes task-group behaviour. Re-run and adapt `test_cancellation` | S–M |
| validators (`base` + 4 versions) | Take the neutral handshake instead of `InitializeResult`. Snake_case `tool.input_schema`. Add a `v2026_07_28` validator; checking `ttlMs`/`cacheScope` presence needs the raw result, or drop that rule | M (1 d) |
| `tooldefs.normalize_tool` | No change for casing (`by_alias=True`). **Decide** about annotation extras (see Stability) | S code, M tests |
| `netpolicy.policy_transport` / `PolicyNetworkBackend` | `httpcore`→`httpcore2`, `httpx`→`httpx2`. Same private attribute (verified), keep the guard test. Also move the webhook adapters/scheduler client to httpx2, so one policy implementation covers every outbound connection | S (2 h) + S |
| `scan.py` | Follows the engine: handshake object instead of `init.protocolVersion`. `LOCK_VERSION` stays 1 | S |
| `demo.py`, `scripts/mock_mcp_server.py` | `FastMCP` → `MCPServer`. Check the host/port/run arguments | S |
| `tests/fixtures/scripted_server.py` | Port to the 2.x lowlevel API. **Add** two raw JSON-RPC fixtures: legacy-only and 2026-only. A 2.x server is dual-era, so it cannot test the fallback | M (½ d) |
| tests | `test_auth_required` (401/403/429), `test_netpolicy` (`_pool` guard, `httpx` usage), `test_adapters` (`httpx.MockTransport` → `httpx2`), `test_check_engine`, `test_protocol_edges`, `test_cancellation`, `test_redact` (error-text format), `test_tooldefs_lint` | M–L (1–1½ d) |
| `pyproject.toml` / Docker | `mcp>=2.3,<3`, `httpx2>=2.5`, `anyio>=4.9`, `pydantic>=2.12`. Drop `httpx` once the adapters move. Docker smoke test must prove TLS works with the OS store in `python:3.13-slim` | S |

**Total for (c): about 5–7 focused days**, mostly tests and the 401/429 re-basing.

## Options

### (a) Stay on 1.x and add a minimal `server/discover` path

When `initialize` fails with `-32601`/`-32022`, retry over the same transport with a hand-built
`server/discover` and `_meta`-enveloped `tools/list`/`tools/call`. The spike proves this works on stdio
and on Streamable HTTP with a header hook.

- ✅ ~2 days. No dependency churn. v0.6 ships unchanged.
- ❌ It relies on `ClientRequest.model_construct` and unvalidated custom models. It floods warnings. It
  re-implements the version negotiation, the `Mcp-Method`/`Mcp-Name` headers and the envelope that the
  SDK already maintains. It is blind to MRTR/`resultType` and to later revisions. The 1.x line only gets
  security fixes, so every future spec change lands on us.

### (b) Dual-stack

Ship both SDKs, through an optional extra or a vendored copy, and pick per server.

- ✅ Maximum isolation per era.
- ❌ `mcp` 1.x and 2.x are the same distribution name and cannot be installed side by side without
  vendoring. Two `httpx` stacks would need the outbound policy implemented twice (SSRF). Every
  touchpoint above would be written twice and tested twice. **The spike shows it is unnecessary:** the
  2.x client already covers both eras.

### (c) Move to 2.x — **recommended**

One client, `ClientSession` + `negotiate_auto`, covers 2025-era servers (initialize fallback, including
SSE) and 2026-07-28 servers (discover), on stdio and Streamable HTTP. The table above lists the work.

- ✅ Fixes T-01 at the root. Stays on the maintained SDK line. One HTTP stack and one outbound policy.
- ❌ ~1 week of work. Two regressions must be handled deliberately: 401/429 classification, and the
  handshake latency for legacy servers. It depends on one private SDK function (`_probe.negotiate_auto`),
  which we isolate and test. If it moves, the fallback is ~30 lines of our own.

## Decision

Adopt **(c)**, as the first protocol item after v0.6 lands on `main`, on its own branch. Do not bump
`mcp` on `feat/mcpsonar-web-app`. Do not ship (a) unless (c) slips past the point where 2026-only
servers show up in real deployments. (a) stays a documented fallback with a ~2-day cost.

## Implementation notes (2026-10-20)

How the decision was carried out (v0.7.0):

- **Own negotiation, no private SDK import.** `check_engine.negotiate()` mirrors
  `negotiate_auto` (about 40 lines) using only public `ClientSession` methods: `send_discover`,
  `initialize` and `adopt`.
- **Which RPC is timed.** Over HTTP/SSE, only the RPC that succeeded counts. Over stdio, the time
  runs from the first request: process startup has always been part of a stdio server's
  latency, so baselines stay continuous.
- **One neutral handshake object.** It covers both eras: `Handshake` holds `protocol_version`,
  `server_info`, `capabilities`, `era` and `latency_ms`. Validators take any object of that
  shape (`ServerHandshake` protocol). A `2026-07-28` validator is added.
- **401/403/429 semantics kept.** `HttpLog`, a response hook on our httpx2 client, records the
  status and headers that mcp 2.x no longer surfaces. The last HTTP error status is appended to
  "down" details (e.g. `(HTTP 503)`).
- **Stored definitions are re-normalized before diffing.** `tooldefs.renormalize()` applies to
  baselines and lockfiles. When only the stored form changed, the baseline is re-pinned quietly.
- **New test fixtures.** `tests/fixtures/era_server.py` is a raw JSON-RPC server that speaks only
  one era (legacy or 2026-only). `scripted_server.py`, `mock_mcp_server.py` and the demo were
  ported to the 2.x server APIs.

**Evidence:**
- 284 tests pass under mcp 2.3.0, including `tests/test_mcp2_migration.py`.
- Tool fingerprints for 7 definition shapes match the values mcp 1.30 produced (golden values
  in the test).
- Against the 24 public servers in `examples/popular-servers.yaml`, the 2.x client and the v0.6
  (1.x) client agree on status, `auth_required` and tool count for **24/24** servers, and on the
  fingerprint of **42/42** tools.
- **5 of those servers already negotiate 2026-07-28** (Cloudflare Docs, Context7, Hugging Face,
  Kiwi.com, Svelte).

## What must stay stable

1. **Tool fingerprints.** Existing baselines and `mcpsonar.lock` files must not all show as changed.
   - Keep `normalize_tool` on `model_dump(mode="json", by_alias=True)` with the camelCase
     `PINNED_FIELDS`. The spike shows that this alone keeps fingerprints identical across SDKs and
     eras.
   - Annotation extras, the only divergence: on the **first check after the upgrade**, re-normalize the
     stored snapshot through the same model (`Tool.model_validate(stored)`) before diffing. A tool that
     differs only by dropped unknown annotation keys is then re-pinned silently, not reported as a rug
     pull. Write a test that pins the 8-shape parity set.
   - `LOCK_VERSION` stays 1. `scan --lock` re-normalizes the lock's definitions the same way.
   - Trade-off to record: under 2.x, hidden text in unknown annotation keys is no longer visible to the
     lint. Python clients built on SDK 2.x drop those keys as well. Capturing raw `tools/list`
     JSON would restore that visibility, but it is out of scope for this decision.
2. **Check semantics.** `auth_required` on 401/403 without credentials, `down` on rejected
   credentials, and `degraded` + `Retry-After` on 429 must survive the move to `MCPError`.
3. **Latency continuity.** Measure the handshake RPC that succeeded, not probe + fallback. Otherwise
   every 2025-era server shows a latency step and false anomalies right after the upgrade. Optionally,
   remember each server's era and probe again only occasionally.
4. **`spec_version`.** It stays the negotiated protocol version string. `2026-07-28` gets its own
   validator. Unknown versions stay informational only.
5. **Transports.** stdio, Streamable HTTP and legacy SSE keep working. SSE stays supported while the
   spec's deprecation window lasts.
6. **Security properties.** The outbound policy on every connection (redirects included), configured
   credentials kept on their origin, the minimal stdio environment (2.x `get_default_environment` is
   still an allowlist), and secret scrubbing of error text.
