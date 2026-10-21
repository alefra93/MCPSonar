"""Core check engine: health-check a single MCP server and produce a :class:`CheckEvent`.

The engine is the only place that speaks MCP. It connects via the official SDK (mcp 2.x),
negotiates the protocol era, lists tools, optionally test-calls configured tools, applies the
version-aware validators, and classifies the result. It **never raises**: any connection or
protocol failure becomes a ``down`` event, so the scheduler can treat every server uniformly.

Two protocol eras are spoken by one client (see ``docs/adr/0001-mcp-sdk-2.md``):

* **modern** (2026-07-28 and later): no handshake; ``server/discover`` tells the client the
  server's versions and capabilities;
* **handshake** (2024-11-05 … 2025-11-25): the ``initialize`` handshake.

:func:`negotiate` probes ``server/discover`` and falls back to ``initialize`` — and reports
the latency of the RPC that *succeeded*, so legacy servers do not show a latency step caused
by the failed probe.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import ssl
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Literal

import httpx2
import mcp_types as types
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import PaginatedRequestParams, Tool
from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_MODERN_VERSION,
    MODERN_PROTOCOL_VERSIONS,
)
from pydantic import ValidationError

from .models import CheckEvent, CheckStatus, ServerConfig, Thresholds, ToolProbe, TransportType
from .netpolicy import policy_transport
from .redact import scrub, secret_values
from .tooldefs import normalize_tool
from .validators import get_validator, run_minimal_common_validation


@functools.cache
def _ssl_context() -> ssl.SSLContext:
    """One TLS context for every check. Building one loads the CA bundle (~200 ms of blocking
    CPU); doing that per check stalls the event loop and inflates the latency measured for
    every *other* server being checked at the same time."""
    return httpx2.create_ssl_context()


MAX_REDIRECTS = 5


def _origin(url: httpx2.URL) -> tuple[str, str, int | None]:
    return url.scheme, url.host, url.port


_REJECTIONS = (401, 403, 429)


@dataclass
class HttpLog:
    """What the server said at the HTTP layer. mcp 2.x turns a 401/403/429 into a generic
    ``MCPError(-32603)`` — status and headers are lost — so the engine records them here to
    keep classifying them: protected (``auth_required``), credentials rejected, rate limited.
    """

    status: int | None = None  # last 401/403/429
    headers: dict[str, str] = field(default_factory=dict)
    last_error: int | None = None  # last HTTP error status of any kind (for the detail)

    async def on_response(self, response: httpx2.Response) -> None:
        if response.status_code >= 400:
            self.last_error = response.status_code
        if response.status_code in _REJECTIONS:
            self.status = response.status_code
            self.headers = {k.lower(): v for k, v in response.headers.items()}
        elif response.is_success and response.request.method == "POST":
            # a later success supersedes earlier failures
            self.status, self.headers, self.last_error = None, {}, None

    def describe(self) -> str:
        """`` (HTTP 503)``-style suffix for an error detail, or ''."""
        return f" (HTTP {self.last_error})" if self.last_error else ""


def _http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx2.Timeout | None = None,
    auth: httpx2.Auth | None = None,
    *,
    log: HttpLog | None = None,
) -> httpx2.AsyncClient:
    """Same defaults as the SDK's ``create_mcp_http_client``, plus:

    * the shared TLS context;
    * the outbound connection policy (:mod:`mcpsonar.netpolicy`) on every connection,
      redirects included (the SDK itself follows MCP redirects only within the origin);
    * credentials stay on the origin they were configured for: every *configured* header
      (``Authorization``, ``X-API-Key``, ...) is removed from a request that left the first
      request's origin;
    * ``log`` records 401/403/429 answers (see :class:`HttpLog`).
    """
    secret_names = list(headers or {})
    first_origin: list[tuple[str, str, int | None]] = []

    async def _keep_credentials_on_origin(request: httpx2.Request) -> None:
        if not first_origin:
            first_origin.append(_origin(request.url))
        elif _origin(request.url) != first_origin[0]:
            for name in secret_names:
                request.headers.pop(name, None)

    hooks: dict[str, list[Any]] = {"request": [_keep_credentials_on_origin]}
    if log is not None:
        hooks["response"] = [log.on_response]
    return httpx2.AsyncClient(
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        headers=headers,
        timeout=timeout if timeout is not None else httpx2.Timeout(30.0, read=300.0),
        auth=auth,
        transport=policy_transport(verify=_ssl_context()),
        event_hooks=hooks,
    )


@contextlib.asynccontextmanager
async def _open_session(
    cfg: ServerConfig, timeout_s: float, log: HttpLog | None = None
) -> AsyncIterator[ClientSession]:
    """Open an MCP ClientSession (not yet negotiated: call :func:`negotiate`).

    * http  — Streamable HTTP, with optional auth ``headers``.
    * sse   — legacy HTTP+SSE (deprecated by 2026-07-28, still supported), same headers.
    * stdio — mcpsonar launches ``command``/``args`` and speaks over the process's stdio.

    The timeout bounds every request, so a hung server surfaces as ``down`` rather than
    blocking forever. HTTP rejections are recorded into ``log`` when given.
    """
    headers = cfg.headers or None
    if cfg.transport == TransportType.SSE:
        factory = functools.partial(_http_client, log=log)
        async with sse_client(
            cfg.url, headers=headers, timeout=timeout_s, httpx_client_factory=factory
        ) as (read, write), ClientSession(read, write, timeout_s) as session:
            yield session
    elif cfg.transport == TransportType.STDIO:
        # No shell: the command is exec'd directly with its argv. The SDK passes only a
        # small allowlist of the parent environment (HOME, PATH, ...) plus ``env``, so
        # mcpsonar's own secrets do not leak into the child process.
        params = StdioServerParameters(
            command=cfg.command, args=cfg.args, env=(cfg.env or None)
        )
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write, timeout_s) as session,
        ):
            yield session
    else:  # TransportType.HTTP -> Streamable HTTP
        timeout = httpx2.Timeout(timeout_s)
        async with (
            _http_client(headers=headers, timeout=timeout, log=log) as http_client,
            streamable_http_client(cfg.url, http_client=http_client) as (read, write),
            ClientSession(read, write, timeout_s) as session,
        ):
            yield session


# ---- protocol negotiation ---------------------------------------------------- #
#: The SDK's fixed timeout for the ``server/discover`` probe (a legacy server that ignores
#: unknown methods costs this much once per check before the ``initialize`` fallback).
DISCOVER_PROBE_TIMEOUT_S = 10.0
_UNSUPPORTED_PROTOCOL_VERSION = -32022


@dataclass(frozen=True)
class Handshake:
    """What a server told us about itself, whichever era it speaks. Validators and the
    scanner use this instead of the handshake-only ``InitializeResult``."""

    protocol_version: str | None
    server_info: types.Implementation | None
    capabilities: types.ServerCapabilities | None
    era: Literal["modern", "handshake"]
    latency_ms: float  # of the RPC that succeeded (discover *or* initialize), not both


def _supported_versions(data: Any) -> list[str] | None:
    try:
        return types.UnsupportedProtocolVersionErrorData.model_validate(data).supported
    except ValidationError:
        return None


def _handshake(session: ClientSession, era: Literal["modern", "handshake"], ms: float) -> Handshake:
    return Handshake(session.protocol_version, session.server_info,
                     session.server_capabilities, era, ms)


async def _initialize(session: ClientSession, since: float | None) -> Handshake:
    start = perf_counter()
    await session.initialize()
    return _handshake(session, "handshake", (perf_counter() - (since or start)) * 1000.0)


async def negotiate(
    session: ClientSession, include_startup: bool = False, log: HttpLog | None = None
) -> Handshake:
    """Pick the protocol era the way the SDK's ``mode="auto"`` does.

    Latency: by default only the RPC that succeeded is timed, so a handshake-era HTTP
    server does not look twice as slow because of the failed ``server/discover`` probe.
    With ``include_startup`` (stdio) the time runs from the first request: there the first
    request also waits for the process to start, and that has always been part of a stdio
    server's measured latency — keeping it keeps baselines continuous across the upgrade.

    ``server/discover`` is probed at the newest modern version (once more at a mutual
    version if the server answers -32022 naming one). Any other JSON-RPC error — or a
    discover result that is unparseable or offers no modern version — means a handshake-era
    server: fall back to ``initialize``. A server that is modern-only *and* shares no
    version with us raises. Transport errors propagate (an outage is not an era verdict).

    An HTTP 401/403/429 on the probe (recorded in ``log``) is not an era signal either: the
    endpoint refuses *every* request, so the error is raised at once instead of paying a
    second round trip for an ``initialize`` that would be refused the same way.
    """
    since = perf_counter() if include_startup else None
    version = LATEST_MODERN_VERSION
    for attempt in range(2):
        start = since or perf_counter()
        try:
            raw = await session.send_discover(version)
        except MCPError as exc:
            if log is not None and log.status in _REJECTIONS:
                raise  # protected / throttled endpoint: the answer won't change
            if exc.code == _UNSUPPORTED_PROTOCOL_VERSION:
                supported = _supported_versions(exc.error.data)
                mutual = [v for v in MODERN_PROTOCOL_VERSIONS if v in (supported or ())]
                if mutual and attempt == 0:
                    version = mutual[-1]
                    continue
                if supported is not None and not any(
                    v in HANDSHAKE_PROTOCOL_VERSIONS for v in supported
                ):
                    raise  # modern-only, and no version in common: a real incompatibility
            return await _initialize(session, since)
        latency_ms = (perf_counter() - start) * 1000.0
        try:
            result = types.DiscoverResult.model_validate(raw)
        except ValidationError:
            return await _initialize(session, since)
        if not any(v in result.supported_versions for v in MODERN_PROTOCOL_VERSIONS):
            return await _initialize(session, since)  # answers discover, advertises only legacy
        session.adopt(result)
        return _handshake(session, "modern", latency_ms)
    raise AssertionError("unreachable")  # pragma: no cover


MAX_TOOL_PAGES = 100


class PaginationError(Exception):
    """``tools/list`` pagination that never ends (cursor loop or absurd page count)."""


async def list_all_tools(session: ClientSession, max_pages: int = MAX_TOOL_PAGES) -> list[Tool]:
    """Every tool the server exposes, following ``next_cursor`` across pages.

    Inspecting only the first page would let a tool on page 2 change (or be poisoned)
    unseen. A repeated cursor or more than ``max_pages`` pages raises
    :class:`PaginationError` rather than looping forever or returning a partial list.
    """
    tools: list[Tool] = []
    cursor: str | None = None
    seen: set[str] = set()
    for _ in range(max_pages):
        params = PaginatedRequestParams(cursor=cursor) if cursor is not None else None
        page = await session.list_tools(params=params)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools
        if cursor in seen:
            raise PaginationError(f"tools/list returned cursor {cursor[:40]!r} twice")
        seen.add(cursor)
    raise PaginationError(f"tools/list did not end after {max_pages} pages")


def _is_destructive(tool: Tool) -> bool:
    ann = tool.annotations
    return bool(ann and ann.destructive_hint is True and ann.read_only_hint is not True)


async def _probe_tools(
    session: ClientSession, probes: list[ToolProbe], timeout_s: float, tools: list[Tool]
) -> tuple[int, int, list[str], list[str]]:
    """Test-call each configured tool with its configured arguments to prove it responds.
    Returns (tools_checked, tools_failed, failure_notes, skipped_notes).

    Only tools listed in ``tools_to_test`` are ever called, one at a time: never a tool
    just because it exists or its name looks harmless. A tool counts as failed if the call
    raises or returns ``is_error``, or if the server no longer lists it (it is then not
    called at all). A tool whose annotations declare it destructive is skipped unless its
    probe sets ``allow_destructive``. Annotations are hints from the server, not
    guarantees: a malicious server can mislabel a destructive tool, so only probe tools you
    know to be safe to call repeatedly. Configure representative ``arguments`` so an error
    is a real malfunction signal rather than a "you called it wrong" artifact.
    """
    by_name = {t.name: t for t in tools}
    checked = 0
    failed = 0
    notes: list[str] = []
    skipped: list[str] = []
    for probe in probes:
        tool = by_name.get(probe.name)
        if tool is not None and _is_destructive(tool) and not probe.allow_destructive:
            skipped.append(f"{probe.name} (annotated destructive; set allow_destructive "
                           "to probe it anyway)")
            continue
        checked += 1
        if tool is None:
            failed += 1
            notes.append(f"{probe.name}: not listed by the server (not called)")
            continue
        try:
            result = await session.call_tool(
                probe.name,
                arguments=probe.arguments,
                read_timeout_seconds=probe.timeout_seconds or timeout_s,
            )
            if getattr(result, "is_error", False):
                failed += 1
                notes.append(f"{probe.name}: tool returned an error result")
        except Exception as exc:  # unknown tool, bad args, transport error, timeout
            raise_if_cancelling(exc)
            failed += 1
            notes.append(f"{probe.name}: {type(exc).__name__}")
    return checked, failed, notes, skipped


def _classify(
    latency_ms: float,
    thresholds: Thresholds,
    tools_checked: int,
    tools_failed: int,
    tool_notes: list[str],
    validation_issues: list[str],
    skipped_probes: Sequence[str] = (),
) -> tuple[CheckStatus, str | None]:
    """Map raw signals to a status + human-readable detail.

    down     : latency >= latency_down_ms, OR every tested tool failed.
    degraded : latency >= latency_degraded_ms, OR some (not all) tested tools failed,
               OR the server violates known-spec validation rules.
    up       : none of the above.

    (An unrecognized spec version is *not* a factor here — it only sets
    spec_version_supported=False on the event; it never changes status.)
    """
    reasons: list[str] = []
    is_down = False
    is_degraded = False

    if latency_ms >= thresholds.latency_down_ms:
        is_down = True
        reasons.append(
            f"latency {latency_ms:.0f}ms >= down threshold {thresholds.latency_down_ms:.0f}ms"
        )
    if tools_checked > 0 and tools_failed == tools_checked:
        is_down = True
        reasons.append(f"all {tools_checked} tested tool(s) failed")

    if not is_down:
        if latency_ms >= thresholds.latency_degraded_ms:
            is_degraded = True
            reasons.append(
                f"latency {latency_ms:.0f}ms >= degraded threshold "
                f"{thresholds.latency_degraded_ms:.0f}ms"
            )
        if 0 < tools_failed < tools_checked:
            is_degraded = True
            reasons.append(f"{tools_failed}/{tools_checked} tested tool(s) failed")
        if validation_issues:
            is_degraded = True
            reasons.append("validation: " + "; ".join(validation_issues))

    # Always surface tool-level errors in detail, even when they drove the classification.
    if tool_notes:
        reasons.append("tool errors: " + "; ".join(tool_notes))
    if skipped_probes:
        reasons.append("probes skipped: " + "; ".join(skipped_probes))

    if is_down:
        status = CheckStatus.DOWN
    elif is_degraded:
        status = CheckStatus.DEGRADED
    else:
        status = CheckStatus.UP

    detail = "; ".join(reasons) if reasons else None
    return status, detail


def _format_exc(exc: BaseException) -> str:
    """Render an exception for the event detail, unwrapping the anyio ExceptionGroup that
    wraps transport errors so the real cause (e.g. ConnectError) is what's reported."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_format_exc(sub) for sub in exc.exceptions)
    return f"{type(exc).__name__}: {exc}"


def _has_auth_header(cfg: ServerConfig) -> bool:
    return any(k.lower() in ("authorization", "x-api-key") for k in cfg.headers)


def _auth_outcome(
    server_id: str, cfg: ServerConfig, log: HttpLog, latency_ms: float
) -> CheckOutcome:
    """Classify a 401/403 answer.

    Without credentials configured, a 401/403 means the server is alive and protected (most
    hosted MCP servers use OAuth): that's **up**, flagged ``auth_required`` — we just can't
    see its tools. With credentials configured it means they were rejected: **down**.
    """
    code = log.status
    challenge = log.headers.get("www-authenticate", "")
    if _has_auth_header(cfg):
        return CheckOutcome(
            CheckEvent(
                server_id=server_id,
                status=CheckStatus.DOWN,
                latency_ms=latency_ms,
                auth_required=True,
                detail=f"credentials rejected ({code}) — check the configured token",
            )
        )
    kind = "MCP OAuth" if "resource_metadata" in challenge else (
        challenge.split(" ", 1)[0] or "authentication")
    status, detail = _classify(latency_ms, cfg.thresholds, 0, 0, [], [])
    note = f"reachable — {kind} required ({code}); add an Authorization header to check tools"
    return CheckOutcome(
        CheckEvent(
            server_id=server_id,
            status=status,
            latency_ms=latency_ms,
            auth_required=True,
            detail="; ".join(filter(None, [note, detail])),
        )
    )


def raise_if_cancelling(exc: BaseException) -> None:
    """Re-raise cancellation that a library turned into an ordinary exception.

    When a check is cancelled mid-flight (server paused/edited/deleted, shutdown), the MCP
    SDK's task groups can surface it as e.g. a ClosedResourceError. Catching that as "server
    down" would swallow the cancellation: the check loop would keep running and whoever
    awaited the cancelled task would wait forever.
    """
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        raise asyncio.CancelledError from exc


@dataclass
class CheckOutcome:
    """A check's event plus the raw material later analysis needs.

    ``tools`` holds the normalized tool definitions from ``tools/list`` (see
    :func:`mcpsonar.tooldefs.normalize_tool`), or None when the handshake never completed.
    """

    event: CheckEvent
    tools: list[dict[str, Any]] | None = None


async def check_server(server_id: str, cfg: ServerConfig) -> CheckEvent:
    """Run one health check against ``cfg`` and return a standardized :class:`CheckEvent`.

    Never raises: connection/handshake failures are caught and returned as a ``down`` event.
    """
    return (await run_check(server_id, cfg)).event


async def run_check(server_id: str, cfg: ServerConfig) -> CheckOutcome:
    """Like :func:`check_server`, but also returns the tool definitions that were listed.

    The event detail is scrubbed of the server's credentials: it is stored, shown in the
    dashboard and pushed to webhooks/Uptime Kuma, and transport errors quote the URL.
    """
    budget = check_budget_s(cfg)
    try:
        async with asyncio.timeout(budget):
            outcome = await _run_check(server_id, cfg)
    except TimeoutError:
        # Belt and braces over the per-request timeouts: whatever hangs (a stdio process
        # that never answers, a probe), the check ends and the loop keeps running.
        outcome = CheckOutcome(
            CheckEvent(
                server_id=server_id,
                status=CheckStatus.DOWN,
                latency_ms=0.0,
                detail=f"check did not complete within {budget:.0f}s (server hung?)",
            )
        )
    outcome.event.detail = scrub(outcome.event.detail, secret_values(cfg))
    return outcome


def request_timeout_s(cfg: ServerConfig) -> float:
    """Per-request timeout: enough headroom to *observe* a down-by-latency result rather
    than aborting a slow-but-alive server early."""
    return cfg.thresholds.latency_down_ms / 1000.0 + 5.0


def check_budget_s(cfg: ServerConfig) -> float:
    """Upper bound for a whole check: connect + discover probe + initialize + listing +
    every probe."""
    t = request_timeout_s(cfg)
    probes = sum((p.timeout_seconds or t) for p in cfg.tools_to_test)
    return 3 * t + DISCOVER_PROBE_TIMEOUT_S + probes


async def _run_check(server_id: str, cfg: ServerConfig) -> CheckOutcome:
    thresholds = cfg.thresholds
    timeout_s = request_timeout_s(cfg)
    log = HttpLog()
    t0 = perf_counter()

    try:
        async with _open_session(cfg, timeout_s, log) as session:
            handshake = await negotiate(session, cfg.transport == TransportType.STDIO, log)
            latency_ms = handshake.latency_ms
            spec_version = handshake.protocol_version or None
            pagination_issue: str | None = None
            try:
                tools: list[Tool] = await list_all_tools(session)
            except PaginationError as exc:
                tools, pagination_issue = [], str(exc)

            tools_checked, tools_failed, tool_notes, skipped = await _probe_tools(
                session, cfg.tools_to_test, timeout_s, tools
            )

            # Version-aware validation: common rules always, version rules only if known.
            issues = run_minimal_common_validation(handshake, tools)
            validator = get_validator(spec_version)
            if validator is not None:
                spec_version_supported = True
                issues = issues + validator.validate(handshake, tools)
            else:
                spec_version_supported = False  # informational only; never changes status
            if pagination_issue:
                issues.append(pagination_issue)

            status, detail = _classify(
                latency_ms, thresholds, tools_checked, tools_failed, tool_notes, issues,
                skipped,
            )

            event = CheckEvent(
                server_id=server_id,
                status=status,
                latency_ms=latency_ms,
                tools_checked=tools_checked,
                tools_failed=tools_failed,
                tools_available=len(tools),
                spec_version=spec_version,
                spec_version_supported=spec_version_supported,
                detail=detail,
            )
            # An incomplete listing must not be diffed: every unseen tool would look removed.
            definitions = None if pagination_issue else [normalize_tool(t) for t in tools]
            return CheckOutcome(event, definitions)

    except Exception as exc:  # connect failure, handshake failure, timeout, etc.
        raise_if_cancelling(exc)
        if log.status in (401, 403):
            return _auth_outcome(server_id, cfg, log, (perf_counter() - t0) * 1000.0)
        if log.status == 429:
            # Alive, but throttling us: a problem worth seeing, not an outage.
            retry = log.headers.get("retry-after")
            return CheckOutcome(
                CheckEvent(
                    server_id=server_id,
                    status=CheckStatus.DEGRADED,
                    latency_ms=(perf_counter() - t0) * 1000.0,
                    detail="rate limited (429)" + (f", retry after {retry}s" if retry else ""),
                )
            )
        return CheckOutcome(
            CheckEvent(
                server_id=server_id,
                status=CheckStatus.DOWN,
                latency_ms=0.0,
                spec_version=None,
                spec_version_supported=False,
                detail=f"connection/handshake failed: {_format_exc(exc)}{log.describe()}",
            )
        )
