"""Remote mode: talk to a running MCPSonar instance through its REST API.

The CLI never opens an instance's database for writing — the instance (its scheduler and
API) is the single writer. Remote commands are thin views over the same endpoints the
dashboard uses, so both always show the same data.

Configuration (environment, so the token stays out of shell history and ``ps``):

* ``MCPSONAR_URL``   — the instance, default ``http://127.0.0.1:8675`` (``--url`` overrides);
* ``MCPSONAR_TOKEN`` — an API token from the dashboard (*API tokens*), needed when the
  instance has its login enabled. ``read`` tokens suffice for every command except
  ``check`` and the ``servers`` commands that change something.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Self
from urllib.parse import quote, urlsplit

import httpx2

from .. import __version__
from ..output import Output

DEFAULT_URL = "http://127.0.0.1:8675"

#: Tests inject an in-process transport (ASGI app) here; never set in normal use.
TRANSPORT_OVERRIDE: httpx2.AsyncBaseTransport | None = None


class RemoteError(Exception):
    """A remote command could not be completed; the message says why and what to do."""


def add_remote_args(parser: Any) -> None:
    parser.add_argument(
        "--url", default=os.environ.get("MCPSONAR_URL", DEFAULT_URL),
        help=f"MCPSonar instance (env MCPSONAR_URL; default {DEFAULT_URL}). The API token is "
        "read from MCPSONAR_TOKEN.",
    )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class Remote:
    """An authenticated client for one instance. Use as an async context manager."""

    def __init__(self, url: str, out: Output, token: str | None = None) -> None:
        self.url = url.rstrip("/")
        self.out = out
        self.token = token if token is not None else os.environ.get("MCPSONAR_TOKEN")
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RemoteError(f"--url must be an http(s) URL, got {url!r}")
        if self.token and parts.scheme == "http" and not _is_loopback(parts.hostname):
            out.warn(f"sending the API token over plain HTTP to {parts.hostname}; "
                     "use https:// for anything but localhost")
        headers = {"User-Agent": f"mcpsonar-cli/{__version__}", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._client = httpx2.AsyncClient(
            base_url=self.url, headers=headers, timeout=httpx2.Timeout(30.0, connect=5.0),
            transport=TRANSPORT_OVERRIDE,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            r = await self._client.request(method, path, **kwargs)
        except httpx2.ConnectError as exc:
            raise RemoteError(
                f"no MCPSonar instance at {self.url} (start one with `mcpsonar run`, or set "
                "MCPSONAR_URL / --url)") from exc
        except httpx2.TimeoutException as exc:
            raise RemoteError(f"{self.url} did not answer in time") from exc
        except httpx2.HTTPError as exc:
            raise RemoteError(f"request to {self.url} failed: {exc}") from exc
        if r.status_code == 401:
            hint = ("the token was rejected (expired or revoked?)" if self.token else
                    "this instance requires a login")
            raise RemoteError(f"{hint}: create an API token in the dashboard (API tokens) and "
                              "set MCPSONAR_TOKEN")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = None
            raise RemoteError(f"{method} {path} → {r.status_code}: {detail or r.reason_phrase}")
        if r.status_code == 204 or not r.content:
            return None
        try:
            return r.json()
        except ValueError as exc:
            raise RemoteError(f"{self.url} did not answer like MCPSonar") from exc

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params={k: v for k, v in params.items()
                                                       if v is not None})

    async def resolve_server(self, ref: str) -> dict[str, Any]:
        """A server by id, exact name, or unambiguous case-insensitive name."""
        servers = await self.get("/api/servers")
        by_id = [s for s in servers if s["id"] == ref]
        exact = [s for s in servers if s["name"] == ref]
        loose = [s for s in servers if s["name"].lower() == ref.lower()]
        for matches in (by_id, exact, loose):
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                ids = ", ".join(f"{s['name']} ({s['id']})" for s in matches)
                raise RemoteError(f"{ref!r} matches several servers: {ids}; use the id")
        names = ", ".join(s["name"] for s in servers) or "(none)"
        raise RemoteError(f"no server {ref!r} on {self.url}; servers: {names}")


def server_path(server: dict[str, Any], suffix: str = "") -> str:
    return f"/api/servers/{quote(server['id'], safe='')}{suffix}"
