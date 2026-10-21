"""Outbound connection policy: where mcpsonar may open HTTP connections.

mcpsonar connects to URLs that people configure (MCP servers, webhooks) and follows HTTP
redirects, which makes it an SSRF vector. It is also *self-hosted*: monitoring an MCP server
on ``10.0.0.12`` or ``localhost`` is a legitimate, common need. So the default is not "block
everything private" but "block what is never a legitimate MCP target":

* **always blocked** — unspecified (``0.0.0.0``, ``::``), multicast, reserved/broadcast, and
  the cloud **metadata** endpoints (``169.254.169.254``, ``fd00:ec2::254``,
  ``100.100.100.200``): reading instance credentials is the classic SSRF payoff;
* **blocked by default** — link-local (``169.254.0.0/16``, ``fe80::/10``);
  ``MCPSONAR_ALLOW_LINK_LOCAL=1`` re-allows it (metadata addresses stay blocked);
* **allowed by default** — loopback and private networks (RFC 1918, ULA, CGNAT);
  ``MCPSONAR_BLOCK_PRIVATE_NETWORKS=1`` blocks them for internet-only deployments;
* ``MCPSONAR_OUTBOUND_ALLOW`` / ``MCPSONAR_OUTBOUND_DENY`` — comma-separated CIDRs that
  override the above (deny wins; an explicit allow is the only way to reach a metadata IP).

**Enforcement point**: the TCP connect, not the URL. The hostname is resolved once, every
address is checked, and the connection goes to the checked address (TLS still verifies
the hostname). That covers redirects (each hop connects anew) and DNS rebinding (there is
no second lookup to race). Limitation: requests sent through an HTTP proxy configured via
``HTTP(S)_PROXY`` connect to the proxy, so the proxy must enforce destination rules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import httpcore2
import httpx2

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_TRUE = {"1", "true", "yes", "on"}


class BlockedDestinationError(httpcore2.ConnectError):
    """A connection refused by the outbound policy (surfaces as ``httpx2.ConnectError``)."""


def _networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip())


@dataclass(frozen=True)
class OutboundPolicy:
    allow_private: bool = True
    allow_loopback: bool = True
    allow_link_local: bool = False
    allow: tuple[IPNetwork, ...] = field(default=())
    deny: tuple[IPNetwork, ...] = field(default=())

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OutboundPolicy:
        env = os.environ if env is None else env  # type: ignore[assignment]
        block_private = env.get("MCPSONAR_BLOCK_PRIVATE_NETWORKS", "").lower() in _TRUE
        return cls(
            allow_private=not block_private,
            allow_loopback=not block_private,
            allow_link_local=env.get("MCPSONAR_ALLOW_LINK_LOCAL", "").lower() in _TRUE,
            allow=_networks(env.get("MCPSONAR_OUTBOUND_ALLOW", "").split(",")),
            deny=_networks(env.get("MCPSONAR_OUTBOUND_DENY", "").split(",")),
        )

    def check_ip(self, ip: IPAddress | str) -> str | None:
        """Why connecting to ``ip`` is not allowed, or None if it is."""
        ip = ipaddress.ip_address(ip)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # ::ffff:169.254.169.254 is 169.254.169.254
        if any(ip in net for net in self.deny):
            return f"{ip} is in MCPSONAR_OUTBOUND_DENY"
        if any(ip in net for net in self.allow):
            return None
        if ip in METADATA_ADDRESSES:
            return f"{ip} is a cloud metadata endpoint"
        if ip.is_loopback:  # before is_reserved: ::1 sits in the reserved ::/8 block
            return None if self.allow_loopback else f"{ip} is loopback (private networks blocked)"
        if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return f"{ip} is not a routable unicast address"
        if ip.is_link_local:
            return None if self.allow_link_local else (
                f"{ip} is link-local (set MCPSONAR_ALLOW_LINK_LOCAL=1 to allow)")
        if ip.is_private or (isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT):
            return None if self.allow_private else (
                f"{ip} is a private address (MCPSONAR_BLOCK_PRIVATE_NETWORKS is set)")
        return None


_policy: OutboundPolicy | None = None


def get_policy() -> OutboundPolicy:
    global _policy
    if _policy is None:
        _policy = OutboundPolicy.from_env()
    return _policy


def set_policy(policy: OutboundPolicy | None) -> None:
    """Replace the process-wide policy (None: re-read the environment on next use)."""
    global _policy
    _policy = policy


async def resolve(host: str, port: int) -> list[IPAddress]:
    """All addresses ``host`` resolves to (an IP literal resolves to itself)."""
    try:
        return [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        pass
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: dict[IPAddress, None] = {}
    for *_, sockaddr in infos:
        seen[ipaddress.ip_address(sockaddr[0].split("%", 1)[0])] = None
    return list(seen)


class PolicyNetworkBackend(httpcore2.AsyncNetworkBackend):
    """Wraps httpcore2's network backend: resolve, check every address, connect to an
    allowed one *by address* — so the address that was checked is the one connected to."""

    def __init__(
        self, inner: httpcore2.AsyncNetworkBackend, policy: OutboundPolicy | None = None
    ) -> None:
        self._inner = inner
        self._policy = policy

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        policy = self._policy or get_policy()
        try:
            addresses = await asyncio.wait_for(resolve(host, port), timeout)
        except (OSError, TimeoutError) as exc:
            raise httpcore2.ConnectError(f"could not resolve {host}: {exc}") from exc
        reasons = []
        last_error: Exception | None = None
        for ip in addresses:
            if reason := policy.check_ip(ip):
                reasons.append(reason)
                continue
            try:
                return await self._inner.connect_tcp(
                    str(ip), port, timeout=timeout, local_address=local_address,
                    socket_options=socket_options,
                )
            except httpcore2.ConnectError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise BlockedDestinationError(
            f"outbound policy blocked {host}: " + "; ".join(dict.fromkeys(reasons))
        )

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore2.AsyncNetworkStream:
        raise BlockedDestinationError("outbound policy: unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def policy_transport(
    verify: ssl.SSLContext | bool = True, policy: OutboundPolicy | None = None
) -> httpx2.AsyncHTTPTransport:
    """An httpx2 transport whose connections go through :class:`PolicyNetworkBackend`."""
    transport = httpx2.AsyncHTTPTransport(verify=verify)
    pool = transport._pool  # httpcore2.AsyncConnectionPool; no public hook for the backend
    pool._network_backend = PolicyNetworkBackend(pool._network_backend, policy)
    return transport
