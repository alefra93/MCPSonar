"""Validator for MCP spec version 2026-07-28 (the first "modern" revision).

No ``initialize`` handshake: the server describes itself through ``server/discover``, and
every request carries its version in ``_meta``. What a healthy tools server must provide is
unchanged — it advertises the ``tools`` capability and every tool has an ``inputSchema``.

Not checked here: ``ttlMs`` / ``cacheScope`` on list results became mandatory in this
revision, but the SDK fills in defaults when a server omits them, so their absence is not
observable from the typed result (see docs/adr/0001-mcp-sdk-2.md).
"""

from __future__ import annotations

from mcp_types import Tool

from .base import BaseValidator, ServerHandshake, register


class V20260728Validator(BaseValidator):
    spec_version = "2026-07-28"

    def validate(self, server: ServerHandshake, tools: list[Tool]) -> list[str]:
        issues: list[str] = []
        if server.capabilities is None or server.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")
        for tool in tools:
            if tool.input_schema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")
        return issues


register(V20260728Validator())
