"""Validator for MCP spec version 2025-11-25 (the last handshake-era revision).

Only *version-specific* rules live here; the engine runs the common rules first. This file
is the template for every future version: copy it, change ``spec_version``, adjust the
rules, and register it — without touching this file or any older one.
"""

from __future__ import annotations

from mcp_types import Tool

from .base import BaseValidator, ServerHandshake, register


class V20251125Validator(BaseValidator):
    spec_version = "2025-11-25"

    def validate(self, server: ServerHandshake, tools: list[Tool]) -> list[str]:
        issues: list[str] = []

        # A server we monitor for tool health is expected to advertise the tools capability.
        if server.capabilities is None or server.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")

        # In this spec every tool must expose an inputSchema so clients can call it.
        for tool in tools:
            if tool.input_schema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")

        return issues


register(V20251125Validator())
