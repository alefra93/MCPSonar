"""Validator for MCP spec version 2025-03-26.

Introduces Streamable HTTP, tool ``annotations`` and OAuth-based authorization. The
rules a tools server must satisfy are the same as in later versions.

Kept as its own file (not a subclass) so each version's rules can evolve independently.
"""

from __future__ import annotations

from mcp_types import Tool

from .base import BaseValidator, ServerHandshake, register


class V20250326Validator(BaseValidator):
    spec_version = "2025-03-26"

    def validate(self, server: ServerHandshake, tools: list[Tool]) -> list[str]:
        issues: list[str] = []

        if server.capabilities is None or server.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")

        for tool in tools:
            if tool.input_schema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")

        return issues


register(V20250326Validator())
