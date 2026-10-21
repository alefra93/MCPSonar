"""Validator for MCP spec version 2025-06-18.

Adds structured tool output (``outputSchema``) and tool ``title``s; removes JSON-RPC
batching. None of that changes what a healthy tools server must provide, so the rules
match 2025-11-25.

Kept as its own file (not a subclass) so each version's rules can evolve independently.
"""

from __future__ import annotations

from mcp_types import Tool

from .base import BaseValidator, ServerHandshake, register


class V20250618Validator(BaseValidator):
    spec_version = "2025-06-18"

    def validate(self, server: ServerHandshake, tools: list[Tool]) -> list[str]:
        issues: list[str] = []

        if server.capabilities is None or server.capabilities.tools is None:
            issues.append("server does not advertise the 'tools' capability")

        for tool in tools:
            if tool.input_schema is None:
                issues.append(f"tool '{tool.name}' is missing inputSchema")

        return issues


register(V20250618Validator())
