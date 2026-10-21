"""Version-aware validation layer.

The MCP spec is versioned (2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, ...), and the
capabilities/fields expected of a server change between versions. mcpsonar must therefore
**not** hardcode a single schema.

Design:

* :func:`run_minimal_common_validation` holds the rules true for *every* version. It is the
  only validation applied when a server declares a spec version we don't recognize — so an
  unknown version never produces version-specific false positives/negatives.
* Each known version gets its own :class:`BaseValidator` subclass, self-registered into
  :data:`VALIDATOR_REGISTRY` keyed by its exact ``spec_version`` string. A validator only
  encodes the *version-specific* rules — the engine always runs the common rules first, so
  validators must not repeat them.

Adding support for a new spec version = add one file with one ``@register``-ed subclass.
Existing validators are never touched, so older servers keep being validated by the exact
rules they were built against.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from mcp_types import Implementation, ServerCapabilities, Tool


class ServerHandshake(Protocol):
    """What validators need to know about a server, whichever protocol era it speaks:
    from ``initialize`` (handshake era) or ``server/discover`` (2026-07-28 and later).
    Implemented by :class:`mcpsonar.check_engine.Handshake`."""

    @property
    def protocol_version(self) -> str | None: ...

    @property
    def server_info(self) -> Implementation | None: ...

    @property
    def capabilities(self) -> ServerCapabilities | None: ...


def run_minimal_common_validation(server: ServerHandshake, tools: list[Tool]) -> list[str]:
    """Rules that hold for *all* MCP spec versions. Returns a list of issue strings.

    Keep this deliberately conservative: anything here is asserted against servers whose
    spec version we do not otherwise understand, so it must only flag things that are
    unambiguously wrong regardless of version.
    """
    issues: list[str] = []
    if not server.protocol_version:
        issues.append("server declared an empty protocolVersion")
    if server.server_info is None or not server.server_info.name:
        issues.append("server did not report serverInfo.name")
    seen: set[str] = set()
    for tool in tools:
        if not tool.name:
            issues.append("a listed tool has an empty name")
        elif tool.name in seen:
            # Two definitions under one name: which one a client uses is undefined, and a
            # second copy is an easy way to shadow a reviewed tool.
            issues.append(f"tool name '{tool.name}' is listed more than once")
        seen.add(tool.name)
    return issues


class BaseValidator(ABC):
    """Interface every version-specific validator implements.

    ``spec_version`` is the exact string a server reports in the ``initialize`` handshake
    (e.g. ``"2025-11-25"``); it is the registry key.
    """

    #: exact MCP spec version this validator knows how to validate
    spec_version: str

    @abstractmethod
    def validate(self, server: ServerHandshake, tools: list[Tool]) -> list[str]:
        """Return version-specific issues (empty list == clean).

        The engine has already run :func:`run_minimal_common_validation`; do not repeat it.
        """
        raise NotImplementedError


#: spec_version -> validator instance
VALIDATOR_REGISTRY: dict[str, BaseValidator] = {}


def register(validator: BaseValidator) -> BaseValidator:
    """Register a validator instance under its ``spec_version``. Usable as a decorator on
    the class (``@register`` won't work directly — see the concrete files for the idiom)."""
    VALIDATOR_REGISTRY[validator.spec_version] = validator
    return validator


def get_validator(spec_version: str | None) -> BaseValidator | None:
    """Return the validator for a spec version, or None if we don't recognize it."""
    if spec_version is None:
        return None
    return VALIDATOR_REGISTRY.get(spec_version)
