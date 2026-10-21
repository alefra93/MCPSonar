"""Validator registry package.

Importing this package registers every known version validator as a side effect, so
``get_validator("2025-11-25")`` works after a plain ``import mcpsonar.validators``.
Register a new spec version by adding a module here and importing it below.
"""

from __future__ import annotations

# Import concrete validators for their registration side effects.
from . import v2024_11_05, v2025_03_26, v2025_06_18, v2025_11_25, v2026_07_28  # noqa: F401
from .base import (
    VALIDATOR_REGISTRY,
    BaseValidator,
    get_validator,
    register,
    run_minimal_common_validation,
)

__all__ = [
    "VALIDATOR_REGISTRY",
    "BaseValidator",
    "get_validator",
    "register",
    "run_minimal_common_validation",
]
