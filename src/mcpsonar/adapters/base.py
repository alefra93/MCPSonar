"""Adapter interface: translate a CheckEvent for one external system.

Every push adapter implements the same ``async send(event)`` so new destinations (ExeWatch,
Slack, ...) drop in without touching the core. Adapters receive a shared ``httpx2.AsyncClient``
at construction — the caller owns its lifecycle — which keeps ``send`` clean and testable
(inject a client backed by ``httpx2.MockTransport``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx2

from ..models import CheckEvent


class BaseAdapter(ABC):
    #: short adapter name, for logging
    name: str = "adapter"

    def __init__(self, client: httpx2.AsyncClient) -> None:
        self._client = client

    @abstractmethod
    async def send(self, event: CheckEvent) -> None:
        """Deliver ``event`` to the external system. May raise on unrecoverable failure."""
        raise NotImplementedError
