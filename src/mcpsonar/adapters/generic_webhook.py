"""Generic webhook adapter: POST the raw CheckEvent JSON to an arbitrary URL.

Fires for the statuses listed in ``on`` (default down + degraded) and, when ``on_anomaly`` is
set (the default), for any check that detected something new — a latency anomaly, flapping,
or a tool-definition change — whatever its status. Retries transient
failures up to ``max_retries`` attempts with exponential backoff, then raises so the caller
can log the final failure.
"""

from __future__ import annotations

import asyncio
import logging

import httpx2

from ..models import CheckEvent, CheckStatus
from ..redact import redact_url, scrub
from .base import BaseAdapter

logger = logging.getLogger("mcpsonar.adapters.generic_webhook")


class GenericWebhookAdapter(BaseAdapter):
    name = "generic"

    def __init__(
        self,
        url: str,
        on: list[CheckStatus],
        client: httpx2.AsyncClient,
        max_retries: int = 3,
        backoff: float = 0.5,
        on_anomaly: bool = True,
    ) -> None:
        super().__init__(client)
        self._url = url
        self._on = set(on)
        self._on_anomaly = on_anomaly
        self._max_retries = max_retries
        self._backoff = backoff

    async def send(self, event: CheckEvent) -> None:
        if event.status not in self._on and not (self._on_anomaly and event.anomalies):
            return  # nothing this webhook cares about

        payload = event.model_dump(mode="json")
        delay = self._backoff
        last_exc: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                response = await self._client.post(self._url, json=payload)
                response.raise_for_status()
                logger.debug("posted %s to %s (attempt %d)", event.server_id,
                             redact_url(self._url, whole_path=True), attempt)
                return
            except Exception as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    # Retries are troubleshooting detail; the dispatcher logs the final
                    # failure once at warning, so keep these at debug to avoid log spam.
                    logger.debug(
                        "webhook POST to %s failed (attempt %d/%d): %s; retrying in %.1fs",
                        redact_url(self._url, whole_path=True),
                        attempt,
                        self._max_retries,
                        scrub(str(exc), [self._url]),
                        delay,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2

        assert last_exc is not None
        raise last_exc
