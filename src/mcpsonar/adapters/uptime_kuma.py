"""Uptime Kuma push adapter.

Uptime Kuma has no notion of 'degraded', only up/down. We map ``degraded`` -> ``up`` so a
mere slowdown does not raise a false down-alarm, but we put the real status and detail in the
``msg`` field so the degradation is visible in Kuma. Only ``down`` maps to Kuma ``down``.
"""

from __future__ import annotations

import logging

import httpx2

from ..models import CheckEvent, CheckStatus
from .base import BaseAdapter

logger = logging.getLogger("mcpsonar.adapters.uptime_kuma")


class UptimeKumaAdapter(BaseAdapter):
    name = "uptime_kuma"

    def __init__(self, push_url: str, client: httpx2.AsyncClient) -> None:
        super().__init__(client)
        self._push_url = push_url

    async def send(self, event: CheckEvent) -> None:
        kuma_status = "down" if event.status == CheckStatus.DOWN else "up"  # degraded -> up
        msg = event.status.value if not event.detail else f"{event.status.value}: {event.detail}"
        if event.anomalies:
            msg += " | " + "; ".join(f"{a.kind}: {a.detail}" for a in event.anomalies)
        params = {
            "status": kuma_status,
            "msg": msg,
            "ping": round(event.latency_ms),
        }
        response = await self._client.get(self._push_url, params=params)
        response.raise_for_status()
        logger.debug("pushed %s (%s) to Uptime Kuma", event.server_id, kuma_status)
