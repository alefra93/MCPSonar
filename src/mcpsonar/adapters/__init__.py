"""Output adapters and the dispatcher that fans check events out to them.

Push adapters (Uptime Kuma, generic webhook) implement :class:`BaseAdapter` and share one
``httpx2.AsyncClient`` owned by :class:`AdapterDispatcher`. The Prometheus exporter is not a
push adapter — it is scraped via ``/metrics`` and reads the StateStore directly.
"""

from __future__ import annotations

import httpx2

from ..models import GenericWebhook, ServerConfig, UptimeKumaWebhook
from .base import BaseAdapter
from .generic_webhook import GenericWebhookAdapter
from .prometheus import CONTENT_TYPE, render_metrics
from .uptime_kuma import UptimeKumaAdapter

__all__ = [
    "CONTENT_TYPE",
    "BaseAdapter",
    "GenericWebhookAdapter",
    "UptimeKumaAdapter",
    "build_push_adapters",
    "render_metrics",
]


def build_push_adapters(cfg: ServerConfig, client: httpx2.AsyncClient) -> list[BaseAdapter]:
    """Construct the push adapters declared in a server's webhook config. The scheduler owns
    the shared client and dispatches events to these per server."""
    adapters: list[BaseAdapter] = []
    for webhook in cfg.webhooks:
        if isinstance(webhook, UptimeKumaWebhook):
            adapters.append(UptimeKumaAdapter(webhook.push_url, client))
        elif isinstance(webhook, GenericWebhook):
            adapters.append(
                GenericWebhookAdapter(
                    webhook.url, webhook.on, client, on_anomaly=webhook.on_anomaly
                )
            )
    return adapters
