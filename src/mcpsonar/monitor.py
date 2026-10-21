"""The check pipeline: one check → analysis → policy → persisted :class:`CheckEvent`.

:mod:`mcpsonar.check_engine` speaks MCP and knows nothing about history. This module adds
everything that needs memory of past checks:

1. **Tool pinning** — diff ``tools/list`` against the last-seen definitions; any add /
   remove / change is recorded until a human reviews it (rug-pull detection).
2. **Tool-poisoning lint** — flag suspicious content in the current definitions.
3. **Anomaly detection** — latency spike / shift and flapping vs. the server's own history.
4. **Policy** — apply ``on_tool_change`` / ``anomaly.degrade`` to the status, then persist.

Both the scheduler loop and the "Check now" API go through :func:`process_check`, so a
manual check is analysed exactly like a scheduled one.
"""

from __future__ import annotations

from . import anomaly as ad
from .check_engine import run_check
from .lint import lint_tools, risk_count
from .models import Anomaly, CheckEvent, CheckStatus, ServerConfig
from .storage import Storage
from .tooldefs import diff_tools, index_tools, renormalize


async def process_check(storage: Storage, server_id: str, cfg: ServerConfig) -> CheckEvent:
    outcome = await run_check(server_id, cfg)
    event = outcome.event
    found: list[Anomaly] = []

    if outcome.tools is not None:
        event.tool_risks = risk_count(lint_tools(outcome.tools))
        if cfg.on_tool_change != "ignore":
            found += await _track_tool_changes(storage, server_id, outcome.tools)
    if cfg.on_tool_change != "ignore":
        # Pending changes stay visible even while the server is down.
        event.tool_changes = await storage.count_pending_tool_changes(server_id)

    if cfg.anomaly.enabled:
        found += await _detect_anomalies(storage, event, cfg)

    event.anomalies = found
    _apply_policy(event, cfg)
    await storage.record_check(event)
    return event


async def _track_tool_changes(
    storage: Storage, server_id: str, tools: list[dict]
) -> list[Anomaly]:
    current = index_tools(tools)
    stored = await storage.get_tool_snapshot(server_id)
    if stored is None:  # first successful listing: pin it as the baseline, silently
        await storage.save_tool_snapshot(server_id, current)
        return []
    previous = {name: renormalize(d) for name, d in stored.items()}
    changes = diff_tools(previous, current)
    if not changes:
        if previous != stored:  # only the stored form changed (SDK upgrade): re-pin quietly
            await storage.save_tool_snapshot(server_id, current)
        return []
    await storage.add_tool_changes(server_id, changes)
    await storage.save_tool_snapshot(server_id, current)
    return [Anomaly(kind="tool_change", detail="; ".join(c.summary() for c in changes))]


async def _detect_anomalies(
    storage: Storage, event: CheckEvent, cfg: ServerConfig
) -> list[Anomaly]:
    found: list[Anomaly] = []
    # Oldest → newest, *excluding* the current check (not recorded yet).
    history = await storage.get_history(event.server_id, limit=ad.BASELINE_WINDOW)

    if event.status != CheckStatus.DOWN:
        healthy = [e for e in history if e.status != CheckStatus.DOWN]
        baseline = ad.robust_baseline([e.latency_ms for e in healthy])
        if baseline is not None:
            score = ad.robust_score(event.latency_ms, baseline)
            event.latency_baseline_ms = round(baseline.median, 1)
            event.latency_score = round(score, 2)
            if ad.is_spike(event.latency_ms, baseline, cfg.anomaly.sensitivity):
                found.append(
                    Anomaly(
                        kind="latency_spike",
                        detail=f"latency {event.latency_ms:.0f}ms vs baseline "
                        f"{baseline.median:.0f}ms ({score:.1f}σ)",
                        score=round(score, 2),
                    )
                )

        window = healthy[-(ad.SHIFT_WINDOW - 1):] + [event]
        cp = ad.find_change_point([e.latency_ms for e in window])
        if cp is not None and len(window) - cp.index <= ad.SHIFT_MAX_AGE:
            changed_at = window[cp.index].checked_at
            if not await storage.anomaly_reported_since(
                event.server_id, "latency_shift", changed_at
            ):
                direction = "slower" if cp.after_ms > cp.before_ms else "faster"
                found.append(
                    Anomaly(
                        kind="latency_shift",
                        detail=f"latency shifted {cp.before_ms:.0f}ms → {cp.after_ms:.0f}ms "
                        f"({direction}, ×{max(cp.ratio, 1 / cp.ratio):.1f}) since "
                        f"{changed_at.strftime('%H:%M')} UTC",
                        score=round(cp.t_stat, 2),
                    )
                )

    recent = history[-(ad.FLAP_WINDOW - 1):]
    statuses = [e.status.value for e in recent] + [event.status.value]
    if recent and ad.is_flapping(statuses) and not await storage.anomaly_reported_since(
        event.server_id, "flapping", recent[0].checked_at
    ):
        found.append(
            Anomaly(
                kind="flapping",
                detail=f"{ad.count_transitions(statuses)} status changes in the last "
                f"{len(statuses)} checks",
                score=float(ad.count_transitions(statuses)),
            )
        )
    return found


def _apply_policy(event: CheckEvent, cfg: ServerConfig) -> None:
    """Escalate up → degraded for unreviewed tool changes / latency anomalies (if enabled)."""
    reasons: list[str] = []
    if cfg.on_tool_change == "degrade" and event.tool_changes:
        reasons.append(f"{event.tool_changes} unreviewed tool change(s)")
    if cfg.anomaly.degrade:
        reasons += [a.detail for a in event.anomalies if a.kind.startswith("latency_")]
    if not reasons or event.status == CheckStatus.DOWN:
        return
    event.status = CheckStatus.DEGRADED
    event.detail = "; ".join(filter(None, [event.detail, *reasons]))
