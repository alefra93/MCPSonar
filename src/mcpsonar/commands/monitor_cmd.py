"""Remote-mode views of a running instance: ``status``, ``check``, ``diff``, ``history``.

They render the same endpoints as the dashboard (so the numbers always agree) and never
decide anything themselves: health, findings, baselines and change detection all come from
the instance's engine. ``diff`` never approves anything — approval stays a human action in
the dashboard.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from statistics import median
from typing import Any

from ..lint import SEVERITY_ORDER
from ..output import (
    EXIT_ERROR,
    EXIT_FAILED,
    EXIT_OK,
    Output,
    Style,
    add_format_args,
    output_for,
    table,
)
from ._remote import Remote, RemoteError, add_remote_args, server_path

STATUS_WORD = {"up": "HEALTHY", "degraded": "DEGRADED", "down": "DOWN"}
_RANK = {"up": 0, "degraded": 1, "down": 2}


def register(sub: Any) -> None:
    status = sub.add_parser(
        "status", help="Overview of the servers a running instance monitors.",
        description="Health, latency, last check, unreviewed tool changes, findings and "
        "anomalies of every monitored server, as the dashboard shows them.")
    add_remote_args(status)
    status.add_argument("--fail-on", choices=["down", "degraded", "never"], default="never",
                        help="Exit 1 if an enabled server is at least this unhealthy "
                        "(default: never).")
    add_format_args(status)
    status.set_defaults(handler=run_status)

    check = sub.add_parser(
        "check", help="Check a server now, on the instance (needs a write token).",
        description="Run an immediate check through the instance, so it is recorded and "
        "analysed exactly like a scheduled one.")
    check.add_argument("server", nargs="?", help="Server name or id.")
    check.add_argument("--all", action="store_true", help="Check every enabled server.")
    add_remote_args(check)
    check.add_argument("--fail-on", choices=["down", "degraded", "never"], default="down",
                       help="Exit 1 if a result is at least this unhealthy (default: down).")
    add_format_args(check)
    check.set_defaults(handler=run_check)

    diff = sub.add_parser(
        "diff", help="Tool-definition changes waiting for review (never approves).",
        description="Show added, removed and changed tools vs. the trusted definitions. A "
        "change whose new definition has findings is marked SUSPICIOUS. Exit 1 while changes "
        "are unreviewed. Approve in the dashboard after reading the diff.")
    diff.add_argument("server", help="Server name or id.")
    diff.add_argument("--all", action="store_true",
                      help="Include changes already approved (marked APPROVED).")
    add_remote_args(diff)
    add_format_args(diff)
    diff.set_defaults(handler=run_diff)

    history = sub.add_parser(
        "history", help="Availability and latency history of a server.",
        description="Uptime, latency percentiles, the learned baseline, incidents and "
        "anomalies over a window (default: the last 24h, at most 500 checks).")
    history.add_argument("server", help="Server name or id.")
    history.add_argument("--last", default="24h", metavar="DURATION",
                         help="Window: e.g. 90m, 24h, 7d (default 24h).")
    history.add_argument("--limit", type=int, default=500,
                         help="At most this many checks (1-5000, default 500).")
    add_remote_args(history)
    add_format_args(history)
    history.set_defaults(handler=run_history)


# ---- helpers ------------------------------------------------------------------ #
def ago(iso: str | None) -> str:
    if not iso:
        return "—"
    s = (datetime.now(UTC) - datetime.fromisoformat(iso)).total_seconds()
    if s < 60:
        return f"{max(int(s), 0)}s ago"
    if s < 3600:
        return f"{int(s // 60)}m ago"
    if s < 86400:
        return f"{int(s // 3600)}h ago"
    return f"{int(s // 86400)}d ago"


def status_word(event: dict | None, enabled: bool) -> str:
    if not enabled:
        return "PAUSED"
    if event is None:
        return "PENDING"
    return STATUS_WORD[event["status"]]


def colored(word: str, s: Style) -> str:
    return {"HEALTHY": s.green, "DEGRADED": s.yellow, "DOWN": s.red}.get(word, s.dim)(word)


def _fails(status: str, fail_on: str) -> bool:
    return fail_on != "never" and _RANK[status] >= _RANK[fail_on]


async def _remote(args: Any, out: Output) -> Remote | None:
    try:
        return Remote(args.url, out)
    except RemoteError as exc:
        out.error(str(exc))
        return None


# ---- status ------------------------------------------------------------------- #
async def run_status(args: Any) -> int:
    out = output_for(args)
    remote = await _remote(args, out)
    if remote is None:
        return EXIT_ERROR
    try:
        async with remote:
            data = await remote.get("/api/status")
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR

    servers = sorted(data.items(), key=lambda kv: kv[1]["name"].lower())
    failed = any(
        s["enabled"] and s["event"] and _fails(s["event"]["status"], args.fail_on)
        for _, s in servers
    )
    code = EXIT_FAILED if failed else EXIT_OK
    if out.json_mode:
        out.emit_json("status", {"url": remote.url, "servers": [
            {"id": sid, "name": s["name"], "enabled": s["enabled"],
             "transport": s["transport"], "target": s["target"],
             "status": status_word(s["event"], s["enabled"]).lower(),
             "event": s["event"], "last_anomaly": s["last_anomaly"]}
            for sid, s in servers]})
        return code

    st = out.style
    out.print(f"{st.bold('MCPSonar')} · {remote.url}")
    out.print()
    if not servers:
        out.print("  No servers monitored yet. Add one in the dashboard or with "
                  "`mcpsonar servers add`.")
        return code
    rows, words = [], []
    pending_changes = risky = 0
    for _, s in servers:
        ev = s["event"]
        word = status_word(ev, s["enabled"])
        words.append(word)
        notes = []
        if ev and ev.get("auth_required"):
            notes.append("auth required")
        if s["last_anomaly"]:
            la = s["last_anomaly"]
            notes.append(f"{la['kind'].replace('_', ' ')} {ago(la['checked_at'])}")
        changes = ev["tool_changes"] if ev else 0
        risks = ev["tool_risks"] if ev else 0
        pending_changes += changes
        risky += 1 if risks else 0
        latency = f"{ev['latency_ms']:.0f} ms" if ev and ev["status"] != "down" else "—"
        rows.append([
            s["name"], colored(word, st), latency, ago(ev["checked_at"]) if ev else "—",
            st.yellow(str(changes)) if changes else "0",
            st.red(str(risks)) if risks else "0", ", ".join(notes),
        ])
    out.print(table(["SERVER", "STATUS", "LATENCY", "LAST CHECK", "CHANGES", "RISKS", "NOTE"],
                    rows, st))
    out.print()
    counts = {w: words.count(w) for w in ("HEALTHY", "DEGRADED", "DOWN", "PAUSED", "PENDING")}
    summary = " · ".join(f"{n} {w.lower()}" for w, n in counts.items() if n)
    out.print(f"{len(servers)} monitored · {summary}")
    if pending_changes:
        out.print(st.yellow(f"WARNING: {pending_changes} unreviewed tool definition change(s)"
                            " — run `mcpsonar diff <server>`"))
    if risky:
        out.print(st.yellow(f"WARNING: {risky} server(s) with tool-poisoning findings — run "
                            "`mcpsonar risks`; findings are heuristics for review"))
    return code


# ---- check -------------------------------------------------------------------- #
async def run_check(args: Any) -> int:
    out = output_for(args)
    if bool(args.server) == bool(args.all):
        out.error("give a server name or id, or --all")
        return EXIT_ERROR
    remote = await _remote(args, out)
    if remote is None:
        return EXIT_ERROR
    results = []
    try:
        async with remote:
            if args.all:
                targets = [s for s in await remote.get("/api/servers") if s["enabled"]]
            else:
                targets = [await remote.resolve_server(args.server)]
            for server in targets:
                event = await remote.request("POST", server_path(server, "/check"))
                results.append((server, event))
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR

    failed = any(_fails(ev["status"], args.fail_on) for _, ev in results)
    code = EXIT_FAILED if failed else EXIT_OK
    if out.json_mode:
        out.emit_json("check", {"results": [{"id": s["id"], "name": s["name"], "event": ev}
                                            for s, ev in results]})
        return code
    st = out.style
    if not results:
        out.print("No enabled servers to check.")
    rows = [[s["name"], colored(STATUS_WORD[ev["status"]], st),
             f"{ev['latency_ms']:.0f} ms" if ev["status"] != "down" else "—",
             str(ev["tool_changes"]), str(ev["tool_risks"]), ev.get("detail") or ""]
            for s, ev in results]
    if rows:
        out.print(table(["SERVER", "STATUS", "LATENCY", "CHANGES", "RISKS", "DETAIL"], rows, st))
    return code


# ---- diff --------------------------------------------------------------------- #
def classify(change: dict) -> str:
    if change["reviewed"]:
        return "approved"
    if any(SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER["medium"]
           for f in change.get("findings", [])):
        return "suspicious"
    return "pending"


def _props(defn: dict | None) -> set[str]:
    schema = (defn or {}).get("inputSchema") or {}
    return set((schema.get("properties") or {}).keys())


def _clip(text: str, n: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + "…"


async def run_diff(args: Any) -> int:
    out = output_for(args)
    remote = await _remote(args, out)
    if remote is None:
        return EXIT_ERROR
    try:
        async with remote:
            server = await remote.resolve_server(args.server)
            changes = await remote.get(server_path(server, "/tool-changes"),
                                       all="true" if args.all else None)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    pending = [c for c in changes if not c["reviewed"]]
    code = EXIT_FAILED if pending else EXIT_OK
    if out.json_mode:
        out.emit_json("diff", {"server": {"id": server["id"], "name": server["name"]},
                               "pending": len(pending),
                               "changes": [{**c, "classification": classify(c)}
                                           for c in changes]})
        return code

    st = out.style
    out.print(f"{st.bold('mcpsonar diff')} · {server['name']} · "
              f"{len(pending)} unreviewed change(s)")
    out.print()
    if not changes:
        out.print("  Tools match the trusted definitions.")
        return code
    sym = {"added": st.green("+"), "removed": st.red("-"), "changed": st.yellow("~")}
    label = {"approved": st.green("APPROVED"), "suspicious": st.red("SUSPICIOUS · review"),
             "pending": st.yellow("pending review")}
    for c in changes:
        what = f"{', '.join(c['fields'])} changed" if c["kind"] == "changed" else c["kind"]
        out.print(f"  {sym[c['kind']]} {st.bold(c['tool'])}  [{label[classify(c)]}]  {what}  "
                  f"{st.dim('· detected ' + c['detected_at'][:19].replace('T', ' ') + ' UTC')}")
        before, after = c.get("before") or {}, c.get("after") or {}
        if c["kind"] == "changed" and "description" in c["fields"]:
            out.print(f"      {st.red('- ' + _clip(before.get('description') or ''))}")
            out.print(f"      {st.green('+ ' + _clip(after.get('description') or ''))}")
        added, removed = _props(after) - _props(before), _props(before) - _props(after)
        if c["kind"] == "changed" and (added or removed):
            parts = [f"+{p}" for p in sorted(added)] + [f"-{p}" for p in sorted(removed)]
            out.print(f"      parameters: {' '.join(parts)}")
        for f in c.get("findings", []):
            out.print(f"      {st.severity(f['severity'], 6)} {f['rule']} — {f['message']}")
        out.print()
    if pending:
        out.print("  Review, then approve in the dashboard (Changes → Approve). "
                  "mcpsonar never approves changes on its own.")
    return code


# ---- history ------------------------------------------------------------------ #
_DURATION = re.compile(r"^(\d+)\s*([mhd])$")


def parse_duration(text: str) -> int:
    """Minutes in ``90m`` / ``24h`` / ``7d``."""
    m = _DURATION.match(text.strip().lower())
    if not m:
        raise ValueError(f"invalid duration {text!r}: use e.g. 90m, 24h, 7d")
    return int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]


def incidents(events: list[dict]) -> list[dict]:
    """Runs of non-up checks: when each started, its worst status, and when it recovered."""
    found: list[dict] = []
    current: dict | None = None
    for e in events:
        if e["status"] != "up":
            if current is None:
                current = {"started": e["checked_at"], "worst": e["status"], "checks": 0,
                           "recovered": None, "detail": e.get("detail")}
                found.append(current)
            current["checks"] += 1
            if _RANK[e["status"]] > _RANK[current["worst"]]:
                current["worst"] = e["status"]
        elif current is not None:
            current["recovered"] = e["checked_at"]
            current = None
    return found


async def run_history(args: Any) -> int:
    out = output_for(args)
    try:
        minutes = parse_duration(args.last)
    except ValueError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if not 1 <= args.limit <= 5000:
        out.error("--limit must be between 1 and 5000")
        return EXIT_ERROR
    remote = await _remote(args, out)
    if remote is None:
        return EXIT_ERROR
    try:
        async with remote:
            server = await remote.resolve_server(args.server)
            events = await remote.get(server_path(server, "/history"),
                                      minutes=minutes, limit=args.limit)
            insights = await remote.get(server_path(server, "/insights"),
                                        minutes=minutes, limit=args.limit)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR

    healthy = [e["latency_ms"] for e in events if e["status"] != "down"]
    summary = {
        "checks": len(events),
        "uptime_pct": round(100 * len(healthy) / len(events), 2) if events else None,
        "latency_p50_ms": round(median(healthy), 1) if healthy else None,
        "latency_p95_ms": round(_percentile(healthy, 0.95), 1) if healthy else None,
        "latency_max_ms": round(max(healthy), 1) if healthy else None,
        "baseline": insights.get("baseline"),
        "change_point": insights.get("change_point"),
        "incidents": incidents(events),
        "anomalies": insights.get("anomalies", []),
    }
    if out.json_mode:
        out.emit_json("history", {"server": {"id": server["id"], "name": server["name"]},
                                  "window_minutes": minutes, "summary": summary,
                                  "events": events})
        return EXIT_OK

    st = out.style
    out.print(f"{st.bold('mcpsonar history')} · {server['name']} · last {args.last}")
    out.print()
    if not events:
        out.print("  No checks in this window.")
        return EXIT_OK
    out.print(f"  checks   {summary['checks']}   uptime {summary['uptime_pct']}%  "
              f"(degraded counts as up; down does not)")
    if healthy:
        out.print(f"  latency  p50 {summary['latency_p50_ms']:.0f} ms · p95 "
                  f"{summary['latency_p95_ms']:.0f} ms · max {summary['latency_max_ms']:.0f} ms")
    if summary["baseline"]:
        out.print(f"  baseline {summary['baseline']['median_ms']:.0f} ms (learned median)")
    cp = summary["change_point"]
    if cp:
        out.print(st.yellow(f"  shift    {cp['before_ms']:.0f} ms → {cp['after_ms']:.0f} ms "
                            f"since {cp['at'][:16].replace('T', ' ')} UTC"))
    out.print()
    incs = summary["incidents"]
    if incs:
        rows = [[i["started"][:19].replace("T", " "), colored(STATUS_WORD[i["worst"]], st),
                 str(i["checks"]),
                 i["recovered"][:19].replace("T", " ") if i["recovered"] else st.red("ongoing"),
                 (i["detail"] or "")[:60]]
                for i in incs]
        out.print(table(["INCIDENT START (UTC)", "WORST", "CHECKS", "RECOVERED", "DETAIL"],
                        rows, st))
    else:
        out.print(f"  {st.green('No incidents')} in this window.")
    if summary["anomalies"]:
        out.print()
        for a in summary["anomalies"][-10:]:
            out.print(f"  {a['checked_at'][:16].replace('T', ' ')}  "
                      f"{a['kind'].replace('_', ' ')}: {a['detail']}")
    return EXIT_OK
