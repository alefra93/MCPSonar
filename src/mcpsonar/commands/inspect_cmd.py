"""``mcpsonar tools`` and ``mcpsonar risks``: what a server exposes right now, and what in
it deserves a human look. Both use :func:`mcpsonar.services.inspect_server` — the same
inspection the dashboard's "Tools" view and ``mcpsonar scan`` run."""

from __future__ import annotations

import json
from typing import Any

from ..lint import RULES, SEVERITY_ORDER, Finding
from ..output import EXIT_ERROR, EXIT_FAILED, EXIT_OK, Output, add_format_args, output_for, table
from ..services import Inspection, inspect_server
from ..tooldefs import fingerprint
from ._target import TargetError, add_target_args, resolve_target

DISCLAIMER = (
    "Findings are heuristic matches on tool-definition text: reasons for a human to review a "
    "tool, not proof of malicious behavior."
)


def register(sub: Any) -> None:
    tools = sub.add_parser(
        "tools",
        help="List the tools a server exposes, with risk indicators.",
        description="Connect once, list every tool (all pages) and show it with its findings. "
        "Exit 0 when the server could be read, 2 when it could not.",
    )
    add_target_args(tools)
    tools.add_argument("--detail", action="store_true",
                       help="Show full descriptions, input/output schemas and annotations.")
    add_format_args(tools)
    tools.set_defaults(handler=run_tools)

    risks = sub.add_parser(
        "risks",
        help="Explain tool-poisoning findings, with evidence and what to review.",
        description="Lint every tool definition and explain each finding. " + DISCLAIMER,
    )
    add_target_args(risks)
    risks.add_argument("--severity", choices=["high", "medium", "low"], default="low",
                       help="Only show findings at or above this severity (default: low).")
    risks.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never",
                       help="Exit 1 if a finding at or above this severity exists "
                       "(default: never — reporting only).")
    add_format_args(risks)
    risks.set_defaults(handler=run_risks)


async def _inspect(args: Any, out: Output) -> Inspection | None:
    try:
        cfg, label = resolve_target(args)
    except TargetError as exc:
        out.error(str(exc))
        return None
    found = await inspect_server(cfg, label, args.timeout)
    if found.error:
        hint = " (pass a token with -H 'Authorization: Bearer <token>')" if found.auth_required else ""
        out.error(f"could not read {label}: {found.error}{hint}")
        return None
    return found


def _server_line(found: Inspection, out: Output) -> str:
    s = out.style
    name = " ".join(filter(None, [found.server_name or "?", found.server_version]))
    return (f"  {s.dim('server')}  {name} · spec {found.spec_version} · "
            f"{len(found.tools)} tools · {found.latency_ms:.0f} ms")


def _worst(findings: list[Finding]) -> str | None:
    return min((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__, default=None)


async def run_tools(args: Any) -> int:
    out = output_for(args)
    found = await _inspect(args, out)
    if found is None:
        return EXIT_ERROR
    if out.json_mode:
        out.emit_json("tools", {
            "target": found.target,
            "server": {"name": found.server_name, "version": found.server_version},
            "spec_version": found.spec_version,
            "latency_ms": round(found.latency_ms, 1),
            "tools": [
                {
                    "name": name,
                    "fingerprint": fingerprint(d),
                    "definition": d,
                    "findings": [f.to_dict() for f in found.tool_findings(name)],
                }
                for name, d in found.tools.items()
            ],
        })
        return EXIT_OK

    s = out.style
    out.print(f"{s.bold('mcpsonar tools')} · {found.target}")
    out.print(_server_line(found, out))
    out.print()
    if not found.tools:
        out.print("  This server exposes no tools.")
        return EXIT_OK
    rows = []
    for name, d in found.tools.items():
        fs = found.tool_findings(name)
        worst = _worst(fs)
        risk = f"{s.severity(worst)} ({len(fs)})" if worst else s.dim("—")
        desc = " ".join((d.get("description") or "").split())
        rows.append([name, risk, desc[:70] + ("…" if len(desc) > 70 else "")])
    if not args.detail:
        out.print(table(["TOOL", "RISK", "DESCRIPTION"], rows, s))
    else:
        for name, d in found.tools.items():
            out.print(s.bold(name) + (f"  ({d['title']})" if d.get("title") else ""))
            out.print(f"  {d.get('description') or s.dim('(no description)')}")
            for key in ("inputSchema", "outputSchema", "annotations"):
                if d.get(key):
                    body = json.dumps(d[key], indent=2, ensure_ascii=False)
                    out.print(f"  {s.dim(key)}:")
                    out.print("\n".join("    " + line for line in body.splitlines()))
            for f in found.tool_findings(name):
                out.print(f"  {s.severity(f.severity)} {f.rule} — {f.message}")
            out.print()
    risky = sum(1 for n in found.tools if found.tool_findings(n))
    if risky:
        out.print()
        out.print(f"  {risky} tool(s) with findings — run `mcpsonar risks` for explanations.")
    return EXIT_OK


async def run_risks(args: Any) -> int:
    out = output_for(args)
    found = await _inspect(args, out)
    if found is None:
        return EXIT_ERROR
    limit = SEVERITY_ORDER[args.severity]
    shown = [f for f in found.findings if SEVERITY_ORDER[f.severity] <= limit]
    failed = args.fail_on != "never" and any(
        SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[args.fail_on] for f in found.findings
    )
    code = EXIT_FAILED if failed else EXIT_OK

    if out.json_mode:
        out.emit_json("risks", {
            "target": found.target,
            "disclaimer": DISCLAIMER,
            "findings": [
                {
                    **f.to_dict(),
                    "evidence": f.excerpt,
                    "title": RULES[f.rule].title if f.rule in RULES else f.rule,
                    "explanation": RULES[f.rule].explanation if f.rule in RULES else f.message,
                    "remediation": RULES[f.rule].remediation if f.rule in RULES else None,
                }
                for f in shown
            ],
        })
        return code

    s = out.style
    out.print(f"{s.bold('mcpsonar risks')} · {found.target}")
    out.print(_server_line(found, out))
    out.print()
    if not shown:
        out.print(f"  {s.green('No findings')} at or above {args.severity} severity "
                  f"in {len(found.tools)} tools.")
    for f in shown:
        info = RULES.get(f.rule)
        out.print(f"  {s.severity(f.severity, 6)} "
                  f"{s.bold(f.rule)} · tool {s.bold(f.tool)} · {f.location}")
        out.print(f"         {info.explanation if info else f.message}")
        out.print(f"         {s.dim('evidence:')} {f.excerpt}")
        if info:
            out.print(f"         {s.dim('review:')}   {info.remediation}")
        out.print()
    counts = {k: sum(1 for f in shown if f.severity == k) for k in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n) or "no findings"
    out.print(f"  {summary}. {s.dim(DISCLAIMER)}")
    return code
