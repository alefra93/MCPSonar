"""In-process management dashboard.

A single self-contained page (inlined CSS + vanilla JS, no external assets, no build step)
that lets a user add, edit, pause, delete and re-check MCP servers from the browser and watch
their live status, heartbeat and history — the Uptime-Kuma experience, but MCP-aware. It talks
to the CRUD API (see :mod:`mcpsonar.api`); adding a server starts checks immediately.

Also serves ``/api/status`` (live state + recent heartbeat for polling) and Prometheus
``/metrics``.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .adapters import CONTENT_TYPE, render_metrics
from .api import register_api
from .auth import CookieSecure, register_auth
from .redact import redact_url
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage
from .websec import DEFAULT_MAX_BODY_BYTES, install_web_security

_HEARTBEAT_POINTS = 40


def create_app(
    storage: Storage,
    store: StateStore,
    scheduler: Scheduler,
    require_auth: bool = True,
    *,
    setup_token: str | None = None,
    cookie_secure: CookieSecure = "auto",
    allowed_hosts: list[str] | None = None,
    trusted_origins: Iterable[str] = (),
    allow_stdio_api: bool | None = None,
    metrics_token: str | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> FastAPI:
    """Build the dashboard/API app.

    ``allow_stdio_api`` (default: ``require_auth``) decides whether stdio servers — which
    make mcpsonar launch a command — may be created or changed over the HTTP API. Without a
    login, anyone who can reach the port could otherwise run commands on this host; stdio
    servers can still come from the seed YAML (``--config``).
    """
    app = FastAPI(title="mcpsonar", docs_url=None, redoc_url=None)
    register_auth(app, storage, require_auth, setup_token=setup_token,
                  cookie_secure=cookie_secure)
    register_api(app, storage, store, scheduler,
                 allow_stdio=require_auth if allow_stdio_api is None else allow_stdio_api)
    install_web_security(app, allowed_hosts=allowed_hosts, trusted_origins=trusted_origins,
                         max_body_bytes=max_body_bytes)

    @app.get("/api/status")
    async def api_status() -> JSONResponse:
        snap = store.snapshot()
        servers = await storage.list_servers()
        out: dict = {}
        for s in servers:
            recent = await storage.get_history(s.id, limit=_HEARTBEAT_POINTS)
            last_anomaly = next(
                (
                    {"checked_at": e.checked_at.isoformat(), **e.anomalies[-1].model_dump()}
                    for e in reversed(recent)
                    if e.anomalies
                ),
                None,
            )
            out[s.id] = {
                "name": s.name,
                "enabled": s.enabled,
                "transport": s.transport.value,
                "target": redact_url(s.url) or s.command or "",
                "event": snap[s.id].model_dump(mode="json") if s.id in snap else None,
                "recent": [
                    {
                        "status": e.status.value,
                        "latency_ms": e.latency_ms,
                        "anomalies": [a.kind for a in e.anomalies],
                    }
                    for e in recent
                ],
                "last_anomaly": last_anomaly,
            }
        return JSONResponse(out)

    @app.get("/metrics")
    async def metrics(request: Request) -> PlainTextResponse:
        if metrics_token is not None:
            given = request.headers.get("authorization", "")
            if not hmac.compare_digest(given.encode(), f"Bearer {metrics_token}".encode()):
                return PlainTextResponse(
                    "bearer token required", status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        servers = await storage.list_servers()
        return PlainTextResponse(render_metrics(servers, store), media_type=CONTENT_TYPE)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(_PAGE)

    return app


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcpsonar</title>
<style>
  :root{
    --bg:#f1f4f9; --surface:#ffffff; --surface-2:#f6f9fc; --elev:#ffffff;
    --border:#e4e9f2; --border-strong:#d2dbe8;
    --text:#0e1a2b; --muted:#5b6b83; --faint:#93a1b6;
    --accent:#0d9488; --accent-strong:#0f766e; --accent-ink:#ffffff; --accent-soft:rgba(13,148,136,.10);
    --up:#15a34a; --degraded:#d97706; --down:#dc2626; --pending:#6b7a92; --anom:#7c3aed;
    --shadow:0 1px 2px rgba(14,26,43,.05), 0 10px 26px rgba(14,26,43,.06);
    --shadow-lg:0 24px 70px rgba(14,26,43,.24);
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --r:12px;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#070c15; --surface:#0f1826; --surface-2:#131f30; --elev:#14202f;
      --border:#1f2b3e; --border-strong:#2c3c54;
      --text:#e7eefb; --muted:#93a3bd; --faint:#5f708a;
      --accent:#2dd4bf; --accent-strong:#5eead4; --accent-ink:#04120f; --accent-soft:rgba(45,212,191,.12);
      --up:#34d399; --degraded:#fbbf24; --down:#f87171; --pending:#7c8aa5; --anom:#a78bfa;
      --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 32px rgba(0,0,0,.38);
      --shadow-lg:0 28px 80px rgba(0,0,0,.62);
    }
  }
  :root[data-theme="light"]{
    --bg:#f1f4f9; --surface:#ffffff; --surface-2:#f6f9fc; --elev:#ffffff;
    --border:#e4e9f2; --border-strong:#d2dbe8; --text:#0e1a2b; --muted:#5b6b83; --faint:#93a1b6;
    --accent:#0d9488; --accent-strong:#0f766e; --accent-ink:#ffffff; --accent-soft:rgba(13,148,136,.10);
    --up:#15a34a; --degraded:#d97706; --down:#dc2626; --pending:#6b7a92; --anom:#7c3aed;
    --shadow:0 1px 2px rgba(14,26,43,.05), 0 10px 26px rgba(14,26,43,.06);
    --shadow-lg:0 24px 70px rgba(14,26,43,.24);
  }
  :root[data-theme="dark"]{
    --bg:#070c15; --surface:#0f1826; --surface-2:#131f30; --elev:#14202f;
    --border:#1f2b3e; --border-strong:#2c3c54; --text:#e7eefb; --muted:#93a3bd; --faint:#5f708a;
    --accent:#2dd4bf; --accent-strong:#5eead4; --accent-ink:#04120f; --accent-soft:rgba(45,212,191,.12);
    --up:#34d399; --degraded:#fbbf24; --down:#f87171; --pending:#7c8aa5; --anom:#a78bfa;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 32px rgba(0,0,0,.38);
    --shadow-lg:0 28px 80px rgba(0,0,0,.62);
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.45;
       -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
  .num{font-variant-numeric:tabular-nums;}
  ::selection{background:var(--accent-soft);}

  /* top bar */
  .topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:14px;
       padding:14px 26px;background:color-mix(in srgb,var(--surface) 88%,transparent);
       backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--border);}
  .brand{display:flex;align-items:center;gap:12px;margin-right:auto;}
  .logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:20px;
       background:linear-gradient(150deg,var(--accent),var(--accent-strong));
       box-shadow:0 6px 18px var(--accent-soft), inset 0 1px 0 rgba(255,255,255,.25);}
  .brand h1{margin:0;font-size:17px;font-weight:700;letter-spacing:-.02em;}
  .brand .live{display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);margin-top:1px;}
  .ping{width:7px;height:7px;border-radius:50%;background:var(--accent);position:relative;}
  .ping::after{content:"";position:absolute;inset:-4px;border-radius:50%;border:1px solid var(--accent);
       animation:ping 1.9s ease-out infinite;}
  @keyframes ping{0%{transform:scale(.6);opacity:.8}100%{transform:scale(1.9);opacity:0}}
  @media (prefers-reduced-motion:reduce){.ping::after{animation:none;}}

  .btn{font:inherit;font-size:13.5px;font-weight:550;cursor:pointer;border:1px solid var(--border-strong);
       background:var(--surface);color:var(--text);border-radius:9px;padding:8px 13px;
       display:inline-flex;align-items:center;gap:7px;transition:all .14s ease;}
  .btn:hover{border-color:var(--accent);color:var(--accent-strong);transform:translateY(-1px);}
  .btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
  .btn.primary{background:linear-gradient(150deg,var(--accent),var(--accent-strong));
       border-color:transparent;color:var(--accent-ink);box-shadow:0 6px 16px var(--accent-soft);}
  .btn.primary:hover{color:var(--accent-ink);filter:brightness(1.06);}
  .btn.icon{padding:8px 10px;}
  .whoami{font-size:12.5px;color:var(--muted);display:inline-flex;align-items:center;gap:6px;}
  .whoami .av{width:22px;height:22px;border-radius:50%;background:var(--accent-soft);color:var(--accent-strong);
       display:grid;place-items:center;font-weight:700;font-size:11px;text-transform:uppercase;}

  main{max-width:1120px;margin:0 auto;padding:26px 26px 70px;}

  /* summary tiles */
  .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:14px;margin-bottom:24px;}
  .tile{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:15px 17px;
       box-shadow:var(--shadow);position:relative;overflow:hidden;}
  .tile .k{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:600;}
  .tile .v{font-size:27px;font-weight:750;letter-spacing:-.02em;margin-top:4px;}
  .tile .rail{position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--faint);}
  .tile.up .rail{background:var(--up);} .tile.degraded .rail{background:var(--degraded);}
  .tile.down .rail{background:var(--down);} .tile.accent .rail{background:var(--accent);}

  .board-head{display:flex;align-items:baseline;justify-content:space-between;margin:0 2px 12px;}
  .board-head h2{margin:0;font-size:15px;font-weight:650;letter-spacing:-.01em;}
  .board-head .hint{font-size:12px;color:var(--faint);}

  /* server cards */
  .cards{display:flex;flex-direction:column;gap:12px;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
       padding:15px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden;
       transition:border-color .15s,transform .15s,box-shadow .15s;}
  .card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--pending);opacity:.9;}
  .card.up::before{background:var(--up);} .card.degraded::before{background:var(--degraded);}
  .card.down::before{background:var(--down);} .card.pending::before{background:var(--faint);}
  .card:hover{border-color:var(--border-strong);transform:translateY(-1px);box-shadow:var(--shadow-lg);}
  /* card = 3 stacked rows: header (name/status), heartbeat, footer (meta/actions) */
  .chead{display:flex;align-items:center;gap:10px;}
  .sdot{width:10px;height:10px;border-radius:50%;flex:none;}
  .sdot.up{background:var(--up);box-shadow:0 0 0 4px color-mix(in srgb,var(--up) 22%,transparent);}
  .sdot.degraded{background:var(--degraded);box-shadow:0 0 0 4px color-mix(in srgb,var(--degraded) 22%,transparent);}
  .sdot.down{background:var(--down);box-shadow:0 0 0 4px color-mix(in srgb,var(--down) 22%,transparent);}
  .sdot.pending{background:var(--faint);}
  .cname{font-weight:650;font-size:14.5px;flex:1 1 auto;min-width:0;white-space:nowrap;
       overflow:hidden;text-overflow:ellipsis;}
  .cname .paused{color:var(--faint);font-weight:500;font-size:12px;margin-left:6px;}
  .tport{font-family:var(--mono);font-size:10px;color:var(--accent-strong);background:var(--accent-soft);
       padding:2px 7px;border-radius:5px;text-transform:uppercase;letter-spacing:.03em;flex:none;}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 11px 4px 9px;border-radius:999px;
       font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex:none;}
  .pill .d{width:6px;height:6px;border-radius:50%;background:currentColor;}
  .pill.up{color:var(--up);background:color-mix(in srgb,var(--up) 13%,transparent);}
  .pill.degraded{color:var(--degraded);background:color-mix(in srgb,var(--degraded) 15%,transparent);}
  .pill.down{color:var(--down);background:color-mix(in srgb,var(--down) 13%,transparent);}
  .pill.pending{color:var(--pending);background:color-mix(in srgb,var(--pending) 14%,transparent);}
  .lat{font-weight:700;font-size:14px;flex:none;min-width:56px;text-align:right;}

  .heartbeat{display:flex;gap:2px;align-items:center;height:30px;width:100%;margin-top:12px;overflow:hidden;}
  .hb{flex:1 1 0;min-width:2px;height:26px;border-radius:2px;}
  .hb.empty{background:var(--border);opacity:.55;height:13px;}

  .cfoot{display:flex;align-items:center;justify-content:space-between;gap:8px 16px;flex-wrap:wrap;
       margin-top:12px;padding-top:11px;border-top:1px dashed var(--border);}
  .meta{display:flex;flex-wrap:wrap;gap:4px 15px;font-size:12px;color:var(--muted);min-width:0;}
  .meta b{color:var(--text);font-weight:600;}
  .target,.spec{font-family:var(--mono);}
  .spec .unk{font-family:var(--sans);color:var(--degraded);}
  .detail{color:var(--down);}
  .tlink{cursor:pointer;}
  .tlink:hover{color:var(--accent-strong);}
  .toollist{display:flex;flex-direction:column;gap:8px;max-height:54vh;overflow:auto;}
  .toolitem{padding:10px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;}
  .toolitem .tn{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--accent-strong);}
  .toolitem .td{font-size:12.5px;color:var(--muted);margin-top:3px;}
  .acts{display:flex;gap:2px;flex:none;}
  .act{border:none;background:none;font:inherit;font-size:12.5px;cursor:pointer;color:var(--muted);
       padding:5px 9px;border-radius:7px;transition:all .12s;}
  .act:hover{background:var(--surface-2);color:var(--accent-strong);}
  .act.danger{color:var(--down);opacity:.8;}
  .act.danger:hover{background:color-mix(in srgb,var(--down) 12%,transparent);opacity:1;}
  .act:focus-visible{outline:2px solid var(--accent);outline-offset:1px;}
  .empty{background:var(--surface);border:1px dashed var(--border-strong);border-radius:var(--r);
       padding:44px 20px;text-align:center;color:var(--muted);}
  .empty .big{font-size:34px;margin-bottom:8px;}

  /* modal */
  .overlay{position:fixed;inset:0;background:color-mix(in srgb,#04070d 55%,transparent);
       backdrop-filter:blur(3px);display:none;align-items:flex-start;justify-content:center;
       padding:7vh 16px 16px;z-index:50;}
  .overlay.open{display:flex;animation:fade .16s ease;}
  @keyframes fade{from{opacity:0}to{opacity:1}}
  .modal{background:var(--elev);border:1px solid var(--border);border-radius:16px;width:min(560px,96vw);
       padding:24px 26px;box-shadow:var(--shadow-lg);max-height:86vh;overflow:auto;}
  .modal.wide{width:min(680px,96vw);}
  .modal h2{margin:0 0 3px;font-size:18px;letter-spacing:-.01em;}
  .modal .lead{color:var(--muted);font-size:13px;margin:0 0 18px;}
  .field{margin-bottom:13px;}
  .field label{display:block;font-size:12.5px;font-weight:600;margin-bottom:5px;}
  .field label code{font-family:var(--mono);font-size:11px;background:var(--surface-2);padding:1px 5px;border-radius:4px;}
  .field input,.field select,.field textarea{width:100%;padding:9px 12px;border:1px solid var(--border-strong);
       border-radius:9px;font:inherit;font-size:13.5px;background:var(--surface-2);color:var(--text);
       transition:border-color .12s,box-shadow .12s;}
  .field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:var(--accent);
       box-shadow:0 0 0 3px var(--accent-soft);}
  .field textarea{font-family:var(--mono);font-size:12.5px;resize:vertical;}
  .row2{display:flex;gap:12px;} .row2>*{flex:1;}
  .toklist{display:flex;flex-direction:column;gap:8px;margin:0 0 16px;}
  .tok{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--border);
       border-radius:10px;background:var(--surface-2);font-size:13px;}
  .tok .nm{font-weight:650;} .tok .meta{color:var(--muted);font-size:12px;margin-right:auto;}
  .newtok{font-family:var(--mono);font-size:12px;word-break:break-all;padding:10px 12px;
       border:1px dashed var(--accent);border-radius:10px;background:var(--accent-soft);margin:0 0 14px;}
  .buttons{display:flex;justify-content:flex-end;gap:10px;margin-top:10px;}
  .err{color:var(--down);font-size:13px;min-height:18px;margin-top:6px;}
  .ranges{display:flex;gap:4px;margin-bottom:14px;background:var(--surface-2);padding:3px;border-radius:9px;width:max-content;}
  .ranges .rbtn{border:none;background:none;font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);
       padding:5px 12px;border-radius:7px;cursor:pointer;}
  .ranges .rbtn.on,.ranges .rbtn:hover{background:var(--surface);color:var(--accent-strong);box-shadow:var(--shadow);}
  .stats{display:flex;gap:24px;margin-bottom:16px;flex-wrap:wrap;}
  .stats .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;}
  .stats .v{font-size:20px;font-weight:750;letter-spacing:-.02em;}
  .clabel{font-size:11px;color:var(--muted);margin:12px 0 4px;text-transform:uppercase;letter-spacing:.04em;}

  /* security + anomaly badges */
  .badges{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;}
  .badges:empty{display:none;}
  .badge{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:11.5px;font-weight:650;
       padding:4px 10px;border-radius:7px;border:1px solid transparent;cursor:pointer;line-height:1.3;}
  .badge.warn{color:var(--down);background:color-mix(in srgb,var(--down) 11%,transparent);
       border-color:color-mix(in srgb,var(--down) 30%,transparent);}
  .badge.risk{color:var(--degraded);background:color-mix(in srgb,var(--degraded) 12%,transparent);
       border-color:color-mix(in srgb,var(--degraded) 30%,transparent);}
  .badge.anom{color:var(--anom);background:color-mix(in srgb,var(--anom) 11%,transparent);
       border-color:color-mix(in srgb,var(--anom) 28%,transparent);}
  .badge.lock{color:var(--muted);background:var(--surface-2);border-color:var(--border-strong);cursor:default;}
  .badge:hover{filter:brightness(1.08);}
  .badge .when{font-weight:500;opacity:.8;}
  .tile.warn .rail{background:var(--down);} .tile.anom .rail{background:var(--anom);}

  /* tool changes (diff) */
  .chg{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden;}
  .chg-h{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--surface-2);
       border-bottom:1px solid var(--border);font-size:12.5px;flex-wrap:wrap;}
  .chg-h .tn{font-family:var(--mono);font-weight:650;color:var(--text);}
  .chg-h .when{margin-left:auto;color:var(--faint);}
  .kind{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:5px;}
  .kind.added{color:var(--up);background:color-mix(in srgb,var(--up) 13%,transparent);}
  .kind.removed{color:var(--down);background:color-mix(in srgb,var(--down) 13%,transparent);}
  .kind.changed{color:var(--degraded);background:color-mix(in srgb,var(--degraded) 14%,transparent);}
  .chg-b{padding:10px 12px;font-size:12.5px;}
  .chg-b .fl{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:650;margin:8px 0 4px;}
  .chg-b .fl:first-child{margin-top:0;}
  .diff{font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word;line-height:1.55;
       background:var(--surface-2);border:1px solid var(--border);border-radius:7px;padding:8px 10px;max-height:260px;overflow:auto;}
  .diff del{background:color-mix(in srgb,var(--down) 20%,transparent);color:var(--down);text-decoration:line-through;border-radius:3px;}
  .diff ins{background:color-mix(in srgb,var(--up) 20%,transparent);color:var(--up);text-decoration:none;border-radius:3px;}
  .diff .ln-del{display:block;background:color-mix(in srgb,var(--down) 13%,transparent);color:var(--down);}
  .diff .ln-ins{display:block;background:color-mix(in srgb,var(--up) 13%,transparent);color:var(--up);}
  .diff .ln-eq{display:block;color:var(--muted);}
  .okmsg{padding:18px;text-align:center;color:var(--muted);}

  /* lint findings */
  .findings{margin-top:8px;display:flex;flex-direction:column;gap:5px;}
  .finding{font-size:12px;display:flex;gap:8px;align-items:baseline;}
  .sev{font-size:10px;font-weight:750;text-transform:uppercase;padding:1px 6px;border-radius:4px;flex:none;}
  .sev.high{color:var(--down);background:color-mix(in srgb,var(--down) 14%,transparent);}
  .sev.medium{color:var(--degraded);background:color-mix(in srgb,var(--degraded) 15%,transparent);}
  .sev.low{color:var(--muted);background:var(--border);}
  .finding code{font-family:var(--mono);font-size:11px;color:var(--muted);word-break:break-word;}
  .toolitem.risky{border-color:color-mix(in srgb,var(--degraded) 45%,transparent);}

  /* history anomalies */
  .alist{display:flex;flex-direction:column;gap:6px;margin-top:6px;max-height:180px;overflow:auto;}
  .aitem{font-size:12.5px;display:flex;gap:8px;align-items:baseline;}
  .aitem .t{color:var(--faint);font-family:var(--mono);font-size:11px;flex:none;}
  .legend{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-top:6px;}
  .legend i{display:inline-block;width:14px;height:8px;border-radius:2px;margin-right:5px;vertical-align:middle;}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="logo">🛰️</div>
    <div><h1>mcpsonar</h1><div class="live"><span class="ping"></span><span id="sub">connecting…</span></div></div>
  </div>
  <span class="whoami" id="whoami"></span>
  <button class="btn icon" id="themeBtn" title="Toggle theme" onclick="toggleTheme()">🌙</button>
  <button class="btn" onclick="location.href='/api/export'">Export</button>
  <button class="btn" onclick="openImport()">Import</button>
  <button class="btn primary" onclick="openForm()">＋ Add server</button>
  <button class="btn" id="tokensBtn" style="display:none" onclick="openTokens()">API tokens</button>
  <button class="btn" id="logoutBtn" style="display:none" onclick="logout()">Logout</button>
</div>

<main>
  <div class="summary" id="summary"></div>
  <div class="board-head"><h2>Monitored servers</h2><span class="hint">auto-refresh · 5s</span></div>
  <div class="cards" id="rows"><div class="empty">Loading…</div></div>
</main>

<div class="overlay" id="overlay">
  <div class="modal">
    <h2 id="formTitle">Add server</h2>
    <p class="lead">Adding a server starts checking it immediately — no restart.</p>
    <input type="hidden" id="f_id">
    <div class="field"><label>Name</label><input id="f_name" placeholder="My MCP server"></div>
    <div class="row2">
      <div class="field"><label>Transport</label>
        <select id="f_transport" onchange="onTransport()">
          <option value="http">http (Streamable HTTP)</option>
          <option value="sse">sse (legacy)</option>
          <option value="stdio">stdio (local process)</option></select></div>
      <div class="field"><label>Interval (s)</label><input id="f_interval" type="number" value="60"></div>
    </div>
    <div id="grpHttp">
      <div class="field"><label>URL</label><input id="f_url" placeholder="https://example.com/mcp"></div>
      <div class="field"><label>Headers (optional — one per line: <code>Key: Value</code>)</label>
        <textarea id="f_headers" rows="2" placeholder="Authorization: Bearer &lt;token&gt;"></textarea></div>
    </div>
    <div id="grpStdio" style="display:none">
      <div class="field"><label>Command</label><input id="f_command" placeholder="npx"></div>
      <div class="field"><label>Arguments (space-separated)</label>
        <input id="f_args" placeholder="-y @modelcontextprotocol/server-everything"></div>
      <div class="field"><label>Environment (optional — one per line: <code>KEY=value</code>)</label>
        <textarea id="f_env" rows="2" placeholder="API_TOKEN=..."></textarea></div>
    </div>
    <div class="field"><label>Tools to test (comma-separated, optional)</label>
      <input id="f_tools" placeholder="ping, health"></div>
    <div class="row2">
      <div class="field"><label>Degraded latency (ms)</label><input id="f_deg" type="number" value="2000"></div>
      <div class="field"><label>Down latency (ms)</label><input id="f_down" type="number" value="10000"></div>
    </div>
    <div class="row2">
      <div class="field"><label>When tool definitions change</label>
        <select id="f_toolpol">
          <option value="degrade">Degrade until reviewed (recommended)</option>
          <option value="alert">Alert only</option>
          <option value="ignore">Ignore (no pinning)</option></select></div>
      <div class="field"><label>Anomaly sensitivity (σ)</label><input id="f_sens" type="number" step="0.5" value="4"></div>
    </div>
    <div class="err" id="formErr"></div>
    <div class="buttons">
      <button class="btn" onclick="closeForm()">Cancel</button>
      <button class="btn primary" onclick="saveForm()">Save server</button>
    </div>
  </div>
</div>

<div class="overlay" id="histOverlay">
  <div class="modal wide">
    <h2 id="histTitle">History</h2>
    <div class="ranges" style="margin-top:14px">
      <button class="rbtn" onclick="loadHistory(60,this)">1h</button>
      <button class="rbtn on" onclick="loadHistory(360,this)">6h</button>
      <button class="rbtn" onclick="loadHistory(1440,this)">24h</button>
      <button class="rbtn" onclick="loadHistory(null,this)">All</button>
    </div>
    <div id="histBody"><p class="muted">Loading…</p></div>
    <div class="buttons"><button class="btn" onclick="closeHistory()">Close</button></div>
  </div>
</div>

<div class="overlay" id="toolsOverlay">
  <div class="modal">
    <h2 id="toolsTitle">Tools</h2>
    <p class="lead">The tools this server exposes right now (queried live via tools/list).</p>
    <div id="toolsBody"><p class="muted">Loading…</p></div>
    <div class="buttons"><button class="btn" onclick="closeTools()">Close</button></div>
  </div>
</div>

<div class="overlay" id="changesOverlay">
  <div class="modal wide">
    <h2 id="changesTitle">Tool changes</h2>
    <p class="lead">mcpsonar pinned this server's tool definitions the first time it saw them.
      These are the differences since then — a changed description or schema is exactly how a
      "rug pull" or a tool-poisoning attack reaches your agents. Review, then approve.</p>
    <div class="ranges">
      <button class="rbtn on" id="chgPending" onclick="loadChanges(false)">Pending</button>
      <button class="rbtn" id="chgAll" onclick="loadChanges(true)">All history</button>
    </div>
    <div id="changesBody"><p class="muted">Loading…</p></div>
    <div class="err" id="changesErr"></div>
    <div class="buttons">
      <button class="btn" onclick="closeChanges()">Close</button>
      <button class="btn primary" id="ackBtn" onclick="ackChanges()">✓ Approve changes</button>
    </div>
  </div>
</div>

<div class="overlay" id="tokensOverlay">
  <div class="modal">
    <h2>API tokens</h2>
    <p class="lead">For the <code>mcpsonar</code> CLI and scripts: set <code>MCPSONAR_URL</code>
      and <code>MCPSONAR_TOKEN</code>. A token is shown once; only its hash is stored.
      <b>read</b> tokens can only read; <b>write</b> tokens can also change servers.</p>
    <div class="toklist" id="tokList"></div>
    <div id="newTok" class="newtok" style="display:none"></div>
    <div class="row2">
      <div class="field"><label>Name</label><input id="t_name" placeholder="laptop-cli"></div>
      <div class="field"><label>Scope</label>
        <select id="t_scope"><option value="read">read</option><option value="write">write</option></select></div>
      <div class="field"><label>Expires in (days)</label><input id="t_days" type="number" min="1" placeholder="never"></div>
    </div>
    <div class="err" id="tokErr"></div>
    <div class="buttons">
      <button class="btn" onclick="closeTokens()">Close</button>
      <button class="btn primary" onclick="createToken()">Create token</button>
    </div>
  </div>
</div>

<div class="overlay" id="importOverlay">
  <div class="modal">
    <h2>Import servers</h2>
    <p class="lead">Paste a YAML config or choose a file — each server is created and started.</p>
    <div class="field">
      <input type="file" id="importFile" accept=".yaml,.yml" onchange="loadFile(event)">
    </div>
    <div class="field">
      <textarea id="importText" rows="10"
        placeholder="servers:&#10;  my-server:&#10;    url: https://example.com/mcp"></textarea>
    </div>
    <div class="err" id="importErr"></div>
    <div class="buttons">
      <button class="btn" onclick="closeImport()">Cancel</button>
      <button class="btn primary" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const sc = s => css(s==="up"?"--up":s==="degraded"?"--degraded":s==="down"?"--down":"--pending");

/* theme */
function applyTheme(t){ if(t){document.documentElement.setAttribute("data-theme",t);}
  else{document.documentElement.removeAttribute("data-theme");}
  const dark = (t||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light"))==="dark";
  $("themeBtn").textContent = dark ? "☀️" : "🌙"; }
function toggleTheme(){ const cur=localStorage.getItem("mcpsonar-theme");
  const dark=(cur||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light"))==="dark";
  const next=dark?"light":"dark"; localStorage.setItem("mcpsonar-theme",next); applyTheme(next); }
applyTheme(localStorage.getItem("mcpsonar-theme"));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"]="application/json"; opt.body=JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) { let d; try { d = await r.json(); } catch(e){}
    throw new Error(d && d.detail ? JSON.stringify(d.detail) : (r.status+" "+r.statusText)); }
  return r.status === 204 ? null : r.json();
}

function relTime(iso){
  const d=(Date.now()-new Date(iso).getTime())/1000;
  if(d<5) return "just now"; if(d<60) return Math.floor(d)+"s ago";
  if(d<3600) return Math.floor(d/60)+"m ago"; if(d<86400) return Math.floor(d/3600)+"h ago";
  return Math.floor(d/86400)+"d ago";
}
function heartbeat(recent){
  const N=40, arr=(recent||[]).slice(-N), pad=N-arr.length;
  let bars="";
  for(let i=0;i<pad;i++) bars+='<span class="hb empty"></span>';
  const anom=css("--anom");
  arr.forEach(e=>{
    const a=(e.anomalies||[]).length;
    const bg=a?`linear-gradient(${anom} 0 6px, ${sc(e.status)} 6px)`:sc(e.status);
    bars+=`<span class="hb" style="background:${bg}" `+
      `title="${e.status} · ${Math.round(e.latency_ms)}ms${a?" · "+e.anomalies.join(", ").replace(/_/g," "):""}"></span>`; });
  return `<div class="heartbeat">${bars}</div>`;
}
function pill(status){ return `<span class="pill ${status}"><span class="d"></span>${status}</span>`; }

function renderSummary(list){
  const n=list.length, c={up:0,degraded:0,down:0};
  let latSum=0, latN=0;
  list.forEach(s=>{ const ev=s.event; if(ev){ if(c[ev.status]!=null)c[ev.status]++;
    if(ev.status!=="down"){latSum+=ev.latency_ms;latN++;} }});
  const avg = latN?Math.round(latSum/latN)+" ms":"—";
  const changes=list.reduce((a,s)=>a+(s.event?s.event.tool_changes||0:0),0);
  const anoms=list.reduce((a,s)=>a+(s.recent||[]).filter(e=>(e.anomalies||[]).length).length,0);
  const tile=(cls,k,v)=>`<div class="tile ${cls}"><span class="rail"></span><div class="k">${k}</div><div class="v num">${v}</div></div>`;
  $("summary").innerHTML =
    tile("accent","Servers",n)+tile("up","Up",c.up)+tile("degraded","Degraded",c.degraded)+
    tile("down","Down",c.down)+tile("accent","Avg latency",avg)+
    tile(changes?"warn":"","Tool changes",changes)+tile(anoms?"anom":"","Anomalies",anoms);
}

let SERVERS = {};
async function refresh() {
  let data;
  try { data = await api("GET", "/api/status"); } catch(e) { return; }
  const ids = Object.keys(data);
  const list = ids.map(id=>({id, ...data[id]}));
  SERVERS = {}; list.forEach(s=>SERVERS[s.id]=s.name);
  $("sub").textContent = ids.length ? (ids.length+" server"+(ids.length===1?"":"s")+" · Live") : "No servers yet";
  renderSummary(list);
  const tb = $("rows");
  if (!ids.length) {
    tb.innerHTML = '<div class="empty"><div class="big">🛰️</div>No servers yet.<br>Click <b>＋ Add server</b> to start monitoring an MCP.</div>';
    return;
  }
  tb.innerHTML = list.map(s => {
    const ev=s.event, status=ev?ev.status:"pending";
    const latency = ev ? Math.round(ev.latency_ms)+" ms" : "—";
    let spec = "—";
    if (ev && ev.spec_version){ spec=esc(ev.spec_version);
      if(!ev.spec_version_supported) spec+=' <span class="unk">unrecognized</span>'; }
    const tAvail = ev ? ev.tools_available : "—";
    const probed = ev && ev.tools_checked
      ? ` · ${ev.tools_checked-ev.tools_failed}/${ev.tools_checked} probed ok` : "";
    const when = ev ? relTime(ev.checked_at) : "never";
    const dcol = ev && ev.status==="up" ? "var(--muted)" : ev && ev.status==="degraded" ? "var(--degraded)" : "var(--down)";
    const detail = ev && ev.detail ? ` · <span class="detail" style="color:${dcol}">${esc(ev.detail)}</span>` : "";
    const paused = s.enabled ? "" : '<span class="paused">paused</span>';
    const baseline = ev && ev.latency_baseline_ms!=null
      ? `<span>baseline <b>${Math.round(ev.latency_baseline_ms)} ms</b></span>` : "";
    let badges = "";
    if (ev && ev.auth_required) badges += `<span class="badge lock" title="${esc(ev.detail||"")}">🔒 auth required · tools not visible</span>`;
    if (ev && ev.tool_changes) badges += `<button class="badge warn" onclick="openChanges('${s.id}')">⚠ ${ev.tool_changes} tool change${ev.tool_changes===1?"":"s"} · Review</button>`;
    if (ev && ev.tool_risks) badges += `<button class="badge risk" onclick="openTools('${s.id}')">🛡 ${ev.tool_risks} suspicious tool finding${ev.tool_risks===1?"":"s"}</button>`;
    const la = s.last_anomaly;
    if (la && la.kind!=="tool_change") badges += `<button class="badge anom" onclick="openHistory('${s.id}')">📈 ${esc(la.detail)} <span class="when">· ${relTime(la.checked_at)}</span></button>`;
    return `<div class="card ${status}">
      <div class="chead">
        <span class="sdot ${status}"></span>
        <span class="cname">${esc(s.name)}${paused}</span>
        <span class="tport">${esc(s.transport)}</span>
        ${pill(status)}
        <span class="lat num">${latency}</span>
      </div>
      ${heartbeat(s.recent)}
      <div class="badges">${badges}</div>
      <div class="cfoot">
        <div class="meta">
          <span class="target">${esc(s.target)}</span>
          <span class="spec">spec ${spec}</span>
          ${baseline}
          <span class="tlink" onclick="openTools('${s.id}')">🔧 <b>${tAvail}</b> tools${probed}</span>
          <span>checked <b>${when}</b>${detail}</span>
        </div>
        <div class="acts">
          <button class="act" onclick="openTools('${s.id}')">Tools</button>
          <button class="act" onclick="openChanges('${s.id}')">Changes</button>
          <button class="act" onclick="openHistory('${s.id}')">History</button>
          <button class="act" onclick="checkNow('${s.id}')">Check</button>
          <button class="act" onclick="editServer('${s.id}')">Edit</button>
          <button class="act" onclick="togglePause('${s.id}',${s.enabled})">${s.enabled?"Pause":"Resume"}</button>
          <button class="act danger" onclick="del('${s.id}')">Delete</button>
        </div>
      </div>
    </div>`;
  }).join("");
}

/* form */
function onTransport(){
  const stdio = $("f_transport").value === "stdio";
  $("grpStdio").style.display = stdio ? "" : "none";
  $("grpHttp").style.display  = stdio ? "none" : "";
}
function parseLines(text, sep){
  const out={};
  text.split("\n").map(l=>l.trim()).filter(Boolean).forEach(l=>{
    const i=l.indexOf(sep); if(i<0) return;
    out[l.slice(0,i).trim()]=l.slice(i+sep.length).trim();
  });
  return out;
}
function dumpLines(obj, sep){ return Object.entries(obj||{}).map(([k,v])=>k+sep+v).join("\n"); }

function openForm() {
  $("formTitle").textContent = "Add server";
  ["f_id","f_name","f_url","f_headers","f_command","f_args","f_env","f_tools"].forEach(i=>$(i).value="");
  $("f_transport").value="http"; onTransport();
  $("f_interval").value=60; $("f_deg").value=2000; $("f_down").value=10000;
  $("f_toolpol").value="degrade"; $("f_sens").value=4;
  $("formErr").textContent=""; $("overlay").classList.add("open");
}
function closeForm(){ $("overlay").classList.remove("open"); }

async function editServer(id) {
  const s = await api("GET", "/api/servers/"+id);
  $("formTitle").textContent = "Edit server";
  $("f_id").value=s.id; $("f_name").value=s.name;
  $("f_transport").value=s.transport; onTransport();
  $("f_url").value=s.url||""; $("f_headers").value=dumpLines(s.headers, ": ");
  $("f_command").value=s.command||""; $("f_args").value=(s.args||[]).join(" ");
  $("f_env").value=dumpLines(s.env, "=");
  $("f_interval").value=s.check_interval_seconds;
  $("f_tools").value=(s.tools_to_test||[]).map(t=>t.name).join(", ");
  $("f_deg").value=s.thresholds.latency_degraded_ms; $("f_down").value=s.thresholds.latency_down_ms;
  $("f_toolpol").value=s.on_tool_change||"degrade"; $("f_sens").value=(s.anomaly||{}).sensitivity||4;
  $("formErr").textContent=""; $("overlay").classList.add("open");
}

function formPayload(enabled) {
  const transport = $("f_transport").value;
  const tools = $("f_tools").value.split(",").map(t=>t.trim()).filter(Boolean);
  const p = { name:$("f_name").value.trim(), enabled, transport,
    check_interval_seconds:parseInt($("f_interval").value,10), tools_to_test:tools,
    thresholds:{ latency_degraded_ms:parseFloat($("f_deg").value), latency_down_ms:parseFloat($("f_down").value) },
    on_tool_change:$("f_toolpol").value, anomaly:{ sensitivity:parseFloat($("f_sens").value)||4 } };
  if (transport==="stdio") {
    p.command=$("f_command").value.trim();
    p.args=$("f_args").value.trim()?$("f_args").value.trim().split(/\s+/):[];
    p.env=parseLines($("f_env").value,"=");
  } else { p.url=$("f_url").value.trim(); p.headers=parseLines($("f_headers").value,": "); }
  return p;
}
async function saveForm() {
  const id=$("f_id").value;
  try {
    let cur=null; if(id) cur=await api("GET","/api/servers/"+id);
    const payload=formPayload(cur?cur.enabled:true);
    if(cur){ payload.webhooks=cur.webhooks;
      payload.anomaly=Object.assign({}, cur.anomaly, payload.anomaly);
      // The form edits probe *names* only: keep each kept probe's arguments/options.
      const prev=Object.fromEntries((cur.tools_to_test||[]).map(t=>[t.name,t]));
      payload.tools_to_test=payload.tools_to_test.map(n=>prev[n]||n); }
    if(id) await api("PUT","/api/servers/"+id,payload); else await api("POST","/api/servers",payload);
    closeForm(); refresh();
  } catch(e){ $("formErr").textContent="Error: "+e.message; }
}
async function del(id) {
  if(!confirm("Delete this server and its history?")) return;
  await api("DELETE","/api/servers/"+id); refresh();
}
async function checkNow(id){ try{ await api("POST","/api/servers/"+id+"/check"); }catch(e){} refresh(); }
async function togglePause(id, enabled) {
  const s=await api("GET","/api/servers/"+id);
  const payload=Object.assign({},s,{enabled:!enabled}); delete payload.id;
  await api("PUT","/api/servers/"+id,payload); refresh();
}

/* history */
let histId=null;
function closeHistory(){ $("histOverlay").classList.remove("open"); }
function openHistory(id){
  histId=id; $("histTitle").textContent="History · "+(SERVERS[id]||id);
  $("histOverlay").classList.add("open"); loadHistory(360);
}
async function loadHistory(minutes, btn){
  if(btn){ document.querySelectorAll("#histOverlay .rbtn").forEach(b=>b.classList.remove("on")); btn.classList.add("on"); }
  const q=minutes?("?minutes="+minutes):"";
  let hist, ins;
  try{ [hist, ins]=await Promise.all([
    api("GET","/api/servers/"+histId+"/history"+q),
    api("GET","/api/servers/"+histId+"/insights"+q)]); }
  catch(e){ $("histBody").innerHTML='<p class="detail">'+esc(e.message)+'</p>'; return; }
  $("histBody").innerHTML=renderCharts(hist, ins);
}
const fmtTime = iso => new Date(iso).toLocaleString([], {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});
function renderCharts(hist, ins){
  if(!hist.length) return '<p class="muted">No checks recorded in this window yet.</p>';
  ins = ins || {};
  const n=hist.length, ups=hist.filter(e=>e.status==="up").length;
  const uptime=(100*ups/n).toFixed(1);
  const oks=hist.filter(e=>e.status!=="down");
  const avg=oks.length?Math.round(oks.reduce((a,e)=>a+e.latency_ms,0)/oks.length):0;
  const last=hist[n-1], accent=sc(last.status), grid=css("--border-strong"), muted=css("--muted");
  const anom=css("--anom"), text=css("--text");
  const W=620,H=170,pad=30;
  const lat=hist.map(e=>e.latency_ms), maxL=Math.max(50,...lat);
  const X=i=>pad+(n===1?(W-2*pad)/2:i*(W-2*pad)/(n-1));
  const Y=v=>H-pad-(Math.min(v,maxL)/maxL)*(H-2*pad);
  const line=lat.map((v,i)=>(i?"L":"M")+X(i).toFixed(1)+" "+Y(v).toFixed(1)).join(" ");
  const area=line+` L ${X(n-1).toFixed(1)} ${H-pad} L ${X(0).toFixed(1)} ${H-pad} Z`;
  const dots=hist.map((e,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(e.latency_ms).toFixed(1)}" r="2.4" fill="${sc(e.status)}"/>`).join("");
  const rings=hist.map((e,i)=>(e.anomalies||[]).length
    ? `<circle cx="${X(i).toFixed(1)}" cy="${Y(e.latency_ms).toFixed(1)}" r="6.5" fill="none" stroke="${anom}" stroke-width="2"><title>${esc(e.anomalies.map(a=>a.detail).join("\n"))}</title></circle>` : "").join("");
  const gy=v=>`<line x1="${pad}" y1="${Y(v).toFixed(1)}" x2="${W-pad}" y2="${Y(v).toFixed(1)}" stroke="${grid}" stroke-dasharray="3 4"/>`+
    `<text x="4" y="${(Y(v)+3).toFixed(1)}" font-size="9" fill="${muted}">${Math.round(v)}</text>`;
  // learned baseline: median ± 3·(scaled MAD) band
  let band="";
  if(ins.baseline){
    const b=ins.baseline, lo=Math.max(0,b.median_ms-3*b.spread_ms), hi=b.median_ms+3*b.spread_ms;
    band=`<rect x="${pad}" y="${Y(hi).toFixed(1)}" width="${W-2*pad}" height="${Math.max(1,Y(lo)-Y(hi)).toFixed(1)}" fill="${anom}" fill-opacity="0.07"/>`+
      `<line x1="${pad}" y1="${Y(b.median_ms).toFixed(1)}" x2="${W-pad}" y2="${Y(b.median_ms).toFixed(1)}" stroke="${anom}" stroke-opacity=".55" stroke-dasharray="6 4"/>`;
  }
  // change point: vertical marker at the first check of the new regime
  let cpMark="", cpText="";
  if(ins.change_point){
    const cp=ins.change_point, t0=new Date(cp.at).getTime();
    const idx=hist.findIndex(e=>new Date(e.checked_at).getTime()>=t0);
    if(idx>=0){
      const x=X(idx).toFixed(1);
      cpMark=`<line x1="${x}" y1="${pad-12}" x2="${x}" y2="${H-pad}" stroke="${text}" stroke-width="1.2" stroke-dasharray="2 3"/>`+
        `<text x="${x}" y="${pad-15}" font-size="10" font-weight="700" fill="${text}" text-anchor="${idx>n*0.7?"end":"start"}">`+
        `${Math.round(cp.before_ms)}→${Math.round(cp.after_ms)} ms</text>`;
      cpText=`<div><div class="k">Level shift</div><div class="v num" style="font-size:15px;margin-top:5px">${Math.round(cp.before_ms)} → ${Math.round(cp.after_ms)} ms</div></div>`;
    }
  }
  const sw=(W-2*pad)/n;
  const strip=hist.map((e,i)=>`<rect x="${(pad+i*sw).toFixed(1)}" y="0" width="${Math.max(1.2,sw-1).toFixed(1)}" height="14" rx="1.5" fill="${sc(e.status)}"/>`).join("");
  const alist=(ins.anomalies||[]).slice().reverse().map(a=>
    `<div class="aitem"><span class="t">${fmtTime(a.checked_at)}</span><span class="badge anom" style="cursor:default">${esc(a.kind.replace(/_/g," "))}</span><span>${esc(a.detail)}</span></div>`).join("");
  return `
    <div class="stats">
      <div><div class="k">Uptime</div><div class="v num">${uptime}%</div></div>
      <div><div class="k">Avg latency</div><div class="v num">${avg} ms</div></div>
      <div><div class="k">Baseline</div><div class="v num">${ins.baseline?Math.round(ins.baseline.median_ms)+" ms":"learning…"}</div></div>
      <div><div class="k">Checks</div><div class="v num">${n}</div></div>
      ${cpText}
      <div><div class="k">Now</div><div style="margin-top:4px">${pill(last.status)}</div></div>
    </div>
    <div class="clabel">Latency (ms)</div>
    <svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block">
      ${gy(maxL)}${gy(maxL/2)}
      ${band}
      <path d="${area}" fill="${accent}" fill-opacity="0.13"/>
      <path d="${line}" fill="none" stroke="${accent}" stroke-width="1.8"/>
      ${dots}${rings}${cpMark}
    </svg>
    <div class="legend">
      <span><i style="background:${anom};opacity:.35"></i>learned baseline (median ± 3σ)</span>
      <span><i style="border:2px solid ${anom};background:none;border-radius:50%;width:10px;height:10px"></i>anomaly</span>
      <span><i style="border-left:2px dashed ${text};background:none;width:2px"></i>level shift</span>
    </div>
    <div class="clabel">Status timeline (oldest → newest)</div>
    <svg viewBox="0 0 ${W} 14" width="100%" style="display:block">${strip}</svg>
    <div class="clabel">Anomalies in this window (${(ins.anomalies||[]).length})</div>
    ${alist?`<div class="alist">${alist}</div>`:'<p class="muted" style="font-size:12.5px;margin:4px 0">None — behaving like its usual self.</p>'}`;
}

/* tools */
function closeTools(){ $("toolsOverlay").classList.remove("open"); }
async function openTools(id){
  $("toolsTitle").textContent = "Tools · " + (SERVERS[id]||id);
  $("toolsBody").innerHTML = '<p class="muted">Connecting to the server…</p>';
  $("toolsOverlay").classList.add("open");
  try {
    const tools = await api("GET", "/api/servers/"+id+"/tools");
    if (!tools.length){ $("toolsBody").innerHTML = '<p class="muted">This server exposes no tools.</p>'; return; }
    const nf = tools.reduce((a,t)=>a+t.findings.filter(f=>f.severity!=="low").length,0);
    const risky = t => t.findings.some(f=>f.severity!=="low");
    tools.sort((a,b)=>risky(b)-risky(a));
    $("toolsBody").innerHTML =
      `<div class="muted" style="margin-bottom:10px">${tools.length} tool(s) exposed · ` +
      (nf ? `<b style="color:var(--degraded)">🛡 ${nf} suspicious finding(s)</b> — descriptions are read by the LLM, so hidden instructions here can hijack your agent.`
          : `🛡 no tool-poisoning patterns found`) + `</div>` +
      '<div class="toollist">' + tools.map(t =>
        `<div class="toolitem${risky(t)?" risky":""}"><div class="tn">${esc(t.name)}</div>` +
        (t.description ? `<div class="td">${esc(t.description)}</div>` : '') +
        (t.findings.length ? '<div class="findings">' + t.findings.map(f =>
          `<div class="finding"><span class="sev ${f.severity}">${f.severity}</span><span>${esc(f.message)}` +
          ` <code>${esc(f.location)}: ${esc(f.excerpt)}</code></span></div>`).join("") + '</div>' : '') +
        `</div>`).join("") +
      '</div>';
  } catch(e){ $("toolsBody").innerHTML = '<p class="detail">Could not list tools: '+esc(e.message)+'</p>'; }
}

/* tool changes (rug-pull review) */
let chgId=null;
function closeChanges(){ $("changesOverlay").classList.remove("open"); }
function openChanges(id){
  chgId=id; $("changesTitle").textContent="Tool changes · "+(SERVERS[id]||id);
  $("changesErr").textContent=""; $("changesOverlay").classList.add("open"); loadChanges(false);
}
// Longest-common-subsequence diff over tokens -> [["=",tok]|["-",tok]|["+",tok]]
function lcsDiff(a, b){
  const n=a.length, m=b.length;
  if(n*m>4e6) return [...a.map(t=>["-",t]), ...b.map(t=>["+",t])];
  const dp=Array.from({length:n+1},()=>new Uint32Array(m+1));
  for(let i=n-1;i>=0;i--) for(let j=m-1;j>=0;j--)
    dp[i][j]=a[i]===b[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
  const out=[]; let i=0,j=0;
  while(i<n&&j<m){
    if(a[i]===b[j]){out.push(["=",a[i]]);i++;j++;}
    else if(dp[i+1][j]>=dp[i][j+1]) out.push(["-",a[i++]]); else out.push(["+",b[j++]]);
  }
  while(i<n) out.push(["-",a[i++]]); while(j<m) out.push(["+",b[j++]]);
  return out;
}
// Make invisible characters visible: they are the whole point of some attacks.
const showHidden = s => s.replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g,
  c=>"⟦U+"+c.charCodeAt(0).toString(16).toUpperCase().padStart(4,"0")+"⟧");
function wordDiff(before, after){
  const tok=s=>showHidden(s||"").split(/(\s+)/).filter(x=>x!=="");
  return lcsDiff(tok(before),tok(after)).map(([op,t])=>
    op==="="?esc(t):op==="-"?`<del>${esc(t)}</del>`:`<ins>${esc(t)}</ins>`).join("");
}
function stableJson(v){
  if(Array.isArray(v)) return v.map(stableJson);
  if(v&&typeof v==="object") return Object.fromEntries(Object.keys(v).sort().map(k=>[k,stableJson(v[k])]));
  return v;
}
function lineDiff(before, after){
  const lines=v=>v===undefined?[]:JSON.stringify(stableJson(v),null,2).split("\n");
  return lcsDiff(lines(before),lines(after)).map(([op,l])=>
    `<span class="ln-${op==="="?"eq":op==="-"?"del":"ins"}">${op==="="?" ":op} ${esc(showHidden(l))}</span>`).join("");
}
function renderChange(c){
  let body="";
  if(c.kind==="changed"){
    c.fields.forEach(f=>{
      const a=(c.before||{})[f], b=(c.after||{})[f];
      body+=`<div class="fl">${esc(f)}</div>`+
        ((typeof a==="string"||typeof b==="string")&&typeof a!=="object"&&typeof b!=="object"
          ? `<div class="diff">${wordDiff(a,b)}</div>` : `<div class="diff">${lineDiff(a,b)}</div>`);
    });
  } else {
    const d=c.after||c.before||{};
    body=`<div class="fl">${c.kind==="added"?"new tool":"removed tool"}</div>`+
      `<div class="diff">${esc(showHidden(d.description||"(no description)"))}</div>`;
  }
  return `<div class="chg"><div class="chg-h"><span class="kind ${c.kind}">${c.kind}</span>`+
    `<span class="tn">${esc(c.tool)}</span>${c.fields.length?`<span class="muted">${esc(c.fields.join(", "))}</span>`:""}`+
    `${c.reviewed?'<span class="muted">· reviewed</span>':""}<span class="when">${fmtTime(c.detected_at)}</span></div>`+
    `<div class="chg-b">${body}</div></div>`;
}
async function loadChanges(all){
  $("chgPending").classList.toggle("on",!all); $("chgAll").classList.toggle("on",all);
  $("changesBody").innerHTML='<p class="muted">Loading…</p>';
  try{
    const list=await api("GET","/api/servers/"+chgId+"/tool-changes"+(all?"?all=true":""));
    const pending=list.filter(c=>!c.reviewed).length;
    $("ackBtn").style.display=pending?"":"none";
    $("changesBody").innerHTML=list.length?list.map(renderChange).join("")
      :`<div class="okmsg">✓ No ${all?"":"pending "}tool changes. The tools match what was pinned.</div>`;
  }catch(e){ $("changesBody").innerHTML='<p class="detail">'+esc(e.message)+'</p>'; }
}
async function ackChanges(){
  try{ await api("POST","/api/servers/"+chgId+"/tool-changes/ack"); loadChanges(false); refresh(); }
  catch(e){ $("changesErr").textContent="Error: "+e.message; }
}

/* import / export */
function closeImport(){ $("importOverlay").classList.remove("open"); }
function openImport(){ $("importText").value=""; $("importErr").textContent=""; $("importOverlay").classList.add("open"); }
function loadFile(ev){
  const f=ev.target.files[0]; if(!f) return;
  const r=new FileReader(); r.onload=()=>{ $("importText").value=r.result; }; r.readAsText(f);
}
async function doImport(){
  const text=$("importText").value;
  try{
    const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/x-yaml"},body:text});
    if(!r.ok){ const d=await r.json().catch(()=>({})); throw new Error(d.detail||r.status); }
    const res=await r.json(); closeImport(); refresh();
    alert("Imported "+res.imported+" server(s).");
  }catch(e){ $("importErr").textContent="Error: "+e.message; }
}

/* API tokens */
function closeTokens(){ $("tokensOverlay").classList.remove("open"); $("newTok").style.display="none"; $("newTok").textContent=""; }
function openTokens(){ $("tokErr").textContent=""; $("t_name").value=""; $("t_days").value=""; loadTokens(); $("tokensOverlay").classList.add("open"); }
const fmtDate = t => t ? new Date(t*1000).toLocaleString() : "never";
async function loadTokens(){
  try{
    const list=await api("GET","/api/tokens");
    $("tokList").innerHTML = list.length ? list.map(t=>
      `<div class="tok"><span class="nm">${esc(t.name)}</span><span class="badge">${esc(t.scope)}</span>`+
      `<span class="meta">created ${esc(fmtDate(t.created_at))} · expires ${esc(fmtDate(t.expires_at))} · last used ${esc(t.last_used_at?fmtDate(t.last_used_at):"never")}</span>`+
      `<button class="btn" onclick="revokeToken('${esc(t.id)}')">Revoke</button></div>`).join("")
      : '<p class="muted">No tokens yet.</p>';
  }catch(e){ $("tokErr").textContent="Error: "+e.message; }
}
async function createToken(){
  $("tokErr").textContent="";
  const days=parseInt($("t_days").value,10);
  try{
    const t=await api("POST","/api/tokens",{name:$("t_name").value.trim(),scope:$("t_scope").value,
      expires_in_days: Number.isFinite(days)?days:null});
    $("newTok").style.display=""; $("newTok").textContent="Copy it now — it will not be shown again:  "+t.token;
    $("t_name").value=""; loadTokens();
  }catch(e){ $("tokErr").textContent="Error: "+e.message; }
}
async function revokeToken(id){
  if(!confirm("Revoke this token? Anything using it stops working immediately.")) return;
  try{ await api("DELETE","/api/tokens/"+id); loadTokens(); }catch(e){ $("tokErr").textContent="Error: "+e.message; }
}

/* auth */
async function logout(){ await fetch("/api/auth/logout",{method:"POST"}); location.href="/login"; }
async function initAuth(){
  try{
    const s=await (await fetch("/api/auth/status")).json();
    if(s.auth_enabled){
      $("logoutBtn").style.display=""; $("tokensBtn").style.display="";
      if(s.username){ $("whoami").innerHTML='<span class="av">'+esc(s.username[0])+'</span>'+esc(s.username); }
    }
  }catch(e){}
}

/* close modals on overlay click / Escape */
document.querySelectorAll(".overlay").forEach(o=>o.addEventListener("mousedown",e=>{ if(e.target===o) o.classList.remove("open"); }));
document.addEventListener("keydown",e=>{ if(e.key==="Escape") document.querySelectorAll(".overlay.open").forEach(o=>o.classList.remove("open")); });

initAuth();
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
