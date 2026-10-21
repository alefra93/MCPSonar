---
title: MCPSonar — monitoring and security scanning for MCP servers
description: >-
  Open-source, self-hosted monitor and security scanner for MCP (Model Context Protocol)
  servers. Detects rug pulls (tool definitions that change under you), tool-poisoning
  patterns, downtime and latency anomalies, and gates CI with SARIF reports.
---

![MCPSonar](img/banner.png)

**MCPSonar** watches the MCP servers your AI agents depend on, and tells you when they go
down, get slower, or **change their tools under you**.

An MCP server can be up and still be dangerous. A tool description that changes after you
approved it (a *rug pull*), or that hides instructions for the model (*tool poisoning*),
goes unnoticed by ordinary uptime monitors. MCPSonar pins every tool definition, flags
every change until a human reviews it, and lints the text of each tool for known
poisoning patterns.

![MCPSonar dashboard: four MCP servers, one degraded by an unreviewed tool change](img/dashboard-dark.png)

## What it does

- **Uptime and latency** of HTTP, SSE and stdio MCP servers, with a learned baseline per
  server instead of fixed thresholds: spikes, sustained regressions, recoveries, flapping.
- **Rug-pull detection:** every tool definition is fingerprinted; any change is shown as a
  diff and stays pending until reviewed.

  ![Diff of a rug-pulled MCP tool: a hidden IMPORTANT block and a new sidenote parameter](img/rugpull-diff.png)

- **Tool-poisoning lint:** documented heuristic rules, mapped to the OWASP MCP Top 10. A
  finding is something to review, not proof of an attack.
- **CI gate:** `mcpsonar scan` and a GitHub Action fail a build on findings or on a changed
  lockfile, and write SARIF for GitHub code scanning.
- **Dashboard, CLI and REST API** over one engine; Prometheus metrics; Uptime Kuma and
  webhook outputs.
- **Secure by default:** login and setup token, hashed sessions and API tokens, masked
  credentials, secret references, outbound connection policy, non-root container.

## Try it

```bash
uvx --from https://github.com/alefra93/MCPSonar/releases/download/v0.8.0/mcpsonar-0.8.0-py3-none-any.whl mcpsonar demo
```

Needs only [uv](https://docs.astral.sh/uv/). The demo dashboard runs against four scripted local MCP servers: one gets rug-pulled, one
gets slower, one flaps.

Scan a server once, as in CI:

```bash
uvx --from https://github.com/alefra93/MCPSonar/releases/download/v0.8.0/mcpsonar-0.8.0-py3-none-any.whl mcpsonar scan https://example.com/mcp
```

## Documentation

- [Command line](cli.md): every command, local and remote mode, exit codes, completion.
- [Configuration](configuration.md): servers, probes, secrets, backups, reverse proxy.
- [Detection rules](detection-rules.md): what each lint rule looks for, its limits, its
  measured false positives.
- [Engineering audit and threat model](engineering-audit.md)
- [Product roadmap](product-roadmap.md) and [comparison with other tools](competitive-positioning.md)

Source code, issues and releases: [github.com/alefra93/MCPSonar](https://github.com/alefra93/MCPSonar).
MIT licensed.
