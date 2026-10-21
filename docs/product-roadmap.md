# MCPSonar product roadmap

> **Positioning:** open-source observability, integrity monitoring and security intelligence
> for MCP infrastructure — continuous, MCP-aware, self-hosted, local by default.

**Guiding goal for 1.0:** reach 1.0 with **5–10 real installations and documented feedback**,
rather than many features nobody has validated. Every milestone below is judged against
"does this help someone run MCPSonar in production and trust what it tells them?"

Effort is in focused engineer-days (one maintainer), and is approximate.

---

## v0.6.0 — Security hardening *(released 2026-10-21)*

**Features** (details in [engineering-audit.md](engineering-audit.md)):
- **Browser-facing hardening:**
  - CSRF and DNS-rebinding guards;
  - setup-token bootstrap with atomic creation;
  - server-side, revocable sessions;
  - login throttling and stronger password hashing;
  - security headers and body limits.
- **Credential handling:**
  - credentials masked in the API, exports, details, webhooks and logs;
  - stored secrets kept through edits.
- **Outbound connection policy:**
  - cloud metadata and link-local blocked;
  - addresses checked at connect time, closing the DNS-rebinding race;
  - configured headers stay on their origin.
- **Protocol and probing:**
  - `tools/list` pagination followed to the end;
  - session and check timeouts;
  - safe probing (unlisted tools never called, destructive ones skipped unless allowed);
  - fingerprints that ignore `required` order;
  - a per-server check lock.
- **Container and CI:**
  - non-root container with a HEALTHCHECK;
  - CI on Windows and macOS, `pip-audit`, a Docker smoke job, Dependabot.

**How it was released (2026-10-21):**
- **CI:** PR #3 was green on all 7 checks (Linux 3.11–3.13, Windows, macOS, pip-audit, Docker).
- **GitHub settings:** private vulnerability reporting enabled and repository topics set.
- **Real-environment check:** the 24/7 watch ran overnight on the 0.6.0 image (13 h 40 min,
  3,934 checks, 99.5% up). Every *down* was a remote timeout, a dropped connection or an HTTP 502.
  Nothing was blocked by the new outbound policy, and no server failed repeatedly.
- **Release:** merged and tagged `v0.6.0`; `release.yml` published the GitHub Release.

**Acceptance criteria:**
- All tests pass on 3.11–3.13, Linux, Windows and macOS.
- `pip-audit` is clean.
- The Docker smoke job is green.
- The upgrade notes in `docs/configuration.md` were checked on an existing v0.5 database.

| Risk | Effort left | Release blockers |
|---|---|---|
| Low–Medium: behavior changes for `--no-auth` LAN users and API scripts that read tokens back | about 1 day | CI green on the new matrix; 48 h soak test |

---

## Product rule: three interfaces, one engine

The CLI, the dashboard/REST API and CI/CD (`scan` + the GitHub Action) are interfaces over
**one** application layer (`mcpsonar/services.py`) and engine. A health classification, a
risk severity, a fingerprint, an anomaly, an approval or a config validation exists once;
interfaces only parse inputs and render outputs. Every milestone below is checked against
this rule, and consistency tests guard it (the first one already exists: the dashboard's
Tools view and `mcpsonar risks` must report the same findings). See [cli.md](cli.md).

> **Reconciliation note (2026-10-20).** This plan merges the CLI expansion with the earlier
> observability roadmap. Compared with the first version of this document:
> - **v0.7** becomes *CLI foundation + protocol currency*. It takes in the MCP SDK 2.x work
>   recommended by [ADR 0001](adr/0001-mcp-sdk-2.md), on branch `spike/mcp-sdk-2-adr`.
> - **Deep observability** (per-tool latency, response drift, anomaly quality) moves to v0.8.
> - **Notifications and the conference demo** move to v0.9.
>
> The order is a proposal awaiting the maintainer's confirmation.

---

## v0.7.0 — CLI foundation and protocol currency

**Features:**
- **Shared application layer.** *IMPLEMENTED (v0.7.0):*
  - `services.inspect_server` is used by the dashboard, `scan` and the CLI;
  - the output layer and exit-code contract (`output.py`);
  - a rule registry (`lint.RULES`).
- **Local-mode commands.** *IMPLEMENTED and tested (v0.7.0):*
  - `tools`, `risks`, `config validate|show|export`, `doctor`, `version`;
  - `--format json` everywhere, `NO_COLOR`, stdout/stderr separation.
- **Remote mode.** *IMPLEMENTED and tested (v0.7.0):*
  - *API tokens:* created in the dashboard, stored hashed, scoped *read* or *write*,
    expiring and revocable. Used as `Authorization: Bearer` by the CLI, without touching
    the v0.6 CSRF and session model.
  - *Client config:* `MCPSONAR_URL` + `MCPSONAR_TOKEN`.
  - *Commands:* `status`, `servers list|show|add|edit|pause|resume|remove`, `check`, `diff`,
    `history`.
- **Remote-mode commands** (all through the instance's API, never its database):
  - `status`;
  - `servers list|add|show|edit|remove|pause|resume`, with confirmation on a TTY and `--yes`
    otherwise;
  - `check NAME|--all`, run by the instance;
  - `diff NAME`, which shows changes and never approves;
  - `history NAME --last 24h`, bounded by default.
- **Service extraction:** move the remaining shared operations from `api.py` into services
  (server CRUD with secret restore, tool-change listing and approval, history and insights).
  The API and the CLI then call the same functions.
- **MCP protocol currency.** *IMPLEMENTED, TESTED and VERIFIED (v0.7.0):*
  - ADR 0001 implemented: mcp 2.x / spec 2026-07-28, with 2025-era servers still supported,
    behind `check_engine` and `services`;
  - fingerprints stable: 42/42 live tools identical, golden-value tests;
  - 24/24 live servers classified as before.

**Dependencies:**
- v0.6 released.
- The API-token design reviewed before it is implemented (it is security-sensitive).

**Acceptance criteria:**
- **Consistency:** each remote command has a consistency test against the API (same
  numbers as the dashboard).
- **Exit codes:** documented, and `scan`'s 0/1/2 contract unchanged.
- **CLI safety:** no command prints a credential, and no command writes to the database.
- **Protocol:** the SDK migration passes the protocol-edge suite, plus a fixture server per
  spec revision.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium–High (auth surface; SDK major version) | 15–20 days (about 4 already done) | Token design review; ADR implemented; Windows, macOS and Linux CI green |

---

## v0.8.0 — Developer tooling and deep observability

**Features:**
- **`mcpsonar report --format json|markdown|sarif`:**
  - SARIF 2.1.0 with the stable rule IDs from `lint.RULES` and a confidence level per
    finding;
  - evidence excerpts only: no secrets, no response bodies;
  - SARIF upload example for the GitHub Action;
  - findings mapped to OWASP MCP Top 10 IDs.
- **Detection quality:** an adversarial fixture corpus with positive and negative cases for
  every rule, and `docs/detection-rules.md`.
- **Packaging:**
  - PyPI readiness: trusted publishing workflow, wheel and sdist smoke-tested on 3 operating
    systems; publishing only with explicit approval;
  - a verified `uvx mcpsonar`;
  - optional shell completion;
  - `doctor` extended to remote-mode checks.
- **Per-phase and per-tool latency:**
  - connect, initialize, discovery and each probe measured separately;
  - shown in `status`/`history`, the API and Prometheus;
  - existing metric names unchanged.
- **Response drift:** for explicitly configured, deterministic probes only. It compares
  structure, error behavior, size bucket and an optional canonicalized hash; full bodies
  are not stored.
- **Anomaly quality:**
  - cold start;
  - the zero-MAD floor;
  - sustained regression versus spike;
  - recovery events;
  - baseline-poisoning resistance;
  - deduplication by episode;
  - a reproducible statistical corpus.
- **Secret references** (`${env:NAME}`, `${file:…}`), resolved at check time.

**Acceptance criteria:**
- **SARIF:** passes GitHub's validator.
- **Rules:** each has at least 3 positive and 3 negative fixtures.
- **Metrics:** none renamed.
- **Drift:** zero false positives over 24 h of the watch deployment.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium | 14–20 days | Schema-migration framework (versioned) before drift data is stored |

---

## v0.9.0 — Ecosystem adoption and teams

**Features:**
- **Conference-ready demo:**
  - deterministic scenarios: healthy servers, rug pull, poisoning, latency regression and a
    CI gate failure;
  - selectable with `mcpsonar demo --scenario …`;
  - fully local, no credentials;
  - `docs/demo/{README,scenarios,speaker-guide,troubleshooting}.md`.
  - The current demo already shows the first four scenarios in the dashboard, but on timers
    with randomness. It needs a deterministic, step-driven mode and the CLI view.
- **Onboarding:** a quickstart that goes from install to the first scan, the dashboard, a
  monitored server, a reviewed change and a CI check in minutes; a FAQ; troubleshooting.
- **Notifications:** Slack, Discord and email adapters on `BaseAdapter`; deduplication;
  recovery notifications.
- **Dashboard consistency and UX:**
  - an incident timeline (started, recovered);
  - filters: unreachable, auth required, unreviewed changes, findings, regressions;
  - accessible colors; mobile layout; loading and error states.
- **Teams:** roles (admin, operator, viewer), password change, session list, and an
  append-only audit history of approvals.
- **MCPSonar Trust Report:** an offline HTML/PDF summary per server or fleet covering
  availability, definition changes and their review status, and heuristic findings labeled
  as such.
- **Community validation:** 5–10 real deployments, with false-positive reports turned into
  fixtures.

**Acceptance criteria:**
- **Demo:** runs identically 3 times in a row offline.
- **Roles:** enforced server-side, with a test per endpoint.
- **Trust Report:** states the limits of its heuristics.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium (auth model change) | 15–20 days | Migration from single-admin tested on real databases |

---

## v1.0.0 — Stable

**Features and work:**
- **Stable interfaces:** documented and versioned, with a deprecation policy, for:
  - the REST API, `CheckEvent`, the lockfile format, metric names and the config schema;
  - **CLI commands, flags, JSON documents (`schema_version`) and exit codes.**
- **MCP spec 2026-07-28 support:** via SDK 2.x or a dual-stack client, according to the v0.7 ADR. Older revisions keep working.
- **Upgrades:** reliable upgrade path from v0.6+ databases, with tests on stored fixtures; documented backup and restore.
- **External security review:** of auth, network policy and stdio; fixes released before the 1.0 tag.
- **Production validation:** the 5–10 installations have run for at least 30 days; known issues are published.

**Acceptance criteria:**
- No open High or Critical findings.
- Upgrade tests pass from every 0.x version since 0.6.
- Every public interface is documented.

| Risk | Effort | Release blockers |
|---|---|---|
| Medium | 15–20 days plus the review lead time | Security review complete; the SDK 2.x decision implemented |

---

## Open-core strategy (options, not commitments)

**Principle:** the Community Edition stays MIT-licensed and complete for a team running its
own MCP fleet. Every feature released under MIT stays MIT. Nothing is moved behind a paywall,
and no artificial limits are added (server counts, retention caps, crippled exports).

**What a paid offering could add** (things that need *operated infrastructure* or
*organization-scale governance*, which a self-hosted single instance does not):

| Option | Why it is naturally commercial |
|---|---|
| Managed hosting (MCPSonar Cloud) | Someone runs, upgrades and backs up the service |
| Managed alert delivery and on-call routing | Reliable delivery infrastructure, SMS and voice |
| Central fleet management across many instances and organizations | Aggregation service, multi-tenancy |
| Enterprise SSO (SAML/OIDC) and SCIM | Integration and support burden. Basic OIDC login could still be community. |
| Organization-wide policies (e.g. "no unreviewed tool change older than 24 h in prod") with attestations | Governance workflows across teams |
| Long-term managed retention and compliance exports | Storage and operations |
| Enterprise support and SLA | People |

**Guardrails:**
- Community detection rules stay open, so the community can audit them.
- The Trust Report is in the Community Edition. A hosted, fleet-wide version is a natural paid
  extension.
- No telemetry without opt-in.

## Adoption plan alongside the releases

- Track installations through opt-in signals: GitHub stars and issues, a voluntary "who uses it"
  list, and Action usage. Never phone home.
- After v0.6: write up the audit, with a "what we fixed and why" post for credibility.
- After v0.8: share on community channels (MCP Discord, r/mcp, Hacker News "Show HN") with the
  PyPI one-liner and the demo.
- Treat every false-positive report as a test fixture.
