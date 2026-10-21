# Contributing to MCPSonar

Thanks for helping. The most valuable contributions right now are, in order:

1. **Real-world reports**: a server MCPSonar gets wrong (false *down*, a false rug-pull alert,
   a poisoning finding on harmless text), with the tool definition that triggered it.
2. **Detection rules** with a real example: a positive case it must catch and a negative one
   it must not.
3. Fixes for open issues; then features from the [roadmap](docs/product-roadmap.md).

Security problems: **don't open an issue**, see [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/alefra93/MCPSonar.git && cd MCPSonar
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   ·   macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q                 # all tests; real MCP servers run locally as subprocesses
ruff check src tests      # ruff is pinned exactly in pyproject.toml
mcpsonar demo             # the whole product, live
```

`bash scripts/smoke_e2e.sh` runs an end-to-end check against a running instance. Set
`SMOKE_SKIP_NPX=1` to skip its stdio check, which downloads and runs an npm package.

## Ground rules

- **Small, reviewable pull requests**: one concern per PR, tests included. A bug fix
  starts with a test that fails without it.
- **No external network in tests.** Use the local mock servers (`scripts/mock_mcp_server.py`,
  `tests/fixtures/scripted_server.py`), `httpx.MockTransport`, or monkeypatched DNS. Never
  launch third-party MCP packages from tests.
- **Never commit credentials**, not even fake-looking ones that resemble a real format.
  Use obviously fake values (`sk-live-0123456789abcdef`).
- **Security-sensitive changes** (auth, `websec.py`, `netpolicy.py`, `redact.py`, stdio,
  probes) need a regression test for the threat, and a sentence in the PR on why the change is
  safe.
- **Heuristics are not verdicts.** Lint output must say "suspicious", not "malicious". Keep
  claims in docs and UI proportional to the evidence.
- Python 3.11+, type hints on public functions, code that reads like the surrounding code.
  Comments explain *why*, not what.
- `mcp` is pinned to the 2.x line (`>=2.3,<3`). A new major version is a deliberate
  migration with its own ADR (see `docs/adr/0001-mcp-sdk-2.md`), never a bump inside an
  unrelated PR.

## Adding things

- **A spec version validator:** add one `validators/vYYYY_MM_DD.py` and register it. Never edit
  older validators.
- **An output adapter:** one class implementing `BaseAdapter.send`, tested with
  `httpx.MockTransport`. Deliveries go through the scheduler's shared client, so the outbound
  policy applies automatically.
- **A lint rule:** add it to `lint.py` with a stable ID, severity and message, plus positive
  *and* negative cases in `tests/test_tooldefs_lint.py`.

## Release checklist (maintainers)

1. On `main`, CI is green on all operating systems, `pip-audit` is clean and the Docker job is
   green.
2. Bump `version` in `pyproject.toml` and the `image:` tags in both compose files.
3. Move `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] — YYYY-MM-DD`; check the upgrade notes.
4. Run `bash scripts/smoke_e2e.sh` and `mcpsonar demo` locally; upgrade a copy of a real
   database from the previous version.
5. Tag `vX.Y.Z` on `main` and push the tag. `release.yml` checks the tag matches the version,
   re-runs the tests and creates the GitHub Release.
6. Update the README examples that pin the Action (`@vX.Y.Z` or a SHA).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
