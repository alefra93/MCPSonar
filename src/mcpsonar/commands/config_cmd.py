"""``mcpsonar config validate | show | export`` for YAML configuration files.

The same validation the monitor applies when it seeds from ``--config`` (one model:
:class:`mcpsonar.models.Config`), and the same redaction the API and dashboard apply
(:mod:`mcpsonar.redact`) — so a config shown here looks exactly like it will in the UI.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ..loader import ConfigError, load_config
from ..models import Config, TransportType
from ..output import EXIT_ERROR, EXIT_OK, Output, add_format_args, output_for
from ..redact import redact_config


def register(sub: Any) -> None:
    config = sub.add_parser("config", help="Validate, show or export a YAML configuration.")
    actions = config.add_subparsers(dest="config_action", required=True, metavar="ACTION")

    validate = actions.add_parser("validate", help="Check a config file; exit 2 if invalid.")
    validate.add_argument("file")
    add_format_args(validate)
    validate.set_defaults(handler=run_validate)

    show = actions.add_parser("show", help="Print the effective config (defaults filled in), "
                                           "credentials masked.")
    show.add_argument("file")
    add_format_args(show, formats=("yaml", "json"))
    show.set_defaults(handler=run_show, format="yaml")

    export = actions.add_parser(
        "export",
        help="Write the normalized config; credentials masked unless --include-secrets.",
        description="Write the normalized config (every default explicit) to stdout or -o. "
        "With --include-secrets the real credentials are written: only to a new file (-o), "
        "created readable by its owner only, never to the terminal.",
    )
    export.add_argument("file")
    export.add_argument("-o", "--output", metavar="OUT", help="Write to this file.")
    export.add_argument("--include-secrets", action="store_true",
                        help="Write real credentials (requires -o; the file must not exist).")
    export.set_defaults(handler=run_export)


def _load(path: str, out: Output) -> Config | None:
    try:
        return load_config(path)
    except ConfigError as exc:
        out.error(str(exc))
    except yaml.YAMLError as exc:
        out.error(f"{path}: not valid YAML: {exc}")
    except ValidationError as exc:
        out.error(f"{path}: {exc.error_count()} problem(s):")
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"])
            print(f"  {loc}: {err['msg']}", file=out.stderr)
    return None


def _notes(config: Config) -> list[str]:
    notes = []
    stdio = [n for n, c in config.servers.items() if c.transport == TransportType.STDIO]
    if stdio:
        notes.append(f"stdio servers run a command on the monitoring host: {', '.join(stdio)}")
    with_secrets = [n for n, c in config.servers.items() if c.headers or c.env]
    if with_secrets:
        notes.append("credentials stored in this file (keep it out of version control): "
                     + ", ".join(with_secrets))
    return notes


def run_validate(args: Any) -> int:
    out = output_for(args)
    config = _load(args.file, out)
    if config is None:
        if out.json_mode:
            out.emit_json("config.validate", {"file": args.file, "valid": False})
        return EXIT_ERROR
    notes = _notes(config)
    if out.json_mode:
        out.emit_json("config.validate", {"file": args.file, "valid": True,
                                          "servers": list(config.servers), "notes": notes})
        return EXIT_OK
    out.print(f"{out.style.green('valid')}: {args.file} · {len(config.servers)} server(s)")
    for note in notes:
        out.print(f"  note: {note}")
    return EXIT_OK


def _redacted(config: Config) -> dict[str, Any]:
    return {"servers": {name: redact_config(cfg) for name, cfg in config.servers.items()}}


def run_show(args: Any) -> int:
    out = output_for(args)
    config = _load(args.file, out)
    if config is None:
        return EXIT_ERROR
    data = _redacted(config)
    if args.format == "json":
        out.emit_json("config", data)
    else:
        out.print(yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip())
    return EXIT_OK


def run_export(args: Any) -> int:
    out = Output()
    config = _load(args.file, out)
    if config is None:
        return EXIT_ERROR
    if args.include_secrets:
        if not args.output:
            out.error("--include-secrets writes real credentials: give a new file with -o "
                      "(they are never printed to the terminal)")
            return EXIT_ERROR
        data = config.model_dump(mode="json")
    else:
        data = _redacted(config)
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    if not args.output:
        out.print(text.rstrip())
        return EXIT_OK
    target = Path(args.output)
    try:
        if args.include_secrets:
            # O_EXCL: never overwrite (or follow a planted symlink to) an existing file;
            # 0o600: owner-only on POSIX (Windows ignores the mode — protect the folder).
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            out.warn(f"{target} contains real credentials: store it like a password file")
        else:
            target.write_text(text, encoding="utf-8")
    except FileExistsError:
        out.error(f"{target} already exists; choose a new file name for a secrets export")
        return EXIT_ERROR
    except OSError as exc:
        out.error(f"cannot write {target}: {exc}")
        return EXIT_ERROR
    print(f"wrote {target}", file=out.stderr)
    return EXIT_OK
