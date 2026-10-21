"""A minimal MCP server for exercising mcpsonar locally, with no external dependency.

Exposes three tools that make the different check outcomes easy to demonstrate:

* ``ping``  — takes no args, returns "pong"  -> succeeds when probed  (=> up)
* ``echo``  — requires a ``text`` arg        -> fails when probed with no args (=> degraded/down)
* ``boom``  — always raises                  -> fails when probed        (=> degraded/down)

Run it:
    python scripts/mock_mcp_server.py                  # Streamable HTTP at http://127.0.0.1:8000/mcp
    python scripts/mock_mcp_server.py --transport sse  # legacy SSE at   http://127.0.0.1:8000/sse
    python scripts/mock_mcp_server.py --transport stdio  # stdio (client launches this process)
    python scripts/mock_mcp_server.py --port 9001
"""

from __future__ import annotations

import argparse
import sys

from mcp.server import MCPServer


def build_server() -> MCPServer:
    # An mcp 2.x server is dual-era: it answers both `server/discover` (2026-07-28) and the
    # `initialize` handshake (2025-11-25 and earlier).
    server = MCPServer("mock-mcp-server")

    @server.tool()
    def ping() -> str:
        """Liveness probe; returns 'pong'. Callable with no arguments."""
        return "pong"

    @server.tool()
    def echo(text: str) -> str:
        """Echo the given text back. Requires the 'text' argument."""
        return text

    @server.tool()
    def boom() -> str:
        """Always raises, to simulate a broken tool."""
        raise RuntimeError("intentional failure for testing")

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock MCP server for mcpsonar testing.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "sse", "stdio"],
        default="streamable-http",
    )
    args = parser.parse_args()

    server = build_server()
    if args.transport == "stdio":
        # stdout is the MCP channel here, so log to stderr only.
        print("mock MCP server: stdio", file=sys.stderr)
        server.run(transport="stdio")
        return
    path = "/mcp" if args.transport == "streamable-http" else "/sse"
    # Log to stderr to keep stdout clean regardless of transport.
    print(
        f"mock MCP server: http://{args.host}:{args.port}{path}  (transport={args.transport})",
        file=sys.stderr,
    )
    server.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
