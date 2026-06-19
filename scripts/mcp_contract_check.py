#!/usr/bin/env python3
"""Detect drift between MCP implementation, OpenAPI, and Droid setup docs."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MCP_GO = ROOT / "internal" / "bootstrap" / "mcp.go"
OPENAPI = ROOT / "api" / "openapi.yaml"
DOCS = ROOT / "docs" / "domains" / "mcp-droid-setup.md"


def main() -> int:
    mcp_go = MCP_GO.read_text()
    openapi = OPENAPI.read_text()
    docs = DOCS.read_text()

    failures: list[str] = []
    require('mcpProtocolVersion          = "2025-11-25"' in mcp_go, "mcp.go protocol version must stay on 2025-11-25", failures)
    require('w.Header().Set("Allow", http.MethodPost)' in mcp_go, "GET /api/v1/mcp must advertise POST only", failures)
    require("http.StatusAccepted" in mcp_go, "MCP notifications must keep 202 Accepted handling", failures)
    require("http.StatusBadRequest" in mcp_go and "unsupported_protocol_version" in mcp_go, "unsupported MCP protocol versions must remain HTTP 400-observable", failures)
    require('"experimental"' not in mcp_go, "initialize capabilities must not reintroduce primitive experimental values", failures)

    mcp_block = extract_path_block(openapi, "/api/v1/mcp:")
    require("'405':" in mcp_block and "not an SSE endpoint" in mcp_block, "OpenAPI must document GET /api/v1/mcp as 405 non-SSE", failures)
    require("'202':" in mcp_block and "'400':" in mcp_block, "OpenAPI must document MCP notification 202 and protocol-version 400 responses", failures)
    require("text/event-stream" not in mcp_block, "OpenAPI MCP path must not advertise SSE event-stream content", failures)

    for phrase in [
        "protocolVersion\": \"2025-11-25\"",
        "Fire-and-forget JSON-RPC notifications can return `202 Accepted`",
        "`GET /api/v1/mcp` is not an SSE endpoint and returns `405 Method Not Allowed`",
        "make mcp-contract-check mcp-sdk-compat",
        "scripts/mcp_smoke.py",
    ]:
        require(phrase in docs, f"docs/domains/mcp-droid-setup.md missing {phrase!r}", failures)

    if failures:
        print("mcp_contract_check: failed", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("mcp_contract_check: ok")
    return 0


def extract_path_block(openapi: str, path_header: str) -> str:
    match = re.search(rf"^  {re.escape(path_header)}\n(?P<body>(?:    .*\n|      .*\n|        .*\n|          .*\n|            .*\n|              .*\n|                .*\n)*)", openapi, re.MULTILINE)
    return match.group("body") if match else ""


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


if __name__ == "__main__":
    raise SystemExit(main())
