#!/usr/bin/env python3
"""Smoke-test Cerebro's stateless MCP HTTP endpoint without printing secrets."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


PROTOCOL_VERSION = "2025-11-25"
FULL_TOOLSET = "full"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("CEREBRO_MCP_URL", ""), help="MCP endpoint URL; defaults to CEREBRO_BASE_URL + /api/v1/mcp")
    parser.add_argument("--base-url", default=os.environ.get("CEREBRO_BASE_URL", ""), help="Cerebro origin used when --url is omitted")
    parser.add_argument("--bearer-token", default=os.environ.get("CEREBRO_MCP_BEARER_TOKEN", ""), help="Bearer/API token for authenticated MCP calls")
    parser.add_argument("--skip-unauthenticated-check", action="store_true", help="Do not assert the unauthenticated OAuth challenge")
    parser.add_argument("--skip-authenticated-check", action="store_true", help="Only check unauthenticated behavior")
    args = parser.parse_args()

    url = mcp_url(args.url, args.base_url)
    if not url:
        print("mcp_smoke: provide --url or CEREBRO_BASE_URL", file=sys.stderr)
        return 2

    if not args.skip_unauthenticated_check:
        check_unauthenticated_challenge(url)

    if args.skip_authenticated_check:
        print("mcp_smoke: unauthenticated checks passed")
        return 0

    if not args.bearer_token:
        print("mcp_smoke: --bearer-token or CEREBRO_MCP_BEARER_TOKEN is required for authenticated checks", file=sys.stderr)
        return 2

    check_authenticated_get(url, args.bearer_token)
    init = rpc(url, args.bearer_token, 1, "initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "cerebro-mcp-smoke", "version": "0"},
    })
    result = init.get("result") or {}
    capabilities = result.get("capabilities") or {}
    experimental = capabilities.get("experimental")
    if experimental is not None and not isinstance(experimental, dict):
        raise SmokeError("initialize capabilities.experimental must be omitted or object-shaped")
    if result.get("protocolVersion") != PROTOCOL_VERSION:
        raise SmokeError(f"initialize negotiated {result.get('protocolVersion')!r}, want {PROTOCOL_VERSION!r}")

    tools = rpc(url, args.bearer_token, 2, "tools/list", {"limit": 100}, toolset=FULL_TOOLSET).get("result", {}).get("tools", [])
    if not isinstance(tools, list) or len(tools) < 10:
        raise SmokeError(f"tools/list returned {len(tools) if isinstance(tools, list) else 'non-list'} tools, want at least 10")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if "cerebro.version" not in names:
        raise SmokeError("tools/list is missing cerebro.version")

    version = rpc(url, args.bearer_token, 3, "tools/call", {"name": "cerebro.version", "arguments": {}}, toolset=FULL_TOOLSET)
    if version.get("result", {}).get("isError") is True:
        raise SmokeError("cerebro.version returned an MCP tool error")

    bad_version_status, _, _ = request(url, "POST", json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/list",
        "params": {},
    }).encode(), auth=args.bearer_token, protocol_version="2099-01-01")
    if bad_version_status != 400:
        raise SmokeError(f"unsupported MCP-Protocol-Version status {bad_version_status}, want 400")

    print(f"mcp_smoke: authenticated full-profile checks passed ({len(tools)} tools)")
    return 0


def mcp_url(url: str, base_url: str) -> str:
    url = url.strip()
    if url:
        return url
    base_url = base_url.strip().rstrip("/")
    if not base_url:
        return ""
    return f"{base_url}/api/v1/mcp"


def check_unauthenticated_challenge(url: str) -> None:
    status, headers, _ = request(url, "POST", b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
    if status != 401:
        raise SmokeError(f"unauthenticated MCP status {status}, want 401")
    challenge = headers.get("www-authenticate", "")
    if "Bearer" not in challenge or "resource_metadata" not in challenge:
        raise SmokeError("unauthenticated challenge is missing Bearer resource metadata")


def check_authenticated_get(url: str, token: str) -> None:
    status, headers, _ = request(url, "GET", auth=token)
    if status != 405:
        raise SmokeError(f"authenticated GET status {status}, want 405")
    if headers.get("mcp-session-id"):
        raise SmokeError("authenticated GET unexpectedly returned Mcp-Session-Id")
    if headers.get("content-type", "").startswith("text/event-stream"):
        raise SmokeError("authenticated GET unexpectedly advertised text/event-stream")


def rpc(url: str, token: str, rpc_id: int, method: str, params: dict, toolset: str = "") -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}).encode()
    status, headers, body = request(url, "POST", payload, auth=token, toolset=toolset)
    if status != 200:
        raise SmokeError(f"{method} status {status}, want 200")
    if headers.get("mcp-session-id"):
        raise SmokeError(f"{method} unexpectedly returned Mcp-Session-Id")
    if not headers.get("content-type", "").startswith("application/json"):
        raise SmokeError(f"{method} content-type {headers.get('content-type')!r}, want application/json")
    try:
        parsed = json.loads(body.decode())
    except json.JSONDecodeError as exc:
        raise SmokeError(f"{method} returned invalid JSON") from exc
    if parsed.get("error"):
        raise SmokeError(f"{method} returned JSON-RPC error code {parsed['error'].get('code')}")
    return parsed


def request(url: str, method: str, body: bytes | None = None, auth: str = "", protocol_version: str = PROTOCOL_VERSION, toolset: str = "") -> tuple[int, dict[str, str], bytes]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": protocol_version,
        "User-Agent": "cerebro-mcp-smoke/0",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    if auth:
        headers["Authorization"] = f"Bearer {auth}"
    if toolset:
        headers["X-Cerebro-MCP-Toolsets"] = toolset
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, normalize_headers(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, normalize_headers(exc.headers), exc.read()
    except urllib.error.URLError as exc:
        raise SmokeError(f"request failed: {exc.reason}") from exc


def normalize_headers(headers) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


class SmokeError(RuntimeError):
    pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeError as exc:
        print(f"mcp_smoke: {exc}", file=sys.stderr)
        raise SystemExit(1)
