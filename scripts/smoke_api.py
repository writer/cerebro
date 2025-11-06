#!/usr/bin/env python3
"""Lightweight smoke tests for Cerebro API health endpoints."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import httpx


DEFAULT_TARGETS = ("core", "db")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@dataclass(frozen=True)
class Endpoint:
    name: str
    path: str
    description: str


ENDPOINTS = {
    "core": Endpoint(name="core", path="/health", description="Core service health"),
    "db": Endpoint(name="db", path="/health/db", description="Database connectivity"),
    "encryption": Endpoint(name="encryption", path="/health/encryption", description="Encryption service"),
    "celery": Endpoint(name="celery", path="/health/celery", description="Celery worker status"),
}


@dataclass
class CheckResult:
    endpoint: Endpoint
    ok: bool
    status_code: Optional[int]
    detail: Optional[str]

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint.name,
            "path": self.endpoint.path,
            "ok": self.ok,
            "status_code": self.status_code,
            "detail": self.detail,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run API smoke checks")
    parser.add_argument(
        "--mode",
        choices=("http", "asgi"),
        default=os.environ.get("CEREBRO_SMOKE_MODE", "http"),
        help="Execution mode: http hits a running server, asgi runs in-process",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("CEREBRO_SMOKE_BASE_URL", "http://localhost:8000"),
        help="Base URL for HTTP mode",
    )
    parser.add_argument(
        "--targets",
        default=os.environ.get("CEREBRO_SMOKE_TARGETS", ",".join(DEFAULT_TARGETS)),
        help="Comma-separated list of endpoints to verify (available: core, db, encryption, celery)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CEREBRO_SMOKE_TIMEOUT", "5")),
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=int(os.environ.get("CEREBRO_SMOKE_RETRIES", "3")),
        help="Number of attempts per endpoint",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=float(os.environ.get("CEREBRO_SMOKE_RETRY_DELAY", "1")),
        help="Delay between retries in seconds",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("CEREBRO_SMOKE_DATABASE_URL"),
        help="Database URL override for ASGI mode",
    )
    parser.add_argument(
        "--environment",
        default=os.environ.get("CEREBRO_SMOKE_ENV", "testing"),
        help="Environment label for ASGI mode",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON (useful for CI)",
    )
    return parser.parse_args()


def resolve_targets(targets_arg: str) -> List[Endpoint]:
    targets: List[Endpoint] = []
    for name in [item.strip().lower() for item in targets_arg.split(",") if item.strip()]:
        if name not in ENDPOINTS:
            raise SystemExit(f"Unknown smoke target '{name}'. Valid options: {', '.join(ENDPOINTS)}")
        targets.append(ENDPOINTS[name])
    if not targets:
        targets = [ENDPOINTS[name] for name in DEFAULT_TARGETS]
    return targets


def configure_environment(args: argparse.Namespace) -> None:
    if args.mode == "asgi":
        os.environ.setdefault("ENVIRONMENT", args.environment)
        # Ensure secrets and DB defaults exist for in-process health checks
        os.environ.setdefault("SECRET_KEY", "dev-smoke-secret-key")
        if args.database_url:
            os.environ.setdefault("DATABASE_URL", args.database_url)
        else:
            os.environ.setdefault(
                "DATABASE_URL",
                "sqlite+aiosqlite:///./cerebro_smoke.db",
            )


async def run_http_checks(
    client: httpx.AsyncClient,
    endpoints: Iterable[Endpoint],
    *,
    retries: int,
    retry_delay: float,
    timeout: float,
) -> List[CheckResult]:
    results: List[CheckResult] = []

    for endpoint in endpoints:
        last_error: Optional[str] = None
        for attempt in range(1, retries + 1):
            try:
                response = await client.get(endpoint.path, timeout=timeout)
                ok = response.status_code == 200
                detail = None if ok else response.text
                results.append(
                    CheckResult(
                        endpoint=endpoint,
                        ok=ok,
                        status_code=response.status_code,
                        detail=detail,
                    )
                )
                break
            except httpx.RequestError as exc:  # pragma: no cover - exercised in CI/real runs
                last_error = str(exc)
                if attempt == retries:
                    results.append(
                        CheckResult(
                            endpoint=endpoint,
                            ok=False,
                            status_code=None,
                            detail=last_error,
                        )
                    )
                else:
                    await asyncio.sleep(retry_delay)
        else:  # pragma: no cover - defensive
            results.append(
                CheckResult(
                    endpoint=endpoint,
                    ok=False,
                    status_code=None,
                    detail=last_error,
                )
            )

    return results


async def run_smoke(args: argparse.Namespace, endpoints: List[Endpoint]) -> List[CheckResult]:
    if args.mode == "asgi":
        from cerebro.api.main import app  # Imported lazily after env configuration

        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            return await run_http_checks(
                client,
                endpoints,
                retries=args.retries,
                retry_delay=args.retry_delay,
                timeout=args.timeout,
            )

    async with httpx.AsyncClient(base_url=args.base_url) as client:
        return await run_http_checks(
            client,
            endpoints,
            retries=args.retries,
            retry_delay=args.retry_delay,
            timeout=args.timeout,
        )


def print_results(results: List[CheckResult], emit_json: bool) -> int:
    if emit_json:
        print(json.dumps([result.to_dict() for result in results], indent=2))
    else:
        for result in results:
            status = "✅" if result.ok else "❌"
            status_code = result.status_code if result.status_code is not None else "n/a"
            detail = f" ({result.detail})" if result.detail else ""
            print(f"{status} {result.endpoint.name:<10} {result.endpoint.path:<18} [{status_code}] {detail}")

    return 0 if all(result.ok for result in results) else 1


def main() -> int:
    args = parse_args()
    configure_environment(args)
    endpoints = resolve_targets(args.targets)

    try:
        results = asyncio.run(run_smoke(args, endpoints))
    except KeyboardInterrupt:  # pragma: no cover - manual interruption
        return 130
    except Exception as exc:
        print(f"Smoke run failed: {exc}", file=sys.stderr)
        return 1

    return print_results(results, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
