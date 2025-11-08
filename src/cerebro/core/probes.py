"""Health probe helpers and CLI entrypoints for Cerebro services."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Dict, Optional, Tuple

from sqlalchemy import text

from cerebro.core.database import async_session_factory

logger = logging.getLogger(__name__)


async def check_database(timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """Verify database connectivity."""

    try:
        async with async_session_factory() as session:
            await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=timeout)
        return True, None
    except Exception as exc:  # pragma: no cover - surface runtime errors
        return False, str(exc)


async def check_celery_workers(timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """Ensure at least one Celery worker responds to control ping."""

    try:
        from cerebro.tasks.celery_app import celery_app
    except Exception as exc:  # pragma: no cover - import errors surfaced at runtime
        return False, f"Failed to import celery app: {exc}"

    loop = asyncio.get_running_loop()

    def _ping() -> bool:
        try:
            responses = celery_app.control.ping(timeout=timeout)
        except Exception as exc:  # pragma: no cover - celery communication errors
            raise RuntimeError(str(exc)) from exc
        return bool(responses)

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _ping),
            timeout=timeout + 1.0,
        )
    except Exception as exc:
        return False, str(exc)

    if not result:
        return False, "No Celery workers responded to ping"

    return True, None


async def check_broker_connection(timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """Verify connectivity to the Celery broker."""

    try:
        from cerebro.tasks.celery_app import celery_app
    except Exception as exc:  # pragma: no cover - import errors surfaced at runtime
        return False, f"Failed to import celery app: {exc}"

    loop = asyncio.get_running_loop()

    def _connect() -> None:
        connection = celery_app.connection()
        try:
            connection.connect()
        finally:
            connection.release()

    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, _connect),
            timeout=timeout + 1.0,
        )
    except Exception as exc:
        return False, str(exc)

    return True, None


async def _run_target(target: str, timeout: float) -> Tuple[bool, Dict[str, Dict[str, Optional[str]]]]:
    if target == "api-ready":
        db_ok, db_error = await check_database(timeout)
        celery_ok, celery_error = await check_celery_workers(timeout)
        broker_ok, broker_error = await check_broker_connection(timeout)

        ready = db_ok and celery_ok and broker_ok
        checks = {
            "database": {"healthy": db_ok, "error": db_error},
            "celery": {"healthy": celery_ok, "error": celery_error},
            "broker": {"healthy": broker_ok, "error": broker_error},
        }
        return ready, checks

    if target == "worker-ready":
        celery_ok, celery_error = await check_celery_workers(timeout)
        return celery_ok, {"celery": {"healthy": celery_ok, "error": celery_error}}

    if target == "beat-ready":
        broker_ok, broker_error = await check_broker_connection(timeout)
        return broker_ok, {"broker": {"healthy": broker_ok, "error": broker_error}}

    if target == "database":
        db_ok, db_error = await check_database(timeout)
        return db_ok, {"database": {"healthy": db_ok, "error": db_error}}

    raise ValueError(f"Unknown probe target: {target}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cerebro service health probes")
    parser.add_argument(
        "target",
        choices=["api-ready", "worker-ready", "beat-ready", "database"],
        help="Probe target to execute",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds for individual dependency checks",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        ready, checks = asyncio.run(_run_target(args.target, args.timeout))
    except KeyboardInterrupt:  # pragma: no cover - CLI interrupt handling
        return 130
    except Exception as exc:  # pragma: no cover - surface unexpected errors
        logger.error("Probe execution failed", target=args.target, error=str(exc))
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    payload = {
        "status": "ready" if ready else "degraded",
        "checks": checks,
    }
    print(json.dumps(payload))
    return 0 if ready else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
