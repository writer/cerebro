"""Generate a lightweight Snowflake usage report for Cerebro workloads.

This script queries SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY to summarize activity by
QUERY_TAG and warehouse.
"""

from __future__ import annotations

import argparse
import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


def _get_int_env(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise SystemExit(f"Invalid integer for {name}: {value!r}") from exc


def _default_query_tag() -> str:
    environment = (os.getenv("ENVIRONMENT") or "unknown").strip().lower()
    return f"cerebro:{environment}:usage-report"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize Snowflake QUERY_HISTORY for Cerebro.")
    parser.add_argument(
        "--url",
        default=os.getenv("SNOWFLAKE_DATABASE_URL"),
        help="Snowflake SQLAlchemy URL (defaults to SNOWFLAKE_DATABASE_URL)",
    )
    parser.add_argument("--days", type=int, default=7, help="Lookback window in days")
    parser.add_argument(
        "--tag-prefix",
        default="cerebro:%",
        help="SQL LIKE pattern for query_tag filtering (default: cerebro:%%)",
    )
    parser.add_argument("--limit", type=int, default=50, help="Max result rows")
    parser.add_argument("--role", default=None, help="Optional Snowflake role override")
    parser.add_argument("--warehouse", default=None, help="Optional Snowflake warehouse override")
    args = parser.parse_args(argv)

    if not args.url:
        raise SystemExit("Snowflake URL not provided; set SNOWFLAKE_DATABASE_URL or pass --url")

    url = make_url(args.url)
    query_tag = os.getenv("SNOWFLAKE_QUERY_TAG") or _default_query_tag()
    application = os.getenv("SNOWFLAKE_APPLICATION", "cerebro")

    session_parameters: dict[str, object] = {
        "QUERY_TAG": query_tag,
        "TIMEZONE": os.getenv("SNOWFLAKE_TIMEZONE", "UTC"),
    }
    if (statement_timeout := _get_int_env("SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS")) is None:
        statement_timeout = 300
    session_parameters["STATEMENT_TIMEOUT_IN_SECONDS"] = statement_timeout

    connect_args: dict[str, object] = {
        "client_session_keep_alive": True,
        "application": application,
        "session_parameters": session_parameters,
    }
    if args.role or os.getenv("SNOWFLAKE_ROLE"):
        connect_args["role"] = args.role or os.getenv("SNOWFLAKE_ROLE")
    if args.warehouse or os.getenv("SNOWFLAKE_WAREHOUSE"):
        connect_args["warehouse"] = args.warehouse or os.getenv("SNOWFLAKE_WAREHOUSE")

    engine = create_engine(
        url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    query = text(
        """
        SELECT
            query_tag,
            warehouse_name,
            COUNT(*) AS query_count,
            SUM(total_elapsed_time) / 1000.0 AS total_elapsed_seconds,
            AVG(total_elapsed_time) / 1000.0 AS avg_elapsed_seconds,
            SUM(bytes_scanned) AS bytes_scanned,
            SUM(credits_used_cloud_services) AS cloud_services_credits
        FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE start_time >= DATEADD(day, -:days, CURRENT_TIMESTAMP())
          AND query_tag LIKE :tag_prefix
        GROUP BY query_tag, warehouse_name
        ORDER BY cloud_services_credits DESC NULLS LAST, total_elapsed_seconds DESC
        LIMIT :limit
        """
    )

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                query,
                {
                    "days": args.days,
                    "tag_prefix": args.tag_prefix,
                    "limit": args.limit,
                },
            ).mappings().all()

        if not rows:
            print("No matching queries found.")
            return 0

        print(f"Snowflake usage report (last {args.days} days)\n")
        for row in rows:
            print(
                " - ",
                row.get("query_tag"),
                "warehouse=", row.get("warehouse_name"),
                "count=", row.get("query_count"),
                "total_s=", round(float(row.get("total_elapsed_seconds") or 0.0), 2),
                "avg_s=", round(float(row.get("avg_elapsed_seconds") or 0.0), 2),
                "bytes_scanned=", int(row.get("bytes_scanned") or 0),
                "cloud_credits=", float(row.get("cloud_services_credits") or 0.0),
                sep="",
            )

        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
