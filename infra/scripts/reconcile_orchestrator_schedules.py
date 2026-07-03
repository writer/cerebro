#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
from typing import Any

try:
    from aws.source_runtime_scope import load_cerebro_config, runtime_family, runtime_ids_from_command, runtime_source_id
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_runtime_scope import load_cerebro_config, runtime_family, runtime_ids_from_command, runtime_source_id


@dataclass(frozen=True)
class ScheduleReconcileRow:
    runtime_id: str
    source_id: str
    family: str
    schedule_name: str
    schedule_expression: str
    declared_runtime: bool
    declared_schedule: bool
    state: str


def _schedule_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for schedule in config.get("orchestratorSchedules") or []:
        if not isinstance(schedule, dict):
            continue
        for runtime_id in runtime_ids_from_command(schedule.get("command")):
            mapped[runtime_id] = schedule
    return mapped


def reconcile_schedules(config: dict[str, Any], source_id: str = "", requested: set[str] | None = None) -> list[ScheduleReconcileRow]:
    schedules = _schedule_map(config)
    requested = requested or set()
    rows: list[ScheduleReconcileRow] = []
    seen: set[str] = set()
    for runtime in config.get("sourceRuntimes") or []:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id") or "").strip()
        if not runtime_id:
            continue
        runtime_source = runtime_source_id(runtime)
        if source_id and runtime_source != source_id:
            continue
        if requested and runtime_id not in requested:
            continue
        schedule = schedules.get(runtime_id)
        seen.add(runtime_id)
        rows.append(
            ScheduleReconcileRow(
                runtime_id=runtime_id,
                source_id=runtime_source,
                family=runtime_family(runtime),
                schedule_name=str((schedule or {}).get("name") or "").strip(),
                schedule_expression=str((schedule or {}).get("scheduleExpression") or "").strip(),
                declared_runtime=True,
                declared_schedule=schedule is not None,
                state="ok" if schedule else "missing_schedule",
            )
        )
    for runtime_id, schedule in schedules.items():
        if runtime_id in seen:
            continue
        if requested and runtime_id not in requested:
            continue
        rows.append(
            ScheduleReconcileRow(
                runtime_id=runtime_id,
                source_id="",
                family="",
                schedule_name=str(schedule.get("name") or "").strip(),
                schedule_expression=str(schedule.get("scheduleExpression") or "").strip(),
                declared_runtime=False,
                declared_schedule=True,
                state="orphan_schedule",
            )
        )
    return sorted(rows, key=lambda row: (row.state != "ok", row.source_id, row.runtime_id))


def _write_tsv(rows: list[ScheduleReconcileRow]) -> None:
    print("runtime_id\tsource_id\tfamily\tschedule_name\tschedule_expression\tdeclared_runtime\tdeclared_schedule\tstate")
    for row in rows:
        print("\t".join(str(value).lower() if isinstance(value, bool) else str(value) for value in asdict(row).values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconcile declared source runtimes with orchestrator schedules.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--source-id", default="")
    parser.add_argument("--runtime-id", action="append", default=[])
    parser.add_argument("--format", choices=["tsv", "json"], default="tsv")
    parser.add_argument("--fail-on-drift", action="store_true")
    args = parser.parse_args(argv)

    rows = reconcile_schedules(load_cerebro_config(args.stack_file), args.source_id, set(args.runtime_id or []))
    if args.format == "json":
        print(json.dumps([asdict(row) for row in rows], indent=2, sort_keys=True))
    else:
        _write_tsv(rows)
    if args.fail_on_drift and any(row.state != "ok" for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
