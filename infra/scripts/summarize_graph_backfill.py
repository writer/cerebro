#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any

try:
    from scripts.graph_backfill_contract import BackfillPlanError, STATE_SCHEMA_VERSION
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.graph_backfill_contract import BackfillPlanError, STATE_SCHEMA_VERSION


NEXT_ACTIONS = {
    "authentication": "Rotate or correct the source credential, then resume this workflow run.",
    "authorization": "Restore the source account permissions, then resume this workflow run.",
    "source_configuration": "Repair the shared source configuration, then resume this workflow run.",
    "rate_limited": "Wait for the provider limit window or lower the batch bounds, then resume this workflow run.",
    "target_configuration": "Repair the runtime schedule or deployed target, then create a new plan.",
    "transient": "Resume the workflow run. Completed runtimes will not run again.",
    "runtime_failure": "Inspect the failed runtime logs, correct the runtime-specific failure, then resume this workflow run.",
}


def _load_states(paths: list[Path]) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != STATE_SCHEMA_VERSION
        ):
            raise BackfillPlanError(f"invalid backfill state file: {path}")
        states.append(state)
    if not states:
        raise BackfillPlanError("no backfill state files were provided")
    plan_hashes = {str(state.get("plan_hash") or "") for state in states}
    if len(plan_hashes) != 1 or not next(iter(plan_hashes)):
        raise BackfillPlanError("backfill state files do not belong to one plan")
    source_ids = [str(state.get("source_id") or "") for state in states]
    if len(source_ids) != len(set(source_ids)):
        raise BackfillPlanError("backfill state files contain duplicate source lanes")
    return sorted(states, key=lambda state: str(state["source_id"]))


def summarize_states(states: list[dict[str, Any]]) -> dict[str, Any]:
    target_counts: Counter[str] = Counter()
    failure_counts: Counter[str] = Counter()
    sources: list[dict[str, Any]] = []
    for state in states:
        targets = state.get("targets") or []
        for target in targets:
            status = str(target.get("status") or "unknown")
            failure_class = str(target.get("failure_class") or "")
            target_counts[status] += 1
            if failure_class and status in {"failed", "blocked"}:
                failure_counts[failure_class] += 1
        sources.append(
            {
                "source_id": state["source_id"],
                "status": state.get("status", "unknown"),
                "completed": sum(
                    1 for target in targets if target.get("status") == "completed"
                ),
                "failed": sum(
                    1 for target in targets if target.get("status") == "failed"
                ),
                "blocked": sum(
                    1 for target in targets if target.get("status") == "blocked"
                ),
                "total": len(targets),
            }
        )
    status = (
        "completed"
        if all(source["status"] == "completed" for source in sources)
        else "incomplete"
    )
    failure_classes = dict(sorted(failure_counts.items()))
    return {
        "schema_version": 1,
        "plan_hash": states[0]["plan_hash"],
        "stack_name": states[0].get("stack_name"),
        "mode": states[0].get("mode"),
        "status": status,
        "target_counts": dict(sorted(target_counts.items())),
        "failure_classes": failure_classes,
        "next_actions": [
            NEXT_ACTIONS[name] for name in failure_classes if name in NEXT_ACTIONS
        ],
        "sources": sources,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Source runtime backfill",
        "",
        f"Status: `{summary['status']}`  ",
        f"Stack: `{summary['stack_name']}`  ",
        f"Mode: `{summary['mode']}`  ",
        f"Plan: `{summary['plan_hash']}`",
        "",
        "| Source | Completed | Failed | Blocked | Total |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for source in summary["sources"]:
        lines.append(
            f"| `{source['source_id']}` | {source['completed']} | {source['failed']} | {source['blocked']} | {source['total']} |"
        )
    if summary["next_actions"]:
        lines.extend(["", "## Required actions", ""])
        lines.extend(f"- {action}" for action in summary["next_actions"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate source-lane backfill checkpoints."
    )
    parser.add_argument("state_files", nargs="+", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = summarize_states(_load_states(args.state_files))
    args.json_output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown_output.write_text(render_markdown(summary), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BackfillPlanError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
