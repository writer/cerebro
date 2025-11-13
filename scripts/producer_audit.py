"""Audit helpers for finding producers.

Usage:
    uv run python scripts/producer_audit.py

Outputs a JSON summary listing each producer, whether it references the
standardized evidence builders, and whether it normalizes the context via
``ProducerRunContext.ensure``.
"""

from __future__ import annotations

import argparse
import inspect
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from cerebro.findings.producers.registry import (
    auto_discover_producers,
    get_producer_registry,
)

BUILDER_TOKENS = (
    "build_identity_user_evidence",
    "build_ci_pipeline_exposure",
    "build_network_exposure_evidence",
    "build_storage_secret_evidence",
    "build_runner_group_exposure",
    "build_runner_host_exposure",
    "build_external_sharing_evidence",
    "build_sharepoint_anonymous_link_evidence",
    "build_security_group_exposure",
    "build_workflow_permission_evidence",
    "build_telemetry_incident_evidence",
)


@dataclass
class ProducerAuditRecord:
    name: str
    module: str
    builder_used: bool
    run_context_normalized: bool


def _detect_builder_usage(source: str) -> bool:
    return any(token in source for token in BUILDER_TOKENS)


def _detect_context_normalization(source: str) -> bool:
    return "ProducerRunContext.ensure" in source or "ProducerContext.ensure" in source


def audit_producers() -> list[ProducerAuditRecord]:
    auto_discover_producers()
    registry = get_producer_registry()
    records: list[ProducerAuditRecord] = []
    for producer_name, producer in sorted(registry._producers.items()):
        cls = producer.__class__
        try:
            source = inspect.getsource(cls.evaluate)
        except OSError:
            source = ""
        records.append(
            ProducerAuditRecord(
                name=producer_name,
                module=cls.__module__,
                builder_used=_detect_builder_usage(source),
                run_context_normalized=_detect_context_normalization(source),
            )
        )
    return records


def _collect_violations(
    records: Sequence[ProducerAuditRecord],
    builder_prefixes: Sequence[str],
    context_prefixes: Sequence[str],
) -> list[str]:
    violations: list[str] = []

    if builder_prefixes:
        for prefix in builder_prefixes:
            missing = [
                record
                for record in records
                if record.module.startswith(prefix) and not record.builder_used
            ]
            if missing:
                violations.append(
                    "Producers missing standardized builder usage: "
                    + ", ".join(record.name for record in missing)
                    + f" (prefix '{prefix}')"
                )

    if context_prefixes:
        for prefix in context_prefixes:
            missing = [
                record
                for record in records
                if record.module.startswith(prefix)
                and not record.run_context_normalized
            ]
            if missing:
                violations.append(
                    "Producers missing ProducerRunContext.ensure: "
                    + ", ".join(record.name for record in missing)
                    + f" (prefix '{prefix}')"
                )

    return violations


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit producer builder usage")
    parser.add_argument(
        "--require-builder-prefix",
        action="append",
        default=[],
        help="Module prefix that must include standardized evidence builder usage.",
    )
    parser.add_argument(
        "--require-context-prefix",
        action="append",
        default=[],
        help="Module prefix that must normalize context via ProducerRunContext.ensure.",
    )
    parser.add_argument(
        "--output-format",
        choices={"json", "compact"},
        default="json",
        help="Output format for audit results.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    records = audit_producers()

    if args.output_format == "json":
        print(json.dumps([asdict(record) for record in records], indent=2))
    else:
        for record in records:
            print(
                f"{record.module}:{record.name} builder_used={record.builder_used} "
                f"run_context_normalized={record.run_context_normalized}"
            )

    violations = _collect_violations(
        records,
        args.require_builder_prefix,
        args.require_context_prefix,
    )

    if violations:
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
