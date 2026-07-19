#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any


CUTOVER_SCHEMA = "cerebro.web-monorepo-cutover-receipt/v1"
ROLLBACK_SCHEMA = "cerebro.web-monorepo-rollback-readiness-receipt/v1"
PRODUCT_RELEASE_SCHEMA = "cerebro.product-release/v1"
TARGET_RECEIPT_SCHEMA = "cerebro.private-product-release-target/v1"
RUNTIME_OBSERVATION_SCHEMA = "cerebro.web-runtime-observation/v1"
ROLLBACK_OBSERVATION_SCHEMA = "cerebro.web-rollback-rehearsal-observation/v1"
SOURCE_IDS = {"web_public", "web_private"}
COMMIT_PATTERN = r"[0-9a-f]{40}"
DIGEST_PATTERN = r"[0-9a-f]{64}"
IMAGE_DIGEST_PATTERN = r"sha256:[0-9a-f]{64}"


class ReceiptError(ValueError):
    """A bounded runtime authority input is incomplete or inconsistent."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReceiptError(code)


def _object(path: Path) -> tuple[dict[str, Any], bytes]:
    _require(path.is_file() and not path.is_symlink(), "input-unavailable")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError("invalid-json") from error
    _require(isinstance(value, dict), "invalid-json")
    return value, raw


def _keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == expected, code)
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _product_release(path: Path) -> tuple[dict[str, Any], str]:
    value, raw = _object(path)
    _keys(
        value,
        {
            "schema_version",
            "version",
            "commit",
            "runtime_image",
            "runtime_digest",
            "web_image",
            "web_digest",
            "slack_archive",
            "slack_sha256",
            "sdk_archive",
            "sdk_sha256",
        },
        "invalid-product-release",
    )
    _require(
        value["schema_version"] == PRODUCT_RELEASE_SCHEMA, "invalid-product-release"
    )
    _require(
        isinstance(value["commit"], str)
        and re.fullmatch(COMMIT_PATTERN, value["commit"]) is not None,
        "invalid-product-release",
    )
    _require(
        isinstance(value["web_digest"], str)
        and re.fullmatch(IMAGE_DIGEST_PATTERN, value["web_digest"]) is not None,
        "invalid-product-release",
    )
    return value, _sha256(raw)


def _target_receipt(path: Path, release: dict[str, Any]) -> tuple[dict[str, Any], str]:
    value, raw = _object(path)
    _keys(
        value,
        {
            "schema_version",
            "release",
            "target",
            "components",
            "runtime_contract_sha256",
            "idempotency_key",
        },
        "invalid-target-receipt",
    )
    _require(value["schema_version"] == TARGET_RECEIPT_SCHEMA, "invalid-target-receipt")
    release_block = _keys(
        value["release"],
        {"schema_version", "tag", "commit", "url", "manifest_sha256"},
        "invalid-target-receipt",
    )
    components = _keys(
        value["components"],
        {"runtime", "web", "slack_companion", "typescript_sdk"},
        "invalid-target-receipt",
    )
    web = _keys(components["web"], {"image", "digest"}, "invalid-target-receipt")
    _keys(
        value["target"],
        {"id", "apply_mode", "stack_file", "stack_sha256"},
        "invalid-target-receipt",
    )
    _require(
        release_block["commit"] == release["commit"]
        and release_block["tag"] == release["version"],
        "target-release-mismatch",
    )
    _require(
        web["image"] == release["web_image"] and web["digest"] == release["web_digest"],
        "target-web-mismatch",
    )
    unsigned = dict(value)
    idempotency_key = unsigned.pop("idempotency_key")
    _require(
        isinstance(idempotency_key, str)
        and re.fullmatch(DIGEST_PATTERN, idempotency_key) is not None
        and idempotency_key == _sha256(_canonical(unsigned)),
        "target-idempotency-mismatch",
    )
    return value, _sha256(raw)


def _observation(
    path: Path, expected_schema: str, expected_keys: set[str]
) -> tuple[dict[str, Any], str]:
    value, raw = _object(path)
    _keys(value, expected_keys, "invalid-observation")
    _require(value["schema_version"] == expected_schema, "invalid-observation")
    return value, _sha256(raw)


def _fresh(observed_at: Any, now: int, max_age: int) -> None:
    _require(
        isinstance(observed_at, int) and observed_at > 0, "invalid-observation-time"
    )
    _require(observed_at <= now, "future-observation")
    _require(now - observed_at <= max_age, "stale-observation")


def produce(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    _require(args.source_id in SOURCE_IDS, "source-not-allowlisted")
    _require(1 <= args.max_age_seconds <= 900, "invalid-max-age")
    now = args.authority_now_epoch or int(time.time())
    cutover_release, cutover_release_digest = _product_release(
        args.cutover_product_release
    )
    _, cutover_target_digest = _target_receipt(
        args.cutover_target_receipt, cutover_release
    )
    runtime, runtime_digest = _observation(
        args.runtime_observation,
        RUNTIME_OBSERVATION_SCHEMA,
        {
            "schema_version",
            "product_release_commit_sha",
            "private_target_commit_sha",
            "web_digest",
            "target_receipt_sha256",
            "runtime_state",
            "traffic_state",
            "probe_state",
            "observed_at_epoch",
        },
    )
    _fresh(runtime["observed_at_epoch"], now, args.max_age_seconds)
    _require(
        runtime["product_release_commit_sha"] == cutover_release["commit"],
        "runtime-release-mismatch",
    )
    _require(
        runtime["web_digest"] == cutover_release["web_digest"], "runtime-web-mismatch"
    )
    _require(
        runtime["target_receipt_sha256"] == cutover_target_digest,
        "runtime-target-mismatch",
    )
    _require(
        runtime["runtime_state"] == "ready"
        and runtime["traffic_state"] == "serving"
        and runtime["probe_state"] == "passed",
        "runtime-not-ready",
    )

    cutover = {
        "schema_version": CUTOVER_SCHEMA,
        "source_repository_id": args.source_id,
        "release": {
            "public_commit_sha": cutover_release["commit"],
            "web_digest": cutover_release["web_digest"],
        },
        "deployment": {
            "private_commit_sha": runtime["private_target_commit_sha"],
            "runtime_state": "ready",
            "traffic_state": "serving",
            "probe_state": "passed",
            "observed_at_epoch": runtime["observed_at_epoch"],
        },
        "evidence": {
            "product_release_sha256": cutover_release_digest,
            "target_receipt_sha256": cutover_target_digest,
            "runtime_observation_sha256": runtime_digest,
        },
    }
    cutover_digest = _sha256(_canonical(cutover))

    rollback_release, rollback_release_digest = _product_release(
        args.rollback_product_release
    )
    _, rollback_target_digest = _target_receipt(
        args.rollback_target_receipt, rollback_release
    )
    rehearsal, rehearsal_digest = _observation(
        args.rollback_observation,
        ROLLBACK_OBSERVATION_SCHEMA,
        {
            "schema_version",
            "private_target_commit_sha",
            "rollback_release_commit_sha",
            "rollback_web_digest",
            "target_receipt_sha256",
            "artifact_state",
            "render_state",
            "workflow_state",
            "rehearsal_state",
            "observed_at_epoch",
        },
    )
    _fresh(rehearsal["observed_at_epoch"], now, args.max_age_seconds)
    _require(
        rollback_release["commit"] != cutover_release["commit"]
        and rollback_release["web_digest"] != cutover_release["web_digest"],
        "rollback-not-distinct",
    )
    _require(
        rehearsal["private_target_commit_sha"] == runtime["private_target_commit_sha"],
        "rollback-private-target-mismatch",
    )
    _require(
        rehearsal["rollback_release_commit_sha"] == rollback_release["commit"]
        and rehearsal["rollback_web_digest"] == rollback_release["web_digest"],
        "rollback-release-mismatch",
    )
    _require(
        rehearsal["target_receipt_sha256"] == rollback_target_digest,
        "rollback-target-mismatch",
    )
    _require(
        rehearsal["artifact_state"] == "available"
        and rehearsal["render_state"] == "verified"
        and rehearsal["workflow_state"] == "verified"
        and rehearsal["rehearsal_state"] == "verified",
        "rollback-not-ready",
    )
    rollback = {
        "schema_version": ROLLBACK_SCHEMA,
        "source_repository_id": args.source_id,
        "cutover_receipt_sha256": cutover_digest,
        "rollback_target": {
            "public_commit_sha": rollback_release["commit"],
            "private_commit_sha": rehearsal["private_target_commit_sha"],
            "web_digest": rollback_release["web_digest"],
        },
        "readiness": {
            "artifact_state": "available",
            "render_state": "verified",
            "workflow_state": "verified",
            "rehearsal_state": "verified",
            "observed_at_epoch": rehearsal["observed_at_epoch"],
        },
        "evidence": {
            "product_release_sha256": rollback_release_digest,
            "target_receipt_sha256": rollback_target_digest,
            "rehearsal_observation_sha256": rehearsal_digest,
        },
    }
    return cutover, rollback


def _write_new(path: Path, value: dict[str, Any]) -> None:
    _require(
        path.parent.is_dir() and not path.parent.is_symlink(), "output-unavailable"
    )
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(_canonical(value))
    except FileExistsError as error:
        raise ReceiptError("output-exists") from error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Produce bounded web cutover and rollback-readiness receipts."
    )
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--cutover-product-release", type=Path, required=True)
    parser.add_argument("--cutover-target-receipt", type=Path, required=True)
    parser.add_argument("--runtime-observation", type=Path, required=True)
    parser.add_argument("--rollback-product-release", type=Path, required=True)
    parser.add_argument("--rollback-target-receipt", type=Path, required=True)
    parser.add_argument("--rollback-observation", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--authority-now-epoch", type=int, default=0)
    parser.add_argument("--max-age-seconds", type=int, default=900)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        cutover, rollback = produce(args)
        _write_new(
            args.output_directory / f"{args.source_id}.cutover-receipt.json", cutover
        )
        try:
            _write_new(
                args.output_directory
                / f"{args.source_id}.rollback-readiness-receipt.json",
                rollback,
            )
        except (OSError, ReceiptError):
            (args.output_directory / f"{args.source_id}.cutover-receipt.json").unlink(
                missing_ok=True
            )
            raise
    except (OSError, ReceiptError) as error:
        code = str(error) if isinstance(error, ReceiptError) else "io-failure"
        print(f"web-runtime-receipts: {code}", file=sys.stderr)
        return 1
    print("web-runtime-receipts: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
