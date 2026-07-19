#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Any


APPLY_CONTRACT_SCHEMA = "cerebro-repository-final-archive-apply-contract/v1"
APPLY_RECEIPT_SCHEMA = "cerebro-repository-final-archive-apply-receipt/v1"
LIVE_OBSERVATION_SCHEMA = "cerebro-repository-archive-live-observation/v1"
FINAL_LOCK_SCHEMA = "cerebro-repository-final-archive-lock/v1"
FINAL_RECEIPT_SCHEMA = "cerebro-repository-final-archive-receipt/v1"
FINAL_VALIDATOR = Path(__file__).with_name("validate_final_archive_contract.sh")
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_CONTRACT_LIFETIME_SECONDS = 300
ALLOWED_SOURCE_IDS = frozenset({"slack_companion", "web_public", "web_private"})
LOWER_HEX = frozenset("0123456789abcdef")


class GateError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class Artifact:
    data: bytes
    sha256: str


@dataclass(frozen=True)
class GateArguments:
    phase: str
    apply_contract: Path
    lock: Path
    readiness_receipt: Path
    ledger: Path
    source_authority: Path
    inventory_receipt: Path | None
    cutover_receipt: Path
    rollback_receipt: Path
    pre_apply_observation: Path
    apply_receipt: Path | None
    postcondition_observation: Path | None


JsonObject = dict[str, Any]


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise GateError(reason)


def _read_artifact(path: Path) -> Artifact:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise GateError("input-unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        _require(stat.S_ISREG(metadata.st_mode), "input-unavailable")
        _require(0 < metadata.st_size <= MAX_INPUT_BYTES, "input-unavailable")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        _require(0 < len(data) <= MAX_INPUT_BYTES, "input-unavailable")
        return Artifact(data=data, sha256=hashlib.sha256(data).hexdigest())
    except OSError as error:
        raise GateError("input-unavailable") from error
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> JsonObject:
    value: JsonObject = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def _load_json(artifact: Artifact, reason: str) -> JsonObject:
    try:
        value = json.loads(
            artifact.data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise GateError(reason) from error
    _require(type(value) is dict, reason)
    return value


def _object(value: object, reason: str) -> JsonObject:
    _require(type(value) is dict, reason)
    return value


def _exact_keys(value: JsonObject, expected: set[str], reason: str) -> None:
    _require(set(value) == expected, reason)


def _integer(
    value: object, reason: str, *, minimum: int = 1, maximum: int | None = None
) -> int:
    _require(type(value) is int and value >= minimum, reason)
    if maximum is not None:
        _require(value <= maximum, reason)
    return value


def _commit(value: object, reason: str) -> str:
    _require(
        type(value) is str and len(value) == 40 and set(value) <= LOWER_HEX, reason
    )
    return value


def _digest(value: object, reason: str) -> str:
    _require(
        type(value) is str and len(value) == 64 and set(value) <= LOWER_HEX, reason
    )
    return value


def _source_id(value: object, reason: str) -> str:
    _require(type(value) is str and value in ALLOWED_SOURCE_IDS, reason)
    return value


def _snapshot(value: object, reason: str) -> dict[str, str]:
    snapshot = _object(value, reason)
    _exact_keys(
        snapshot,
        {
            "source_main_commit_sha",
            "source_tree_sha",
            "public_target_commit_sha",
            "private_target_commit_sha",
        },
        reason,
    )
    return {key: _commit(snapshot[key], reason) for key in sorted(snapshot)}


def _lock_snapshot(lock: JsonObject) -> tuple[str, dict[str, str], int]:
    reason = "invalid-final-lock"
    _require(lock.get("schema_version") == FINAL_LOCK_SCHEMA, reason)
    source_id = _source_id(lock.get("source_repository_id"), reason)
    source = _object(lock.get("source"), reason)
    targets = _object(lock.get("targets"), reason)
    authorities = _object(lock.get("authorities"), reason)
    snapshot = {
        "source_main_commit_sha": _commit(source.get("main_commit_sha"), reason),
        "source_tree_sha": _commit(source.get("tree_sha"), reason),
        "public_target_commit_sha": _commit(targets.get("public_commit_sha"), reason),
        "private_target_commit_sha": _commit(targets.get("private_commit_sha"), reason),
    }
    max_age = _integer(
        authorities.get("max_observation_age_seconds"), reason, maximum=900
    )
    return source_id, snapshot, max_age


def _validate_readiness_receipt(receipt: JsonObject, source_id: str) -> None:
    reason = "invalid-readiness-receipt"
    _require(receipt.get("schema_version") == FINAL_RECEIPT_SCHEMA, reason)
    _require(receipt.get("source_repository_id") == source_id, reason)
    _require(receipt.get("intent") == "dry-run", reason)
    _require(receipt.get("state") == "verified", reason)
    postcondition = _object(receipt.get("postcondition"), reason)
    _require(postcondition.get("checked") is False, reason)
    _require(postcondition.get("archived") is False, reason)
    _require(postcondition.get("observed_at_epoch") == 0, reason)


def _validate_live_observation(
    value: JsonObject,
    *,
    expected_phase: str,
    expected_source_id: str,
) -> tuple[dict[str, str], int, dict[str, str]]:
    reason = "invalid-live-observation"
    _exact_keys(
        value,
        {
            "schema_version",
            "source_repository_id",
            "phase",
            "observed_at_epoch",
            "snapshot",
            "repository",
            "evidence",
        },
        reason,
    )
    _require(value.get("schema_version") == LIVE_OBSERVATION_SCHEMA, reason)
    _require(value.get("source_repository_id") == expected_source_id, reason)
    _require(value.get("phase") == expected_phase, reason)
    observed_at = _integer(value.get("observed_at_epoch"), reason)
    snapshot = _snapshot(value.get("snapshot"), reason)

    repository = _object(value.get("repository"), reason)
    _exact_keys(
        repository,
        {"archived", "open_pull_request_count", "open_issue_count"},
        reason,
    )
    expected_archived = expected_phase == "postcondition"
    _require(repository.get("archived") is expected_archived, reason)
    _require(repository.get("open_pull_request_count") == 0, reason)
    _require(repository.get("open_issue_count") == 0, reason)

    evidence = _object(value.get("evidence"), reason)
    _exact_keys(
        evidence,
        {"repository_metadata_sha256", "default_branch_ref_sha256"},
        reason,
    )
    validated_evidence = {
        key: _digest(evidence[key], reason) for key in sorted(evidence)
    }
    return snapshot, observed_at, validated_evidence


def _validate_apply_contract(
    contract: JsonObject,
    *,
    source_id: str,
    expected_snapshot: dict[str, str],
    lock_max_age: int,
    artifacts: dict[str, Artifact | None],
    pre_observed_at: int,
    now_epoch: int,
) -> tuple[int, int, int, int]:
    reason = "invalid-apply-contract"
    _exact_keys(
        contract,
        {
            "schema_version",
            "source_repository_id",
            "state",
            "validity",
            "artifacts",
            "snapshot",
            "requirements",
        },
        reason,
    )
    _require(contract.get("schema_version") == APPLY_CONTRACT_SCHEMA, reason)
    _require(contract.get("source_repository_id") == source_id, reason)
    _require(contract.get("state") == "sealed", reason)
    _require(
        _snapshot(contract.get("snapshot"), reason) == expected_snapshot,
        "snapshot-mismatch",
    )

    validity = _object(contract.get("validity"), reason)
    _exact_keys(validity, {"sealed_at_epoch", "expires_at_epoch"}, reason)
    sealed_at = _integer(validity.get("sealed_at_epoch"), reason)
    expires_at = _integer(validity.get("expires_at_epoch"), reason)
    _require(sealed_at <= now_epoch, "future-apply-contract")
    _require(sealed_at >= pre_observed_at, reason)
    _require(expires_at >= now_epoch, "stale-apply-contract")
    _require(expires_at > sealed_at, reason)
    _require(
        expires_at - sealed_at <= min(lock_max_age, MAX_CONTRACT_LIFETIME_SECONDS),
        reason,
    )

    requirements = _object(contract.get("requirements"), reason)
    _exact_keys(
        requirements,
        {
            "source_head_revalidation_required",
            "max_pre_apply_observation_age_seconds",
            "postcondition_receipt_required",
            "max_postcondition_observation_age_seconds",
        },
        reason,
    )
    _require(requirements.get("source_head_revalidation_required") is True, reason)
    _require(requirements.get("postcondition_receipt_required") is True, reason)
    max_pre_age = _integer(
        requirements.get("max_pre_apply_observation_age_seconds"), reason, maximum=30
    )
    max_post_age = _integer(
        requirements.get("max_postcondition_observation_age_seconds"),
        reason,
        maximum=30,
    )

    pointers = _object(contract.get("artifacts"), reason)
    expected_pointer_keys = {
        "final_lock_sha256",
        "readiness_receipt_sha256",
        "ledger_sha256",
        "source_authority_sha256",
        "inventory_receipt_sha256",
        "cutover_receipt_sha256",
        "rollback_receipt_sha256",
        "pre_apply_observation_sha256",
    }
    _exact_keys(pointers, expected_pointer_keys, reason)
    for key in sorted(expected_pointer_keys - {"inventory_receipt_sha256"}):
        artifact = artifacts[key]
        _require(artifact is not None, "input-unavailable")
        _require(
            _digest(pointers.get(key), reason) == artifact.sha256,
            "artifact-digest-mismatch",
        )

    inventory = artifacts["inventory_receipt_sha256"]
    if source_id == "slack_companion":
        _require(
            inventory is None and pointers.get("inventory_receipt_sha256") is None,
            reason,
        )
    else:
        _require(inventory is not None, "input-unavailable")
        _require(
            _digest(pointers.get("inventory_receipt_sha256"), reason)
            == inventory.sha256,
            "artifact-digest-mismatch",
        )
    return sealed_at, expires_at, max_pre_age, max_post_age


def _validate_freshness(
    observed_at: int,
    *,
    now_epoch: int,
    max_age: int,
    phase: str,
) -> None:
    _require(observed_at <= now_epoch, f"future-{phase}-observation")
    _require(now_epoch - observed_at <= max_age, f"stale-{phase}-observation")


def _write_validator_input(directory: Path, name: str, artifact: Artifact) -> Path:
    destination = directory / name
    destination.write_bytes(artifact.data)
    destination.chmod(0o600)
    return destination


def _run_final_validator(
    artifacts: dict[str, Artifact | None],
    *,
    snapshot: dict[str, str],
    now_epoch: int,
) -> None:
    with TemporaryDirectory() as raw_directory:
        directory = Path(raw_directory)
        names = {
            "final_lock_sha256": "lock.json",
            "readiness_receipt_sha256": "readiness-receipt.json",
            "ledger_sha256": "ledger.tsv",
            "source_authority_sha256": "source-authority.json",
            "inventory_receipt_sha256": "inventory-receipt.json",
            "cutover_receipt_sha256": "cutover.receipt",
            "rollback_receipt_sha256": "rollback.receipt",
        }
        paths: dict[str, Path] = {}
        for key, name in names.items():
            artifact = artifacts[key]
            if artifact is not None:
                paths[key] = _write_validator_input(directory, name, artifact)

        command = [
            "bash",
            str(FINAL_VALIDATOR),
            "--lock",
            str(paths["final_lock_sha256"]),
            "--receipt",
            str(paths["readiness_receipt_sha256"]),
            "--ledger",
            str(paths["ledger_sha256"]),
            "--source-authority",
            str(paths["source_authority_sha256"]),
            "--cutover-receipt",
            str(paths["cutover_receipt_sha256"]),
            "--rollback-receipt",
            str(paths["rollback_receipt_sha256"]),
            "--live-source-main",
            snapshot["source_main_commit_sha"],
            "--live-source-tree",
            snapshot["source_tree_sha"],
            "--live-public-target",
            snapshot["public_target_commit_sha"],
            "--live-private-target",
            snapshot["private_target_commit_sha"],
            "--authority-now-epoch",
            str(now_epoch),
        ]
        if "inventory_receipt_sha256" in paths:
            command.extend(
                ["--inventory-receipt", str(paths["inventory_receipt_sha256"])]
            )
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GateError("final-contract-rejected") from error
        _require(result.returncode == 0, "final-contract-rejected")
        _require(
            result.stdout.strip() == "final-archive-contract: verified",
            "final-contract-rejected",
        )


def _validate_apply_receipt(
    receipt: JsonObject,
    *,
    source_id: str,
    apply_contract_digest: str,
    pre_observation_digest: str,
    pre_observed_at: int,
    sealed_at: int,
    expected_snapshot: dict[str, str],
    post_observation_digest: str,
    post_snapshot: dict[str, str],
    post_observed_at: int,
    now_epoch: int,
    max_post_age: int,
) -> None:
    reason = "invalid-apply-receipt"
    _exact_keys(
        receipt,
        {
            "schema_version",
            "source_repository_id",
            "state",
            "apply_contract_sha256",
            "pre_apply_observation_sha256",
            "applied_at_epoch",
            "postcondition",
        },
        reason,
    )
    _require(receipt.get("schema_version") == APPLY_RECEIPT_SCHEMA, reason)
    _require(receipt.get("source_repository_id") == source_id, reason)
    _require(receipt.get("state") == "archived", reason)
    _require(receipt.get("apply_contract_sha256") == apply_contract_digest, reason)
    _require(
        receipt.get("pre_apply_observation_sha256") == pre_observation_digest, reason
    )
    applied_at = _integer(receipt.get("applied_at_epoch"), reason)
    _require(applied_at >= max(pre_observed_at, sealed_at), reason)
    _require(applied_at <= post_observed_at, reason)
    _require(applied_at <= now_epoch, reason)
    _require(post_snapshot == expected_snapshot, "snapshot-mismatch")
    _validate_freshness(
        post_observed_at,
        now_epoch=now_epoch,
        max_age=max_post_age,
        phase="postcondition",
    )

    postcondition = _object(receipt.get("postcondition"), reason)
    _exact_keys(
        postcondition,
        {
            "checked",
            "archived",
            "observation_sha256",
            "source_main_commit_sha",
            "source_tree_sha",
            "observed_at_epoch",
        },
        reason,
    )
    _require(postcondition.get("checked") is True, reason)
    _require(postcondition.get("archived") is True, reason)
    _require(postcondition.get("observation_sha256") == post_observation_digest, reason)
    _require(
        postcondition.get("source_main_commit_sha")
        == expected_snapshot["source_main_commit_sha"],
        reason,
    )
    _require(
        postcondition.get("source_tree_sha") == expected_snapshot["source_tree_sha"],
        reason,
    )
    _require(postcondition.get("observed_at_epoch") == post_observed_at, reason)


def validate(arguments: GateArguments, *, now_epoch: int) -> str:
    _require(now_epoch > 0, "invalid-authority-time")
    paths = {
        "apply_contract": arguments.apply_contract,
        "final_lock_sha256": arguments.lock,
        "readiness_receipt_sha256": arguments.readiness_receipt,
        "ledger_sha256": arguments.ledger,
        "source_authority_sha256": arguments.source_authority,
        "inventory_receipt_sha256": arguments.inventory_receipt,
        "cutover_receipt_sha256": arguments.cutover_receipt,
        "rollback_receipt_sha256": arguments.rollback_receipt,
        "pre_apply_observation_sha256": arguments.pre_apply_observation,
    }
    loaded: dict[str, Artifact | None] = {
        key: _read_artifact(path) if path is not None else None
        for key, path in paths.items()
    }
    apply_contract_artifact = loaded.pop("apply_contract")
    _require(apply_contract_artifact is not None, "input-unavailable")
    lock_artifact = loaded["final_lock_sha256"]
    readiness_artifact = loaded["readiness_receipt_sha256"]
    pre_observation_artifact = loaded["pre_apply_observation_sha256"]
    _require(lock_artifact is not None, "input-unavailable")
    _require(readiness_artifact is not None, "input-unavailable")
    _require(pre_observation_artifact is not None, "input-unavailable")

    lock = _load_json(lock_artifact, "invalid-final-lock")
    source_id, expected_snapshot, lock_max_age = _lock_snapshot(lock)
    readiness = _load_json(readiness_artifact, "invalid-readiness-receipt")
    _validate_readiness_receipt(readiness, source_id)
    pre_observation = _load_json(pre_observation_artifact, "invalid-live-observation")
    pre_snapshot, pre_observed_at, pre_evidence = _validate_live_observation(
        pre_observation,
        expected_phase="pre-apply",
        expected_source_id=source_id,
    )
    _require(pre_snapshot == expected_snapshot, "snapshot-mismatch")

    apply_contract = _load_json(apply_contract_artifact, "invalid-apply-contract")
    sealed_at, _expires_at, max_pre_age, max_post_age = _validate_apply_contract(
        apply_contract,
        source_id=source_id,
        expected_snapshot=expected_snapshot,
        lock_max_age=lock_max_age,
        artifacts=loaded,
        pre_observed_at=pre_observed_at,
        now_epoch=now_epoch,
    )
    _validate_freshness(
        pre_observed_at,
        now_epoch=now_epoch,
        max_age=max_pre_age,
        phase="pre-apply",
    )
    _run_final_validator(loaded, snapshot=pre_snapshot, now_epoch=now_epoch)

    if arguments.phase == "pre-apply":
        _require(
            arguments.apply_receipt is None
            and arguments.postcondition_observation is None,
            "unexpected-postcondition-input",
        )
        return "preconditions-verified"

    _require(arguments.phase == "postcondition", "invalid-phase")
    _require(
        arguments.apply_receipt is not None
        and arguments.postcondition_observation is not None,
        "postcondition-input-unavailable",
    )
    apply_receipt_artifact = _read_artifact(arguments.apply_receipt)
    post_observation_artifact = _read_artifact(arguments.postcondition_observation)
    apply_receipt = _load_json(apply_receipt_artifact, "invalid-apply-receipt")
    post_observation = _load_json(post_observation_artifact, "invalid-live-observation")
    post_snapshot, post_observed_at, post_evidence = _validate_live_observation(
        post_observation,
        expected_phase="postcondition",
        expected_source_id=source_id,
    )
    _require(
        post_evidence["repository_metadata_sha256"]
        != pre_evidence["repository_metadata_sha256"],
        "unchanged-postcondition-evidence",
    )
    _validate_apply_receipt(
        apply_receipt,
        source_id=source_id,
        apply_contract_digest=apply_contract_artifact.sha256,
        pre_observation_digest=pre_observation_artifact.sha256,
        pre_observed_at=pre_observed_at,
        sealed_at=sealed_at,
        expected_snapshot=expected_snapshot,
        post_observation_digest=post_observation_artifact.sha256,
        post_snapshot=post_snapshot,
        post_observed_at=post_observed_at,
        now_epoch=now_epoch,
        max_post_age=max_post_age,
    )
    return "postcondition-verified"


def parse_arguments(argv: list[str] | None = None) -> GateArguments:
    parser = argparse.ArgumentParser(
        description="Validate repository archive apply evidence without changing repository state."
    )
    parser.add_argument(
        "--phase", choices=("pre-apply", "postcondition"), default="pre-apply"
    )
    parser.add_argument("--apply-contract", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--readiness-receipt", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--source-authority", type=Path, required=True)
    parser.add_argument("--inventory-receipt", type=Path)
    parser.add_argument("--cutover-receipt", type=Path, required=True)
    parser.add_argument("--rollback-receipt", type=Path, required=True)
    parser.add_argument("--pre-apply-observation", type=Path, required=True)
    parser.add_argument("--apply-receipt", type=Path)
    parser.add_argument("--postcondition-observation", type=Path)
    namespace = parser.parse_args(argv)
    return GateArguments(
        phase=namespace.phase,
        apply_contract=namespace.apply_contract,
        lock=namespace.lock,
        readiness_receipt=namespace.readiness_receipt,
        ledger=namespace.ledger,
        source_authority=namespace.source_authority,
        inventory_receipt=namespace.inventory_receipt,
        cutover_receipt=namespace.cutover_receipt,
        rollback_receipt=namespace.rollback_receipt,
        pre_apply_observation=namespace.pre_apply_observation,
        apply_receipt=namespace.apply_receipt,
        postcondition_observation=namespace.postcondition_observation,
    )


def main(argv: list[str] | None = None, *, now_epoch: int | None = None) -> int:
    arguments = parse_arguments(argv)
    authority_now = (
        now_epoch
        if now_epoch is not None
        else int(datetime.now(timezone.utc).timestamp())
    )
    try:
        result = validate(arguments, now_epoch=authority_now)
    except GateError as error:
        print(f"::error::final-archive-apply: {error.reason}", file=sys.stderr)
        return 1
    print(f"final-archive-apply: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
