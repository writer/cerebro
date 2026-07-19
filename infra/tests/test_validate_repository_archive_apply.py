from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import validate_repository_archive_apply as gate


NOW = 2_000
SOURCE_MAIN = "a" * 40
SOURCE_TREE = "b" * 40
PUBLIC_TARGET = "c" * 40
PRIVATE_TARGET = "d" * 40


def canonical(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class RepositoryArchiveApplyGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.snapshot = {
            "source_main_commit_sha": SOURCE_MAIN,
            "source_tree_sha": SOURCE_TREE,
            "public_target_commit_sha": PUBLIC_TARGET,
            "private_target_commit_sha": PRIVATE_TARGET,
        }
        self.lock = self.write_json(
            "lock.json",
            {
                "schema_version": gate.FINAL_LOCK_SCHEMA,
                "source_repository_id": "slack_companion",
                "source": {
                    "main_commit_sha": SOURCE_MAIN,
                    "tree_sha": SOURCE_TREE,
                },
                "targets": {
                    "public_commit_sha": PUBLIC_TARGET,
                    "private_commit_sha": PRIVATE_TARGET,
                },
                "authorities": {"max_observation_age_seconds": 300},
            },
        )
        self.readiness_receipt = self.write_json(
            "readiness.json",
            {
                "schema_version": gate.FINAL_RECEIPT_SCHEMA,
                "source_repository_id": "slack_companion",
                "intent": "dry-run",
                "state": "verified",
                "postcondition": {
                    "checked": False,
                    "archived": False,
                    "observed_at_epoch": 0,
                },
            },
        )
        self.ledger = self.write_bytes("ledger.tsv", b"bounded-ledger\n")
        self.source_authority = self.write_json(
            "source-authority.json", {"ready": True}
        )
        self.cutover_receipt = self.write_bytes("cutover.receipt", b"cutover\n")
        self.rollback_receipt = self.write_bytes("rollback.receipt", b"rollback\n")
        self.pre_apply_observation = self.write_pre_observation(NOW - 5)
        self.apply_contract = self.write_contract(NOW - 4, NOW + 60)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bytes(self, name: str, value: bytes) -> Path:
        path = self.root / name
        path.write_bytes(value)
        return path

    def write_json(self, name: str, value: dict[str, object]) -> Path:
        return self.write_bytes(name, canonical(value))

    def digest(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def observation(
        self,
        *,
        phase: str,
        observed_at: int,
        archived: bool,
        snapshot: dict[str, str] | None = None,
        repository_digest: str = "1" * 64,
    ) -> dict[str, object]:
        return {
            "schema_version": gate.LIVE_OBSERVATION_SCHEMA,
            "source_repository_id": "slack_companion",
            "phase": phase,
            "observed_at_epoch": observed_at,
            "snapshot": snapshot or self.snapshot,
            "repository": {
                "archived": archived,
                "open_pull_request_count": 0,
                "open_issue_count": 0,
            },
            "evidence": {
                "repository_metadata_sha256": repository_digest,
                "default_branch_ref_sha256": "2" * 64,
            },
        }

    def write_pre_observation(self, observed_at: int) -> Path:
        self.pre_apply_observation = self.write_json(
            "pre-observation.json",
            self.observation(
                phase="pre-apply", observed_at=observed_at, archived=False
            ),
        )
        return self.pre_apply_observation

    def write_contract(self, sealed_at: int, expires_at: int) -> Path:
        self.apply_contract = self.write_json(
            "apply-contract.json",
            {
                "schema_version": gate.APPLY_CONTRACT_SCHEMA,
                "source_repository_id": "slack_companion",
                "state": "sealed",
                "validity": {
                    "sealed_at_epoch": sealed_at,
                    "expires_at_epoch": expires_at,
                },
                "artifacts": {
                    "final_lock_sha256": self.digest(self.lock),
                    "readiness_receipt_sha256": self.digest(self.readiness_receipt),
                    "ledger_sha256": self.digest(self.ledger),
                    "source_authority_sha256": self.digest(self.source_authority),
                    "inventory_receipt_sha256": None,
                    "cutover_receipt_sha256": self.digest(self.cutover_receipt),
                    "rollback_receipt_sha256": self.digest(self.rollback_receipt),
                    "pre_apply_observation_sha256": self.digest(
                        self.pre_apply_observation
                    ),
                },
                "snapshot": self.snapshot,
                "requirements": {
                    "source_head_revalidation_required": True,
                    "max_pre_apply_observation_age_seconds": 30,
                    "postcondition_receipt_required": True,
                    "max_postcondition_observation_age_seconds": 30,
                },
            },
        )
        return self.apply_contract

    def arguments(self, *, phase: str = "pre-apply") -> gate.GateArguments:
        return gate.GateArguments(
            phase=phase,
            apply_contract=self.apply_contract,
            lock=self.lock,
            readiness_receipt=self.readiness_receipt,
            ledger=self.ledger,
            source_authority=self.source_authority,
            inventory_receipt=None,
            cutover_receipt=self.cutover_receipt,
            rollback_receipt=self.rollback_receipt,
            pre_apply_observation=self.pre_apply_observation,
            apply_receipt=None,
            postcondition_observation=None,
        )

    def successful_validator_result(self) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="final-archive-contract: verified\n",
            stderr="",
        )

    @mock.patch.object(gate.subprocess, "run")
    def test_pre_apply_contract_is_verified_without_a_mutation(
        self, run: mock.Mock
    ) -> None:
        run.return_value = self.successful_validator_result()

        result = gate.validate(self.arguments(), now_epoch=NOW)

        self.assertEqual(result, "preconditions-verified")
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["bash", str(gate.FINAL_VALIDATOR)])
        self.assertNotIn("--apply", command)
        self.assertNotIn("PATCH", command)
        self.assertNotIn("POST", command)

    @mock.patch.object(gate.subprocess, "run")
    def test_cutover_receipt_tampering_fails_before_final_validation(
        self, run: mock.Mock
    ) -> None:
        self.cutover_receipt.write_bytes(b"changed\n")

        with self.assertRaisesRegex(gate.GateError, "artifact-digest-mismatch"):
            gate.validate(self.arguments(), now_epoch=NOW)

        run.assert_not_called()

    @mock.patch.object(gate.subprocess, "run")
    def test_stale_pre_apply_source_observation_fails_closed(
        self, run: mock.Mock
    ) -> None:
        self.write_pre_observation(NOW - 31)
        self.write_contract(NOW - 30, NOW + 30)

        with self.assertRaisesRegex(gate.GateError, "stale-pre-apply-observation"):
            gate.validate(self.arguments(), now_epoch=NOW)

        run.assert_not_called()

    @mock.patch.object(gate.subprocess, "run")
    def test_moved_source_head_fails_closed(self, run: mock.Mock) -> None:
        moved_snapshot = {**self.snapshot, "source_main_commit_sha": "9" * 40}
        self.pre_apply_observation = self.write_json(
            "pre-observation.json",
            self.observation(
                phase="pre-apply",
                observed_at=NOW - 5,
                archived=False,
                snapshot=moved_snapshot,
            ),
        )
        self.write_contract(NOW - 4, NOW + 60)

        with self.assertRaisesRegex(gate.GateError, "snapshot-mismatch"):
            gate.validate(self.arguments(), now_epoch=NOW)

        run.assert_not_called()

    @mock.patch.object(gate.subprocess, "run")
    def test_symlinked_evidence_is_rejected(self, run: mock.Mock) -> None:
        actual = self.rollback_receipt
        link = self.root / "rollback-link.receipt"
        link.symlink_to(actual)
        arguments = self.arguments()
        arguments = gate.GateArguments(
            **{**arguments.__dict__, "rollback_receipt": link}
        )

        with self.assertRaisesRegex(gate.GateError, "input-unavailable"):
            gate.validate(arguments, now_epoch=NOW)

        run.assert_not_called()

    @mock.patch.object(gate.subprocess, "run")
    def test_rejected_final_contract_is_bounded(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="sensitive diagnostic"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = gate.main(self.cli_arguments(), now_epoch=NOW)

        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "::error::final-archive-apply: final-contract-rejected\n",
        )
        self.assertNotIn("sensitive diagnostic", stderr.getvalue())

    def test_pre_apply_gate_delegates_to_real_final_contract_validator(self) -> None:
        fixture = Path(__file__).parent / "fixtures/final-archive-contract"
        for source_name, destination_name in (
            ("final-lock.json", "lock.json"),
            ("final-receipt.json", "readiness.json"),
            ("ledger.tsv", "ledger.tsv"),
            ("slack-authority.json", "source-authority.json"),
            ("cutover.receipt", "cutover.receipt"),
            ("rollback.receipt", "rollback.receipt"),
        ):
            shutil.copyfile(fixture / source_name, self.root / destination_name)
        receipt = json.loads(self.readiness_receipt.read_text(encoding="utf-8"))
        lock = json.loads(self.lock.read_text(encoding="utf-8"))
        receipt["lock_sha256"] = hashlib.sha256(canonical(lock)).hexdigest()
        for authority in ("work_queue", "freeze", "archive_capability"):
            receipt["observed"][authority]["observed_at_epoch"] = NOW - 5
        self.readiness_receipt.write_bytes(canonical(receipt))
        self.pre_apply_observation = self.write_pre_observation(NOW - 4)
        self.apply_contract = self.write_contract(NOW - 3, NOW + 60)

        result = gate.validate(self.arguments(), now_epoch=NOW)

        self.assertEqual(result, "preconditions-verified")

    @mock.patch.object(gate.subprocess, "run")
    def test_archived_postcondition_is_content_addressed(self, run: mock.Mock) -> None:
        run.return_value = self.successful_validator_result()
        post_observation = self.write_json(
            "post-observation.json",
            self.observation(
                phase="postcondition",
                observed_at=NOW,
                archived=True,
                repository_digest="3" * 64,
            ),
        )
        apply_receipt = self.write_json(
            "apply-receipt.json",
            {
                "schema_version": gate.APPLY_RECEIPT_SCHEMA,
                "source_repository_id": "slack_companion",
                "state": "archived",
                "apply_contract_sha256": self.digest(self.apply_contract),
                "pre_apply_observation_sha256": self.digest(self.pre_apply_observation),
                "applied_at_epoch": NOW - 1,
                "postcondition": {
                    "checked": True,
                    "archived": True,
                    "observation_sha256": self.digest(post_observation),
                    "source_main_commit_sha": SOURCE_MAIN,
                    "source_tree_sha": SOURCE_TREE,
                    "observed_at_epoch": NOW,
                },
            },
        )
        arguments = self.arguments(phase="postcondition")
        arguments = gate.GateArguments(
            **{
                **arguments.__dict__,
                "apply_receipt": apply_receipt,
                "postcondition_observation": post_observation,
            }
        )

        result = gate.validate(arguments, now_epoch=NOW)

        self.assertEqual(result, "postcondition-verified")

    @mock.patch.object(gate.subprocess, "run")
    def test_non_archived_postcondition_is_rejected(self, run: mock.Mock) -> None:
        run.return_value = self.successful_validator_result()
        post_observation = self.write_json(
            "post-observation.json",
            self.observation(
                phase="postcondition",
                observed_at=NOW,
                archived=False,
                repository_digest="3" * 64,
            ),
        )
        arguments = self.arguments(phase="postcondition")
        arguments = gate.GateArguments(
            **{
                **arguments.__dict__,
                "apply_receipt": self.write_json("apply-receipt.json", {}),
                "postcondition_observation": post_observation,
            }
        )

        with self.assertRaisesRegex(gate.GateError, "invalid-live-observation"):
            gate.validate(arguments, now_epoch=NOW)

    @mock.patch.object(gate.subprocess, "run")
    def test_postcondition_inputs_are_required(self, run: mock.Mock) -> None:
        run.return_value = self.successful_validator_result()

        with self.assertRaisesRegex(gate.GateError, "postcondition-input-unavailable"):
            gate.validate(self.arguments(phase="postcondition"), now_epoch=NOW)

    def test_contract_schemas_are_strict_and_identity_neutral(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        schema_paths = [
            repository_root
            / "infra/repository_retirement/final-archive-apply-contract.schema.json",
            repository_root
            / "infra/repository_retirement/final-archive-apply-receipt.schema.json",
            repository_root
            / "infra/repository_retirement/repository-archive-live-observation.schema.json",
        ]
        for path in schema_paths:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
            )
            self.assertFalse(schema["additionalProperties"])
            rendered = path.read_text(encoding="utf-8")
            self.assertNotIn("github.com", rendered)
            self.assertNotIn("writer/", rendered)
            self.assertNotIn('"$id"', rendered)

    def cli_arguments(self) -> list[str]:
        return [
            "--apply-contract",
            str(self.apply_contract),
            "--lock",
            str(self.lock),
            "--readiness-receipt",
            str(self.readiness_receipt),
            "--ledger",
            str(self.ledger),
            "--source-authority",
            str(self.source_authority),
            "--cutover-receipt",
            str(self.cutover_receipt),
            "--rollback-receipt",
            str(self.rollback_receipt),
            "--pre-apply-observation",
            str(self.pre_apply_observation),
        ]


if __name__ == "__main__":
    unittest.main()
