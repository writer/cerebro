from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import produce_web_runtime_receipts as producer


NOW = 2_000
CUTOVER_COMMIT = "a" * 40
ROLLBACK_COMMIT = "b" * 40
PRIVATE_COMMIT = "c" * 40
CUTOVER_WEB_DIGEST = "sha256:" + "d" * 64
ROLLBACK_WEB_DIGEST = "sha256:" + "e" * 64


def canonical(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class WebRuntimeReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.cutover_release = self.write_release(
            "cutover-release.json", CUTOVER_COMMIT, CUTOVER_WEB_DIGEST, "v2.1.2"
        )
        self.rollback_release = self.write_release(
            "rollback-release.json", ROLLBACK_COMMIT, ROLLBACK_WEB_DIGEST, "v2.1.1"
        )
        self.cutover_target = self.write_target(
            "cutover-target.json", CUTOVER_COMMIT, CUTOVER_WEB_DIGEST, "v2.1.2"
        )
        self.rollback_target = self.write_target(
            "rollback-target.json", ROLLBACK_COMMIT, ROLLBACK_WEB_DIGEST, "v2.1.1"
        )
        self.runtime = self.write_json(
            "runtime.json",
            {
                "schema_version": producer.RUNTIME_OBSERVATION_SCHEMA,
                "product_release_commit_sha": CUTOVER_COMMIT,
                "private_target_commit_sha": PRIVATE_COMMIT,
                "web_digest": CUTOVER_WEB_DIGEST,
                "target_receipt_sha256": hashlib.sha256(
                    self.cutover_target.read_bytes()
                ).hexdigest(),
                "runtime_state": "ready",
                "traffic_state": "serving",
                "probe_state": "passed",
                "observed_at_epoch": NOW - 10,
            },
        )
        self.rehearsal = self.write_json(
            "rehearsal.json",
            {
                "schema_version": producer.ROLLBACK_OBSERVATION_SCHEMA,
                "private_target_commit_sha": PRIVATE_COMMIT,
                "rollback_release_commit_sha": ROLLBACK_COMMIT,
                "rollback_web_digest": ROLLBACK_WEB_DIGEST,
                "target_receipt_sha256": hashlib.sha256(
                    self.rollback_target.read_bytes()
                ).hexdigest(),
                "artifact_state": "available",
                "render_state": "verified",
                "workflow_state": "verified",
                "rehearsal_state": "verified",
                "observed_at_epoch": NOW - 5,
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, value: dict[str, object]) -> Path:
        path = self.root / name
        path.write_bytes(canonical(value))
        return path

    def write_release(self, name: str, commit: str, digest: str, version: str) -> Path:
        return self.write_json(
            name,
            {
                "schema_version": producer.PRODUCT_RELEASE_SCHEMA,
                "version": version,
                "commit": commit,
                "runtime_image": f"runtime:{version}",
                "runtime_digest": "sha256:" + "1" * 64,
                "web_image": f"web:{version}",
                "web_digest": digest,
                "slack_archive": "slack.tgz",
                "slack_sha256": "2" * 64,
                "sdk_archive": "sdk.tgz",
                "sdk_sha256": "3" * 64,
            },
        )

    def write_target(self, name: str, commit: str, digest: str, version: str) -> Path:
        receipt: dict[str, object] = {
            "schema_version": producer.TARGET_RECEIPT_SCHEMA,
            "release": {
                "schema_version": producer.PRODUCT_RELEASE_SCHEMA,
                "tag": version,
                "commit": commit,
                "url": "logical-release",
                "manifest_sha256": "4" * 64,
            },
            "target": {
                "id": "private-target",
                "apply_mode": "pull_request",
                "stack_file": "logical-stack",
                "stack_sha256": "5" * 64,
            },
            "components": {
                "runtime": {
                    "image": f"runtime:{version}",
                    "digest": "sha256:" + "1" * 64,
                },
                "web": {"image": f"web:{version}", "digest": digest},
                "slack_companion": {"archive": "slack.tgz", "sha256": "2" * 64},
                "typescript_sdk": {"archive": "sdk.tgz", "sha256": "3" * 64},
            },
            "runtime_contract_sha256": "6" * 64,
        }
        receipt["idempotency_key"] = hashlib.sha256(canonical(receipt)).hexdigest()
        return self.write_json(name, receipt)

    def arguments(self) -> list[str]:
        return [
            "--source-id",
            "web_public",
            "--cutover-product-release",
            str(self.cutover_release),
            "--cutover-target-receipt",
            str(self.cutover_target),
            "--runtime-observation",
            str(self.runtime),
            "--rollback-product-release",
            str(self.rollback_release),
            "--rollback-target-receipt",
            str(self.rollback_target),
            "--rollback-observation",
            str(self.rehearsal),
            "--output-directory",
            str(self.output),
            "--authority-now-epoch",
            str(NOW),
            "--max-age-seconds",
            "300",
        ]

    def test_produces_cross_bound_logical_receipts(self) -> None:
        self.assertEqual(producer.main(self.arguments()), 0)
        cutover_path = self.output / "web_public.cutover-receipt.json"
        rollback_path = self.output / "web_public.rollback-readiness-receipt.json"
        cutover = json.loads(cutover_path.read_text())
        rollback = json.loads(rollback_path.read_text())
        self.assertEqual(cutover["release"]["public_commit_sha"], CUTOVER_COMMIT)
        self.assertEqual(cutover["deployment"]["private_commit_sha"], PRIVATE_COMMIT)
        self.assertEqual(
            rollback["cutover_receipt_sha256"],
            hashlib.sha256(cutover_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            rollback["rollback_target"]["public_commit_sha"], ROLLBACK_COMMIT
        )
        rendered = json.dumps([cutover, rollback])
        self.assertNotIn("private-target", rendered)
        self.assertNotIn("logical-stack", rendered)
        self.assertNotIn("http", rendered)

    def test_rejects_runtime_digest_mismatch_without_output(self) -> None:
        value = json.loads(self.runtime.read_text())
        value["web_digest"] = ROLLBACK_WEB_DIGEST
        self.runtime.write_bytes(canonical(value))
        self.assertEqual(producer.main(self.arguments()), 1)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_stale_live_observation(self) -> None:
        value = json.loads(self.runtime.read_text())
        value["observed_at_epoch"] = NOW - 301
        self.runtime.write_bytes(canonical(value))
        self.assertEqual(producer.main(self.arguments()), 1)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_unreviewed_extra_authority_fields(self) -> None:
        value = json.loads(self.rehearsal.read_text())
        value["endpoint"] = "not-allowed"
        self.rehearsal.write_bytes(canonical(value))
        self.assertEqual(producer.main(self.arguments()), 1)

    def test_never_overwrites_existing_output(self) -> None:
        path = self.output / "web_public.cutover-receipt.json"
        path.write_text("sentinel\n", encoding="utf-8")
        self.assertEqual(producer.main(self.arguments()), 1)
        self.assertEqual(path.read_text(), "sentinel\n")
        self.assertFalse(
            (self.output / "web_public.rollback-readiness-receipt.json").exists()
        )

    def test_removes_cutover_receipt_when_rollback_write_has_io_failure(self) -> None:
        write_new = producer._write_new
        write_count = 0

        def fail_second_write(path: Path, value: dict[str, object]) -> None:
            nonlocal write_count
            write_count += 1
            if write_count == 2:
                raise OSError("write failed")
            write_new(path, value)

        with mock.patch.object(producer, "_write_new", side_effect=fail_second_write):
            self.assertEqual(producer.main(self.arguments()), 1)

        self.assertEqual(write_count, 2)
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
