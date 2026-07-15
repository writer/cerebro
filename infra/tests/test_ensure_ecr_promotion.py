from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import ensure_ecr_promotion


class EnsureEcrPromotionTest(unittest.TestCase):
    def _stack_file(
        self,
        directory: str,
        *,
        image_tag: str = "v2.1.123",
        web_image_tag: str = "web-20260625",
    ) -> Path:
        stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
        stack_file.write_text(
            "\n".join(
                [
                    "config:",
                    f"  cerebro:imageTag: {image_tag}",
                    f"  cerebro:webImageTag: {web_image_tag}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return stack_file

    def _aws_describe(
        self, tag_to_digest: dict[str, str]
    ) -> list[subprocess.CompletedProcess[str]]:
        responses: list[subprocess.CompletedProcess[str]] = []
        for tag, digest in tag_to_digest.items():
            responses.append(
                subprocess.CompletedProcess(
                    ["aws"],
                    0,
                    stdout=json.dumps(
                        {
                            "imageDetails": [
                                {
                                    "registryId": "944130631940",
                                    "imageDigest": digest,
                                    "imagePushedAt": "2026-06-25T12:00:00+00:00",
                                    "imageTags": [tag],
                                }
                            ]
                        }
                    ),
                    stderr="",
                )
            )
        return responses

    def test_writes_receipt_for_all_stack_images(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stack_file = self._stack_file(temp_dir)
            receipt = Path(temp_dir) / "promotion-receipt.json"
            outputs = Path(temp_dir) / "outputs.txt"
            responses = iter(
                self._aws_describe(
                    {"v2.1.123": "sha256:api", "web-20260625": "sha256:web"}
                )
            )

            with patch(
                "scripts.ensure_ecr_promotion._run",
                side_effect=lambda *_args, **_kwargs: next(responses),
            ):
                status = ensure_ecr_promotion.main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--repository-name",
                        "cerebro",
                        "--region",
                        "us-east-1",
                        "--receipt-output",
                        str(receipt),
                        "--github-output",
                        str(outputs),
                    ]
                )

            payload = json.loads(receipt.read_text(encoding="utf-8"))
            output_text = outputs.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertEqual(payload["stack"], "sec-dev")
        self.assertEqual(payload["source"], "existing_ecr")
        self.assertEqual(
            [image["label"] for image in payload["images"]], ["api", "web"]
        )
        self.assertIn("promotion_api_digest=sha256:api", output_text)
        self.assertIn("promotion_web_digest=sha256:web", output_text)
        self.assertIn("promotion_recovered=false", output_text)

    def test_missing_image_without_dispatch_fails_actionably(self) -> None:
        missing = subprocess.CompletedProcess(
            ["aws"],
            254,
            stdout="",
            stderr="An error occurred (ImageNotFoundException) when calling the DescribeImages operation",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            stack_file = self._stack_file(temp_dir, web_image_tag="")
            with patch("scripts.ensure_ecr_promotion._run", return_value=missing):
                status = ensure_ecr_promotion.main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--github-repository",
                        "WriterInternal/cerebro",
                    ]
                )

        self.assertEqual(status, 1)

    def test_rejects_ecr_image_that_does_not_match_locked_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stack_file = self._stack_file(temp_dir, web_image_tag="")
            receipt = Path(temp_dir) / "promotion-receipt.json"
            responses = iter(self._aws_describe({"v2.1.123": "sha256:published"}))

            with (
                patch(
                    "scripts.ensure_ecr_promotion._run",
                    side_effect=lambda *_args, **_kwargs: next(responses),
                ),
                patch(
                    "scripts.ensure_ecr_promotion._source_release_evidence",
                    return_value=ensure_ecr_promotion.SourceReleaseEvidence(
                        frozenset({"sha256:locked", "sha256:platform"}),
                        frozenset(
                            {
                                ensure_ecr_promotion.ManifestIdentity(
                                    "sha256:source-config", ("sha256:source-layer",)
                                )
                            }
                        ),
                    ),
                ),
                patch(
                    "scripts.ensure_ecr_promotion._ecr_manifest_identity",
                    return_value=ensure_ecr_promotion.ManifestIdentity(
                        "sha256:different-config", ("sha256:different-layer",)
                    ),
                ),
            ):
                status = ensure_ecr_promotion.main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--expected-api-digest",
                        "sha256:locked",
                        "--receipt-output",
                        str(receipt),
                    ]
                )

            self.assertEqual(status, 1)
            self.assertFalse(receipt.exists())

    def test_accepts_platform_manifest_from_locked_release_index(self) -> None:
        image = ensure_ecr_promotion.EcrImage(
            label="api",
            tag="v2.1.123",
            digest="sha256:platform",
            image_uri="944130631940.dkr.ecr.us-east-1.amazonaws.com/cerebro:v2.1.123",
        )
        with (
            patch(
                "scripts.ensure_ecr_promotion._source_release_evidence",
                return_value=ensure_ecr_promotion.SourceReleaseEvidence(
                    frozenset({"sha256:locked", "sha256:platform"}), frozenset()
                ),
            ),
            patch(
                "scripts.ensure_ecr_promotion._ecr_manifest_identity"
            ) as ecr_identity,
        ):
            self.assertTrue(
                ensure_ecr_promotion._verify_expected_api_digest(
                    [image], "sha256:locked", "ghcr.io/writer/cerebro"
                )
            )
        ecr_identity.assert_not_called()

    def test_source_release_evidence_excludes_attestation_manifests(self) -> None:
        release_index = {
            "manifests": [
                {
                    "digest": "sha256:platform",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": "sha256:attestation",
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest"
                    },
                },
            ]
        }
        platform_manifest = {
            "config": {"digest": "sha256:config"},
            "layers": [
                {"digest": "sha256:layer-1"},
                {"digest": "sha256:layer-2"},
            ],
        }
        responses = iter(
            [
                subprocess.CompletedProcess(
                    ["docker"], 0, stdout=json.dumps(release_index), stderr=""
                ),
                subprocess.CompletedProcess(
                    ["docker"], 0, stdout=json.dumps(platform_manifest), stderr=""
                ),
            ]
        )
        with patch(
            "scripts.ensure_ecr_promotion._run",
            side_effect=lambda *_args, **_kwargs: next(responses),
        ):
            evidence = ensure_ecr_promotion._source_release_evidence(
                "ghcr.io/writer/cerebro", "sha256:locked"
            )
        self.assertEqual(
            evidence.allowed_digests,
            frozenset({"sha256:locked", "sha256:platform"}),
        )
        self.assertEqual(
            evidence.manifest_identities,
            frozenset(
                {
                    ensure_ecr_promotion.ManifestIdentity(
                        "sha256:config", ("sha256:layer-1", "sha256:layer-2")
                    )
                }
            ),
        )

    def test_accepts_registry_normalized_manifest_with_identical_blobs(self) -> None:
        image = ensure_ecr_promotion.EcrImage(
            label="api",
            tag="v2.1.749",
            digest="sha256:ecr-normalized",
            image_uri="837279440628.dkr.ecr.us-east-1.amazonaws.com/cerebro:v2.1.749",
        )
        identity = ensure_ecr_promotion.ManifestIdentity(
            "sha256:config", ("sha256:layer-1", "sha256:layer-2")
        )
        with (
            patch(
                "scripts.ensure_ecr_promotion._source_release_evidence",
                return_value=ensure_ecr_promotion.SourceReleaseEvidence(
                    frozenset({"sha256:locked", "sha256:platform"}),
                    frozenset({identity}),
                ),
            ),
            patch(
                "scripts.ensure_ecr_promotion._ecr_manifest_identity",
                return_value=identity,
            ),
        ):
            self.assertTrue(
                ensure_ecr_promotion._verify_expected_api_digest(
                    [image],
                    "sha256:locked",
                    "ghcr.io/writer/cerebro",
                    repository_name="cerebro",
                    region="us-east-1",
                )
            )

    def test_reads_ecr_manifest_identity_from_registry(self) -> None:
        image = ensure_ecr_promotion.EcrImage(
            label="api",
            tag="v2.1.749",
            digest="sha256:ecr-normalized",
            image_uri="837279440628.dkr.ecr.us-east-1.amazonaws.com/cerebro:v2.1.749",
        )
        manifest = {
            "schemaVersion": 2,
            "config": {"digest": "sha256:config"},
            "layers": [{"digest": "sha256:layer"}],
        }
        completed = subprocess.CompletedProcess(
            ["aws"],
            0,
            stdout=json.dumps({"images": [{"imageManifest": json.dumps(manifest)}]}),
            stderr="",
        )
        with patch("scripts.ensure_ecr_promotion._run", return_value=completed) as run:
            identity = ensure_ecr_promotion._ecr_manifest_identity(
                image, repository_name="cerebro", region="us-east-1"
            )
        self.assertEqual(
            identity,
            ensure_ecr_promotion.ManifestIdentity("sha256:config", ("sha256:layer",)),
        )
        self.assertIn("batch-get-image", run.call_args.args[0])

    def test_dispatches_ci_recovery_before_writing_receipt(self) -> None:
        image = ensure_ecr_promotion.EcrImage(
            label="api",
            tag="v2.1.123",
            digest="sha256:api",
            image_uri="944130631940.dkr.ecr.us-east-1.amazonaws.com/cerebro:v2.1.123",
            pushed_at=None,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            stack_file = self._stack_file(temp_dir, web_image_tag="")
            receipt = Path(temp_dir) / "promotion-receipt.json"
            started_at = datetime.now(UTC)
            with (
                patch(
                    "scripts.ensure_ecr_promotion._find_missing_images",
                    side_effect=[
                        ([], [ensure_ecr_promotion.RequiredImage("api", "v2.1.123")]),
                        ([image], []),
                    ],
                ) as find_missing,
                patch(
                    "scripts.ensure_ecr_promotion._dispatch_workflow",
                    return_value=started_at,
                ) as dispatch,
                patch(
                    "scripts.ensure_ecr_promotion._wait_for_dispatched_workflow",
                    return_value="https://github.com/run",
                ) as wait,
            ):
                status = ensure_ecr_promotion.main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--dispatch-if-missing",
                        "--github-repository",
                        "WriterInternal/cerebro",
                        "--receipt-output",
                        str(receipt),
                    ]
                )

            payload = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(find_missing.call_count, 2)
        dispatch.assert_called_once()
        wait.assert_called_once()
        self.assertEqual(payload["source"], "recovered_by_ci_dispatch")
        self.assertEqual(payload["recoveryRunUrl"], "https://github.com/run")


if __name__ == "__main__":
    unittest.main()
