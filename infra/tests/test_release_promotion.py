from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import reconcile_release_promotions
import configure_release_promotion_controls
import refresh_release_promotion_gate
import release_promotion
import request_release_rollback


def receipt(environment: str = "sec-dev") -> release_promotion.DeploymentReceipt:
    return release_promotion.DeploymentReceipt(
        deployment_id=42,
        environment=environment,
        image_tag="v2.1.10",
        image_digest="sha256:release",
        ref="abc123",
        created_at="2026-07-14T10:00:00Z",
        target_url="https://github.com/WriterInternal/cerebro/actions/runs/42",
    )


class ReleasePromotionTest(unittest.TestCase):
    def test_repository_rules_require_pr_and_exact_promotion_status_without_bypass(
        self,
    ) -> None:
        payload = configure_release_promotion_controls.ruleset_payload()

        self.assertEqual(payload["enforcement"], "active")
        self.assertEqual(payload["bypass_actors"], [])
        self.assertIn({"type": "deletion"}, payload["rules"])
        self.assertIn({"type": "non_fast_forward"}, payload["rules"])
        self.assertTrue(
            any(rule["type"] == "pull_request" for rule in payload["rules"])
        )
        status_rule = next(
            rule
            for rule in payload["rules"]
            if rule["type"] == "required_status_checks"
        )
        self.assertEqual(
            status_rule["parameters"]["required_status_checks"],
            [
                {
                    "context": "promotion/sec-dev-deployed",
                    "integration_id": 15368,
                }
            ],
        )

    def test_stable_tags_sort_numerically(self) -> None:
        self.assertGreater(
            release_promotion.parse_stable_tag("v2.1.10"),
            release_promotion.parse_stable_tag("v2.1.9"),
        )
        with self.assertRaises(ValueError):
            release_promotion.parse_stable_tag("v2.1.10-rc.1")

    def test_reads_stack_tag_without_yaml_dependency(self) -> None:
        self.assertEqual(
            release_promotion.read_stack_tag_text(
                "config:\n  cerebro:imageTag: 'v2.1.10' # release\n"
            ),
            "v2.1.10",
        )

    def test_reads_reviewed_stack_digest(self) -> None:
        digest = f"sha256:{'a' * 64}"
        self.assertEqual(
            release_promotion.read_stack_digest_text(
                f"config:\n  cerebro:imageDigest: {digest}\n"
            ),
            digest,
        )

    def test_successful_deployment_requires_exact_digest_and_latest_success_status(
        self,
    ) -> None:
        deployments = [
            {
                "id": 42,
                "environment": "sec-dev",
                "ref": "abc123",
                "created_at": "2026-07-14T10:00:00Z",
                "payload": {"imageTag": "v2.1.10", "imageDigest": "sha256:release"},
            },
            {
                "id": 41,
                "environment": "sec-dev",
                "ref": "older",
                "created_at": "2026-07-14T09:00:00Z",
                "payload": {"imageTag": "v2.1.10", "imageDigest": "sha256:wrong"},
            },
        ]
        statuses = [{"state": "success", "target_url": "https://github.com/run/42"}]
        with patch("release_promotion.gh_json", side_effect=[deployments, statuses]):
            matched = release_promotion.find_successful_deployment(
                "WriterInternal/cerebro",
                environment="sec-dev",
                image_tag="v2.1.10",
                image_digest="sha256:release",
            )
        self.assertIsNotNone(matched)
        self.assertEqual(matched.deployment_id, 42)

    def test_failed_deployment_does_not_open_production_gate(self) -> None:
        deployments = [
            {
                "id": 42,
                "payload": {"imageTag": "v2.1.10", "imageDigest": "sha256:release"},
            }
        ]
        with patch(
            "release_promotion.gh_json",
            side_effect=[deployments, [{"state": "failure"}]],
        ):
            matched = release_promotion.find_successful_deployment(
                "WriterInternal/cerebro",
                environment="sec-dev",
                image_tag="v2.1.10",
                image_digest="sha256:release",
            )
        self.assertIsNone(matched)

    def test_plan_never_dispatches_production_before_sec_dev_receipt(self) -> None:
        plan = reconcile_release_promotions.build_plan(
            latest_tag="v2.1.10",
            sec_dev_tag="v2.1.10",
            go_prod_tag="v2.1.9",
            sec_dev_receipt=None,
            go_prod_receipt=None,
        )
        self.assertEqual(plan.state, "sec-dev-deployment-required")
        self.assertIsNone(plan.dispatch_environment)

        ready_plan = reconcile_release_promotions.build_plan(
            latest_tag="v2.1.10",
            sec_dev_tag="v2.1.10",
            go_prod_tag="v2.1.9",
            sec_dev_receipt=receipt(),
            go_prod_receipt=None,
        )
        self.assertEqual(ready_plan.dispatch_environment, "go-prod")

    def test_plan_repairs_a_tag_with_the_wrong_reviewed_digest(self) -> None:
        plan = reconcile_release_promotions.build_plan(
            latest_tag="v2.1.10",
            latest_digest="sha256:release",
            sec_dev_tag="v2.1.10",
            sec_dev_digest="sha256:wrong",
            go_prod_tag="v2.1.9",
            go_prod_digest="sha256:older",
            sec_dev_receipt=None,
            go_prod_receipt=None,
        )
        self.assertEqual(plan.dispatch_environment, "sec-dev")

    def test_plan_refuses_automatic_downgrade(self) -> None:
        plan = reconcile_release_promotions.build_plan(
            latest_tag="v2.1.9",
            sec_dev_tag="v2.1.10",
            go_prod_tag="v2.1.9",
            sec_dev_receipt=None,
            go_prod_receipt=None,
        )
        self.assertEqual(plan.state, "blocked")
        self.assertIsNone(plan.dispatch_environment)

    def test_reconciler_selects_highest_published_stable_release(self) -> None:
        with patch(
            "reconcile_release_promotions.gh_json",
            return_value=[
                [
                    {"tag_name": "v2.1.9", "published_at": "2026-07-14T12:00:00Z"},
                    {"tag_name": "v2.1.10", "published_at": "2026-07-14T11:00:00Z"},
                    {"tag_name": "v2.1.11-rc.1", "prerelease": True},
                    {"tag_name": "v2.1.12", "draft": True},
                ]
            ],
        ):
            release = reconcile_release_promotions._latest_release("writer/cerebro")
        self.assertEqual(release["tag_name"], "v2.1.10")

    def test_reconciler_recovers_missing_release_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sec_dev = Path(directory) / "Pulumi.sec-dev.yaml"
            go_prod = Path(directory) / "Pulumi.go-prod.yaml"
            sec_dev.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: sha256:{'9' * 64}\n",
                encoding="utf-8",
            )
            go_prod.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: sha256:{'9' * 64}\n",
                encoding="utf-8",
            )
            release = {
                "tag_name": "v2.1.10",
                "html_url": "https://github.com/writer/cerebro/releases/tag/v2.1.10",
                "published_at": "2026-07-14T10:00:00Z",
            }
            with (
                patch(
                    "reconcile_release_promotions._promotion_pause", return_value=None
                ),
                patch(
                    "reconcile_release_promotions._latest_release", return_value=release
                ),
                patch(
                    "reconcile_release_promotions.resolve_image_digest",
                    return_value="sha256:release",
                ),
                patch(
                    "reconcile_release_promotions._promotion_is_active",
                    return_value=False,
                ),
                patch("reconcile_release_promotions._dispatch_promotion") as dispatch,
            ):
                status = reconcile_release_promotions.main(
                    [
                        "--repository",
                        "WriterInternal/cerebro",
                        "--sec-dev-stack",
                        str(sec_dev),
                        "--go-prod-stack",
                        str(go_prod),
                    ]
                )
        self.assertEqual(status, 0)
        dispatch.assert_called_once()
        self.assertEqual(dispatch.call_args.kwargs["environment"], "sec-dev")

    def test_reconciler_does_not_duplicate_active_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sec_dev = Path(directory) / "Pulumi.sec-dev.yaml"
            go_prod = Path(directory) / "Pulumi.go-prod.yaml"
            sec_dev.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: sha256:{'9' * 64}\n",
                encoding="utf-8",
            )
            go_prod.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: sha256:{'9' * 64}\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "reconcile_release_promotions._promotion_pause", return_value=None
                ),
                patch(
                    "reconcile_release_promotions._latest_release",
                    return_value={
                        "tag_name": "v2.1.10",
                        "published_at": "2026-07-14T10:00:00Z",
                    },
                ),
                patch(
                    "reconcile_release_promotions.resolve_image_digest",
                    return_value="sha256:release",
                ),
                patch(
                    "reconcile_release_promotions._promotion_is_active",
                    return_value=True,
                ),
                patch("reconcile_release_promotions._dispatch_promotion") as dispatch,
            ):
                status = reconcile_release_promotions.main(
                    [
                        "--repository",
                        "WriterInternal/cerebro",
                        "--sec-dev-stack",
                        str(sec_dev),
                        "--go-prod-stack",
                        str(go_prod),
                    ]
                )
        self.assertEqual(status, 0)
        dispatch.assert_not_called()

    def test_reconciler_does_not_reverse_an_approved_rollback(self) -> None:
        with (
            patch(
                "reconcile_release_promotions._promotion_pause",
                return_value={
                    "number": 42,
                    "url": "https://github.com/WriterInternal/cerebro/issues/42",
                },
            ),
            patch("reconcile_release_promotions._latest_release") as latest_release,
        ):
            status = reconcile_release_promotions.main(
                ["--repository", "WriterInternal/cerebro"]
            )
        self.assertEqual(status, 0)
        latest_release.assert_not_called()

    def test_gate_blocks_unapproved_rollback(self) -> None:
        result = refresh_release_promotion_gate.evaluate_gate(
            base_tag="v2.1.10",
            target_tag="v2.1.9",
            rollback_approved=False,
            sec_dev_receipt=receipt(),
        )
        self.assertEqual(result.state, "failure")

    def test_gate_requires_exact_sec_dev_receipt(self) -> None:
        pending = refresh_release_promotion_gate.evaluate_gate(
            base_tag="v2.1.9",
            target_tag="v2.1.10",
            rollback_approved=False,
            sec_dev_receipt=None,
        )
        self.assertEqual(pending.state, "pending")
        passed = refresh_release_promotion_gate.evaluate_gate(
            base_tag="v2.1.9",
            target_tag="v2.1.10",
            rollback_approved=False,
            sec_dev_receipt=receipt(),
        )
        self.assertEqual(passed.state, "success")

    def test_go_prod_rollback_requires_sec_dev_receipt_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stack = Path(directory) / "Pulumi.go-prod.yaml"
            stack.write_text("config:\n  cerebro:imageTag: v2.1.10\n", encoding="utf-8")
            sec_dev = Path(directory) / "Pulumi.sec-dev.yaml"
            digest = f"sha256:{'a' * 64}"
            sec_dev.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: {digest}\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "request_release_rollback._published_release",
                    return_value={"tag_name": "v2.1.9"},
                ),
                patch(
                    "request_release_rollback.resolve_image_digest",
                    return_value=digest,
                ),
                patch(
                    "request_release_rollback._ensure_promotion_pause",
                    return_value="2026-07-14T10:00:00Z",
                ),
                patch(
                    "request_release_rollback.find_successful_deployment",
                    return_value=None,
                ),
                self.assertRaisesRegex(RuntimeError, "successful sec-dev deployment"),
            ):
                request_release_rollback.main(
                    [
                        "--repository",
                        "WriterInternal/cerebro",
                        "--environment",
                        "go-prod",
                        "--image-tag",
                        "v2.1.9",
                        "--reason",
                        "Restore the last working image",
                        "--stack-file",
                        str(stack),
                    ]
                )

    def test_rollback_creates_a_durable_promotion_pause(self) -> None:
        with (
            patch("request_release_rollback.run") as command,
            patch(
                "request_release_rollback.gh_json",
                side_effect=[
                    [],
                    [
                        {
                            "number": 42,
                            "title": request_release_rollback.PAUSE_ISSUE_TITLE,
                            "createdAt": "2026-07-14T10:00:00Z",
                        }
                    ],
                ],
            ),
        ):
            created_at = request_release_rollback._ensure_promotion_pause(
                "WriterInternal/cerebro",
                image_tag="v2.1.9",
                environment="sec-dev",
                reason="Restore the last working image",
            )
        self.assertEqual(created_at, "2026-07-14T10:00:00Z")
        commands = [call.args[0] for call in command.call_args_list]
        self.assertTrue(
            any(items[:3] == ["gh", "label", "create"] for items in commands)
        )
        self.assertTrue(
            any(items[:3] == ["gh", "issue", "create"] for items in commands)
        )

    def test_go_prod_rollback_rejects_sec_dev_receipt_from_before_pause(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stack = Path(directory) / "Pulumi.go-prod.yaml"
            stack.write_text("config:\n  cerebro:imageTag: v2.1.10\n", encoding="utf-8")
            sec_dev = Path(directory) / "Pulumi.sec-dev.yaml"
            digest = f"sha256:{'a' * 64}"
            sec_dev.write_text(
                f"config:\n  cerebro:imageTag: v2.1.9\n  cerebro:imageDigest: {digest}\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "request_release_rollback._published_release",
                    return_value={"tag_name": "v2.1.9"},
                ),
                patch(
                    "request_release_rollback.resolve_image_digest",
                    return_value=digest,
                ),
                patch(
                    "request_release_rollback._ensure_promotion_pause",
                    return_value="2026-07-14T10:01:00Z",
                ),
                patch(
                    "request_release_rollback.find_successful_deployment",
                    return_value=receipt(),
                ),
                self.assertRaisesRegex(
                    RuntimeError, "completed after automatic promotion was paused"
                ),
            ):
                request_release_rollback.main(
                    [
                        "--repository",
                        "WriterInternal/cerebro",
                        "--environment",
                        "go-prod",
                        "--image-tag",
                        "v2.1.9",
                        "--reason",
                        "Restore the last working image",
                        "--stack-file",
                        str(stack),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
