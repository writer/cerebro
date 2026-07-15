from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import reconcile_release_promotions
import approve_production_config_change
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
        pull_request_rule = next(
            rule for rule in payload["rules"] if rule["type"] == "pull_request"
        )
        self.assertFalse(
            pull_request_rule["parameters"]["require_code_owner_review"]
        )
        self.assertTrue(
            pull_request_rule["parameters"]["dismiss_stale_reviews_on_push"]
        )
        self.assertEqual(
            pull_request_rule["parameters"]["required_reviewers"],
            [
                {
                    "file_patterns": (
                        configure_release_promotion_controls.SECURITY_CONTROL_PATTERNS
                    ),
                    "minimum_approvals": 1,
                    "reviewer": {
                        "id": configure_release_promotion_controls.SECURITY_TEAM_ID,
                        "type": "Team",
                    },
                }
            ],
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

    def test_rollback_environment_requires_multiple_reviewers_and_no_self_review(
        self,
    ) -> None:
        with patch(
            "configure_release_promotion_controls.gh_json",
            side_effect=[{}, [], {}, {}, {}, {}],
        ) as github:
            configure_release_promotion_controls.apply_controls(
                "WriterInternal/cerebro", [1, 2, 3]
            )

        rollback_call = next(
            call
            for call in github.call_args_list
            if call.args[0][-1].endswith("/environments/production-rollback")
        )
        rollback_payload = rollback_call.kwargs["input_payload"]
        self.assertTrue(rollback_payload["prevent_self_review"])
        self.assertEqual(
            rollback_payload["reviewers"],
            [
                {"type": "User", "id": 1},
                {"type": "User", "id": 2},
                {"type": "User", "id": 3},
            ],
        )
        config_call = next(
            call
            for call in github.call_args_list
            if call.args[0][-1].endswith("/environments/production-config-change")
        )
        config_payload = config_call.kwargs["input_payload"]
        self.assertTrue(config_payload["prevent_self_review"])
        self.assertEqual(
            config_payload["reviewers"],
            [
                {
                    "type": "Team",
                    "id": configure_release_promotion_controls.SECURITY_TEAM_ID,
                }
            ],
        )

    def test_control_verifier_reads_prevent_self_review_from_protection_rule(
        self,
    ) -> None:
        environment = {
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [],
                }
            ]
        }

        self.assertTrue(
            configure_release_promotion_controls._prevents_self_review(environment)
        )
        self.assertFalse(
            configure_release_promotion_controls._prevents_self_review(
                {"prevent_self_review": True, "protection_rules": []}
            )
        )

    def test_successful_deployment_requires_exact_digest_and_latest_success_status(
        self,
    ) -> None:
        digest = f"sha256:{'a' * 64}"
        run_url = "https://github.com/WriterInternal/cerebro/actions/runs/4200"
        deployments = [
            {
                "id": 42,
                "environment": "sec-dev",
                "ref": "abc123",
                "created_at": "2026-07-14T10:00:00Z",
                "creator": {"login": "github-actions[bot]"},
                "payload": {
                    "imageTag": "v2.1.10",
                    "imageDigest": digest,
                    "workflowRun": run_url,
                    "workflowRunId": 4200,
                    "workflowRunAttempt": 1,
                },
            },
            {
                "id": 41,
                "environment": "sec-dev",
                "ref": "older",
                "created_at": "2026-07-14T09:00:00Z",
                "payload": {"imageTag": "v2.1.10", "imageDigest": "sha256:wrong"},
            },
        ]
        statuses = [
            {
                "state": "success",
                "environment": "sec-dev",
                "target_url": run_url,
                "creator": {"login": "github-actions[bot]"},
            }
        ]
        workflow_run = {
            "id": 4200,
            "event": "push",
            "head_branch": "main",
            "head_sha": "abc123",
            "path": release_promotion.INFRA_DEPLOY_WORKFLOW_PATH,
            "run_attempt": 1,
            "conclusion": "success",
            "html_url": run_url,
            "repository": {"full_name": "WriterInternal/cerebro"},
        }
        jobs = {
            "jobs": [
                {
                    "name": "Deploy sec-dev",
                    "conclusion": "success",
                    "steps": [
                        {"name": "Pulumi Up (sec-dev)", "conclusion": "success"}
                    ],
                }
            ]
        }
        stack_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {digest}\n"
        )
        with (
            patch(
                "release_promotion.gh_json",
                side_effect=[deployments, statuses, workflow_run, jobs],
            ),
            patch("release_promotion.repository_file", return_value=stack_text),
        ):
            matched = release_promotion.find_successful_deployment(
                "WriterInternal/cerebro",
                environment="sec-dev",
                image_tag="v2.1.10",
                image_digest=digest,
            )
        self.assertIsNotNone(matched)
        self.assertEqual(matched.deployment_id, 42)

    def test_forged_deployment_record_does_not_open_production_gate(self) -> None:
        digest = f"sha256:{'a' * 64}"
        deployments = [
            {
                "id": 42,
                "ref": "abc123",
                "creator": {"login": "write-user"},
                "payload": {
                    "imageTag": "v2.1.10",
                    "imageDigest": digest,
                    "workflowRunId": 4200,
                    "workflowRunAttempt": 1,
                },
            }
        ]
        with patch("release_promotion.gh_json", return_value=deployments) as github:
            matched = release_promotion.find_successful_deployment(
                "WriterInternal/cerebro",
                environment="sec-dev",
                image_tag="v2.1.10",
                image_digest=digest,
            )

        self.assertIsNone(matched)
        github.assert_called_once()

    def test_workflow_without_successful_pulumi_up_does_not_open_gate(self) -> None:
        digest = f"sha256:{'a' * 64}"
        run_url = "https://github.com/WriterInternal/cerebro/actions/runs/4200"
        payload = {
            "imageTag": "v2.1.10",
            "imageDigest": digest,
            "workflowRun": run_url,
            "workflowRunId": 4200,
            "workflowRunAttempt": 1,
        }
        deployment = {
            "id": 42,
            "environment": "sec-dev",
            "ref": "abc123",
            "creator": {"login": "github-actions[bot]"},
            "payload": payload,
        }
        status = {
            "state": "success",
            "environment": "sec-dev",
            "target_url": run_url,
            "creator": {"login": "github-actions[bot]"},
        }
        workflow_run = {
            "id": 4200,
            "event": "push",
            "head_branch": "main",
            "head_sha": "abc123",
            "path": release_promotion.INFRA_DEPLOY_WORKFLOW_PATH,
            "run_attempt": 1,
            "conclusion": "success",
            "html_url": run_url,
            "repository": {"full_name": "WriterInternal/cerebro"},
        }
        jobs = {
            "jobs": [
                {
                    "name": "Deploy sec-dev",
                    "conclusion": "success",
                    "steps": [
                        {"name": "Pulumi Up (sec-dev)", "conclusion": "skipped"}
                    ],
                }
            ]
        }
        stack_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {digest}\n"
        )
        with (
            patch(
                "release_promotion.gh_json",
                side_effect=[[deployment], [status], workflow_run, jobs],
            ),
            patch("release_promotion.repository_file", return_value=stack_text),
        ):
            matched = release_promotion.find_successful_deployment(
                "WriterInternal/cerebro",
                environment="sec-dev",
                image_tag="v2.1.10",
                image_digest=digest,
            )

        self.assertIsNone(matched)

    def test_failed_deployment_does_not_open_production_gate(self) -> None:
        deployments = [
            {
                "id": 42,
                "creator": {"login": "github-actions[bot]"},
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

    def test_gate_accepts_only_protected_workflow_rollback_approval(self) -> None:
        run_url = "https://github.com/WriterInternal/cerebro/actions/runs/4200"
        statuses = [
            {
                "context": release_promotion.ROLLBACK_APPROVAL_CONTEXT,
                "state": "success",
                "target_url": run_url,
                "creator": {"login": "github-actions[bot]"},
            }
        ]
        workflow_run = {
            "id": 4200,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": refresh_release_promotion_gate.ROLLBACK_WORKFLOW_PATH,
            "conclusion": "success",
            "html_url": run_url,
            "repository": {"full_name": "WriterInternal/cerebro"},
        }
        approvals = [
            {
                "state": "approved",
                "environments": [{"name": "production-rollback"}],
            }
        ]
        with patch(
            "refresh_release_promotion_gate.gh_json",
            side_effect=[statuses, workflow_run, approvals],
        ):
            approved = refresh_release_promotion_gate._rollback_approved(
                "WriterInternal/cerebro", "head-sha"
            )

        self.assertTrue(approved)

    def test_gate_rejects_write_user_rollback_status(self) -> None:
        statuses = [
            {
                "context": release_promotion.ROLLBACK_APPROVAL_CONTEXT,
                "state": "success",
                "target_url": (
                    "https://github.com/WriterInternal/cerebro/actions/runs/4200"
                ),
                "creator": {"login": "write-user"},
            }
        ]
        with patch(
            "refresh_release_promotion_gate.gh_json", return_value=statuses
        ) as github:
            approved = refresh_release_promotion_gate._rollback_approved(
                "WriterInternal/cerebro", "head-sha"
            )

        self.assertFalse(approved)
        github.assert_called_once()

    def test_gate_rejects_rollback_without_environment_approval(self) -> None:
        run_url = "https://github.com/WriterInternal/cerebro/actions/runs/4200"
        statuses = [
            {
                "context": release_promotion.ROLLBACK_APPROVAL_CONTEXT,
                "state": "success",
                "target_url": run_url,
                "creator": {"login": "github-actions[bot]"},
            }
        ]
        workflow_run = {
            "id": 4200,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": refresh_release_promotion_gate.ROLLBACK_WORKFLOW_PATH,
            "conclusion": "success",
            "html_url": run_url,
            "repository": {"full_name": "WriterInternal/cerebro"},
        }
        with patch(
            "refresh_release_promotion_gate.gh_json",
            side_effect=[statuses, workflow_run, []],
        ):
            approved = refresh_release_promotion_gate._rollback_approved(
                "WriterInternal/cerebro", "head-sha"
            )

        self.assertFalse(approved)

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

    def test_gate_requires_sec_dev_receipt_for_same_tag_digest_change(self) -> None:
        pending = refresh_release_promotion_gate.evaluate_gate(
            base_tag="v2.1.10",
            target_tag="v2.1.10",
            base_digest="sha256:old",
            target_digest="sha256:new",
            rollback_approved=False,
            sec_dev_receipt=None,
        )
        self.assertEqual(pending.state, "pending")

        passed = refresh_release_promotion_gate.evaluate_gate(
            base_tag="v2.1.10",
            target_tag="v2.1.10",
            base_digest="sha256:old",
            target_digest="sha256:new",
            rollback_approved=False,
            sec_dev_receipt=receipt(),
        )
        self.assertEqual(passed.state, "success")

    def test_gate_verifies_same_tag_digest_change_against_sec_dev(self) -> None:
        base_digest = f"sha256:{'a' * 64}"
        target_digest = f"sha256:{'b' * 64}"
        pull = {"head": {"sha": "head-sha"}, "base": {"sha": "base-sha"}}
        base_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {base_digest}\n"
        )
        target_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {target_digest}\n"
        )
        with (
            patch("refresh_release_promotion_gate.gh_json", return_value=pull),
            patch(
                "refresh_release_promotion_gate.repository_file",
                side_effect=[base_text, target_text],
            ),
            patch(
                "refresh_release_promotion_gate._published_release", return_value=True
            ),
            patch(
                "refresh_release_promotion_gate.resolve_image_digest",
                return_value=target_digest,
            ),
            patch(
                "refresh_release_promotion_gate.find_successful_deployment",
                return_value=receipt(),
            ) as find_receipt,
            patch("refresh_release_promotion_gate.post_commit_status"),
        ):
            result = refresh_release_promotion_gate._refresh_pull(
                "WriterInternal/cerebro", "writer/cerebro", 42
            )

        self.assertEqual(result.state, "success")
        find_receipt.assert_called_once_with(
            "WriterInternal/cerebro",
            environment="sec-dev",
            image_tag="v2.1.10",
            image_digest=target_digest,
        )

    def test_gate_requires_protected_approval_for_non_image_production_change(
        self,
    ) -> None:
        digest = f"sha256:{'a' * 64}"
        pull = {"head": {"sha": "head-sha"}, "base": {"sha": "base-sha"}}
        base_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {digest}\n  cerebro:vpcId: vpc-old\n"
        )
        target_text = base_text.replace("vpc-old", "vpc-new")
        with (
            patch("refresh_release_promotion_gate.gh_json", return_value=pull),
            patch(
                "refresh_release_promotion_gate.repository_file",
                side_effect=[base_text, target_text],
            ),
            patch(
                "refresh_release_promotion_gate._production_config_approved",
                return_value=False,
            ),
            patch("refresh_release_promotion_gate.resolve_image_digest") as resolve,
            patch("refresh_release_promotion_gate.post_commit_status") as post_status,
        ):
            result = refresh_release_promotion_gate._refresh_pull(
                "WriterInternal/cerebro", "writer/cerebro", 42
            )

        self.assertEqual(result.state, "pending")
        self.assertEqual(result.description, "Production configuration approval is required")
        resolve.assert_not_called()
        self.assertEqual(
            post_status.call_args.kwargs["context"],
            refresh_release_promotion_gate.CONTEXT,
        )

    def test_gate_accepts_only_protected_production_config_approval(self) -> None:
        run_url = "https://github.com/WriterInternal/cerebro/actions/runs/4300"
        statuses = [
            {
                "context": release_promotion.PRODUCTION_CONFIG_APPROVAL_CONTEXT,
                "state": "success",
                "target_url": run_url,
                "creator": {"login": "github-actions[bot]"},
            }
        ]
        workflow_run = {
            "id": 4300,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": refresh_release_promotion_gate.PRODUCTION_CONFIG_WORKFLOW_PATH,
            "conclusion": "success",
            "html_url": run_url,
            "repository": {"full_name": "WriterInternal/cerebro"},
        }
        approvals = [
            {
                "state": "approved",
                "environments": [{"name": "production-config-change"}],
            }
        ]
        with patch(
            "refresh_release_promotion_gate.gh_json",
            side_effect=[statuses, workflow_run, approvals],
        ):
            approved = refresh_release_promotion_gate._production_config_approved(
                "WriterInternal/cerebro", "head-sha"
            )

        self.assertTrue(approved)

    def test_production_config_approval_records_exact_pr_commit(self) -> None:
        pull = {
            "state": "open",
            "base": {"ref": "main"},
            "head": {
                "sha": "config-head",
                "repo": {"full_name": "WriterInternal/cerebro"},
            },
        }
        with (
            patch("approve_production_config_change.gh_json", return_value=pull),
            patch(
                "approve_production_config_change.post_commit_status"
            ) as post_status,
            patch.dict(
                "os.environ",
                {
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_RUN_ID": "4300",
                },
                clear=False,
            ),
        ):
            target_url = approve_production_config_change.approve_pull_request(
                "WriterInternal/cerebro", 42
            )

        self.assertEqual(
            target_url,
            "https://github.com/WriterInternal/cerebro/actions/runs/4300",
        )
        post_status.assert_called_once_with(
            "WriterInternal/cerebro",
            sha="config-head",
            state="success",
            context=release_promotion.PRODUCTION_CONFIG_APPROVAL_CONTEXT,
            description="Protected production configuration approval for PR #42",
            target_url=target_url,
        )

    def test_gate_posts_error_status_when_release_verification_is_unavailable(
        self,
    ) -> None:
        digest = f"sha256:{'a' * 64}"
        pull = {
            "head": {"sha": "head-sha"},
            "base": {"sha": "base-sha"},
            "labels": [],
        }
        base_text = (
            f"config:\n  cerebro:imageTag: v2.1.9\n"
            f"  cerebro:imageDigest: {digest}\n"
        )
        target_text = (
            f"config:\n  cerebro:imageTag: v2.1.10\n"
            f"  cerebro:imageDigest: {digest}\n"
        )
        with (
            patch("refresh_release_promotion_gate.gh_json", return_value=pull),
            patch(
                "refresh_release_promotion_gate.repository_file",
                side_effect=[base_text, target_text],
            ),
            patch(
                "refresh_release_promotion_gate._published_release", return_value=True
            ),
            patch(
                "refresh_release_promotion_gate.resolve_image_digest",
                side_effect=RuntimeError("registry unavailable"),
            ),
            patch("refresh_release_promotion_gate.post_commit_status") as post_status,
        ):
            result = refresh_release_promotion_gate._refresh_pull(
                "WriterInternal/cerebro", "writer/cerebro", 42
            )

        self.assertEqual(result.state, "error")
        post_status.assert_called_once_with(
            "WriterInternal/cerebro",
            sha="head-sha",
            state="error",
            context=refresh_release_promotion_gate.CONTEXT,
            description="Release verification unavailable; retry scheduled",
            target_url="",
        )

    def test_gate_refresh_continues_after_a_pull_request_failure(self) -> None:
        with (
            patch(
                "refresh_release_promotion_gate._pull_numbers", return_value=[41, 42]
            ),
            patch(
                "refresh_release_promotion_gate._refresh_pull",
                side_effect=[
                    RuntimeError("GitHub unavailable"),
                    refresh_release_promotion_gate.GateResult(
                        "success", "No production image change"
                    ),
                ],
            ) as refresh_pull,
        ):
            status = refresh_release_promotion_gate.main(
                ["--repository", "WriterInternal/cerebro"]
            )

        self.assertEqual(status, 1)
        self.assertEqual(refresh_pull.call_count, 2)

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

    def test_rollback_records_approval_on_the_exact_pr_commit(self) -> None:
        with (
            patch(
                "request_release_rollback.gh_json",
                return_value={"headRefOid": "rollback-head"},
            ),
            patch("request_release_rollback.post_commit_status") as post_status,
            patch.dict(
                "os.environ",
                {
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_RUN_ID": "4200",
                },
                clear=False,
            ),
        ):
            request_release_rollback._record_rollback_approval(
                "WriterInternal/cerebro",
                pr_url="https://github.com/WriterInternal/cerebro/pull/42",
                image_tag="v2.1.9",
            )

        post_status.assert_called_once_with(
            "WriterInternal/cerebro",
            sha="rollback-head",
            state="success",
            context=release_promotion.ROLLBACK_APPROVAL_CONTEXT,
            description="Protected rollback workflow approved v2.1.9",
            target_url=(
                "https://github.com/WriterInternal/cerebro/actions/runs/4200"
            ),
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
