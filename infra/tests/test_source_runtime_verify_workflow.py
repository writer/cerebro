from __future__ import annotations

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "source-runtime-verify.yml"
INFRA_DEPLOY_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "infra-deploy.yml"
DRIFT_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "source-runtime-drift.yml"
BACKFILL_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "source-runtime-backfill.yml"


class SourceRuntimeVerifyWorkflowTest(unittest.TestCase):
    def test_manual_source_runtime_workflow_exposes_readiness_controls(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("- dry-run", workflow)
        self.assertIn("observability_targets:", workflow)
        self.assertIn("allow_missing_targets:", workflow)
        self.assertIn("family:", workflow)
        self.assertIn("target_concurrency:", workflow)

    def test_manual_source_runtime_workflow_uses_live_go_prod_panopticon_api_verification(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        go_prod_block = workflow.split("verify-go-prod:", 1)[1]

        self.assertNotIn("GO_PROD_PANOPTICON_READINESS_ONLY", go_prod_block)
        self.assertNotIn("not_configured/dry_run", go_prod_block)
        self.assertNotIn("--exclude-source-id panopticon", go_prod_block)
        self.assertIn('if [ "${VERIFY_MODE}" = "run" ]; then', go_prod_block)
        self.assertIn("args+=(--run)", go_prod_block)

    def test_infra_deploy_wires_panopticon_api_live_modes(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("GO_PROD_PANOPTICON_READINESS_ONLY", workflow)
        self.assertNotIn("not_configured/dry_run", workflow)
        self.assertNotIn("--exclude-source-id panopticon", workflow)
        self.assertIn("scripts/verify_aws_scan_role_trust.py --stack-file aws/Pulumi.go-prod.yaml --same-account-only", workflow)
        self.assertIn("--source-runtime-observability-targets --source-id panopticon --source-target-concurrency 4", workflow)
        self.assertIn(
            "--source-runtime-observability-targets --source-id panopticon --source-target-concurrency 2",
            workflow,
        )
        self.assertNotIn("--source-runtime-dry-run", workflow)
        self.assertNotIn("--source-runtime-allow-missing-targets --source-id panopticon", workflow)

    def test_scan_role_guards_do_not_special_case_panopticon_api_runtimes(self) -> None:
        manual_workflow = WORKFLOW.read_text(encoding="utf-8")
        infra_workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        drift_workflow = DRIFT_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "scripts/verify_aws_scan_role_trust.py --stack-file aws/Pulumi.sec-dev.yaml --same-account-only",
            manual_workflow,
        )
        self.assertIn(
            "scripts/verify_aws_scan_role_trust.py --stack-file aws/Pulumi.sec-dev.yaml --same-account-only",
            infra_workflow,
        )
        self.assertNotIn("--exclude-source-id panopticon", manual_workflow)
        self.assertNotIn("--exclude-source-id panopticon", infra_workflow)
        self.assertNotIn("--exclude-source-id panopticon", drift_workflow)

    def test_backfill_workflow_uses_planner_and_graph_ingest_verification(self) -> None:
        workflow = BACKFILL_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("scripts/plan_graph_backfill.py", workflow)
        self.assertIn("source-runtime-backfill-plan.tsv", workflow)
        self.assertIn("--format commands", workflow)
        self.assertIn("environment: production", workflow)


if __name__ == "__main__":
    unittest.main()
