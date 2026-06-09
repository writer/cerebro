from __future__ import annotations

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "source-runtime-verify.yml"
INFRA_DEPLOY_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "infra-deploy.yml"


class SourceRuntimeVerifyWorkflowTest(unittest.TestCase):
    def test_manual_source_runtime_workflow_exposes_readiness_controls(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("- dry-run", workflow)
        self.assertIn("observability_targets:", workflow)
        self.assertIn("allow_missing_targets:", workflow)
        self.assertIn("family:", workflow)
        self.assertIn("target_concurrency:", workflow)

    def test_manual_source_runtime_workflow_keeps_go_prod_panopticon_readiness_only(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        go_prod_block = workflow.split("verify-go-prod:", 1)[1]

        self.assertIn('if [ "${SOURCE_ID}" = "panopticon" ] && [ "${OBSERVABILITY_TARGETS}" = "true" ]; then', go_prod_block)
        self.assertIn('if [ "${VERIFY_MODE}" = "run" ]; then', go_prod_block)
        self.assertIn("args+=(--dry-run --allow-missing-targets)", go_prod_block)

    def test_infra_deploy_wires_panopticon_live_and_readiness_modes(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("--source-runtime-observability-targets --source-id panopticon --source-target-concurrency 4", workflow)
        self.assertIn(
            "--source-runtime-dry-run --source-runtime-observability-targets --source-runtime-allow-missing-targets --source-id panopticon --source-target-concurrency 2",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
