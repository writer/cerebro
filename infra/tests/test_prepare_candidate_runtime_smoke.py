from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.prepare_candidate_runtime_smoke import (
    _candidate_task_family,
    _task_definition_with_candidate_image,
    _validate_candidate_image,
    prepare_candidate_task_definition,
)
from scripts.verify_source_runtime_ecs import RuntimeTarget


class PrepareCandidateRuntimeSmokeTest(unittest.TestCase):
    def test_candidate_task_family_stays_within_ecs_limit(self) -> None:
        family = "a" * 255

        candidate = _candidate_task_family(family)

        self.assertEqual(len(candidate), 255)
        self.assertTrue(candidate.endswith("-candidate-smoke"))

    def test_candidate_image_requires_exact_configured_ecr_digest(self) -> None:
        digest = f"sha256:{'a' * 64}"
        base = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cerebro"

        self.assertEqual(_validate_candidate_image(f"{base}@{digest}", base), f"{base}@{digest}")
        with self.assertRaisesRegex(ValueError, "exact ECR image digest"):
            _validate_candidate_image(f"{base}:candidate", base)
        with self.assertRaisesRegex(ValueError, "configured ECR repository"):
            _validate_candidate_image(
                f"123456789012.dkr.ecr.us-east-1.amazonaws.com/other@{digest}",
                base,
            )

    def test_task_definition_replaces_only_cerebro_image(self) -> None:
        candidate_image = f"123456789012.dkr.ecr.us-east-1.amazonaws.com/cerebro@sha256:{'b' * 64}"
        task_definition = {
            "taskDefinitionArn": "ignored",
            "revision": 4,
            "status": "ACTIVE",
            "family": "cerebro-go-production-orchestrator-okta",
            "taskRoleArn": "task-role",
            "executionRoleArn": "execution-role",
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "cpu": "1024",
            "memory": "2048",
            "containerDefinitions": [
                {"name": "source-runtime-bootstrap", "image": "bootstrap-image"},
                {"name": "cerebro", "image": "stable-image", "dependsOn": [{"containerName": "source-runtime-bootstrap"}]},
            ],
        }

        payload = _task_definition_with_candidate_image(task_definition, candidate_image)

        self.assertEqual(payload["family"], "cerebro-go-production-orchestrator-okta-candidate-smoke")
        self.assertEqual(payload["containerDefinitions"][0]["image"], "bootstrap-image")
        self.assertEqual(payload["containerDefinitions"][1]["image"], candidate_image)
        self.assertNotIn("taskDefinitionArn", payload)
        self.assertNotIn("revision", payload)
        self.assertNotIn("status", payload)

    def test_prepare_registers_candidate_revision_for_exact_runtime_target(self) -> None:
        digest = f"sha256:{'c' * 64}"
        ecr_base = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cerebro"
        candidate_image = f"{ecr_base}@{digest}"
        target = RuntimeTarget(
            runtime_id="runtime-1",
            schedule_name="runtime-1",
            rule_name="runtime-1",
            target={"EcsParameters": {"TaskDefinitionArn": "scheduled:3"}},
        )
        base_definition = {
            "family": "runtime",
            "containerDefinitions": [{"name": "cerebro", "image": "stable-image"}],
            "networkMode": "awsvpc",
        }

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {"taskDefinition": base_definition}
            if args[:2] == ["ecs", "register-task-definition"]:
                payload = json.loads(args[args.index("--cli-input-json") + 1])
                self.assertEqual(payload["containerDefinitions"][0]["image"], candidate_image)
                return {"taskDefinition": {"taskDefinitionArn": "candidate:1"}}
            raise AssertionError(f"unexpected args: {args}")

        with (
            patch(
                "scripts.prepare_candidate_runtime_smoke.runtime_verifier._load_config",
                return_value={"environment": "go-production", "ecrBaseUri": ecr_base},
            ),
            patch(
                "scripts.prepare_candidate_runtime_smoke.runtime_verifier._declared_runtime_ids",
                return_value=["runtime-1"],
            ),
            patch(
                "scripts.prepare_candidate_runtime_smoke.runtime_verifier._runtime_targets",
                return_value=[target],
            ),
            patch(
                "scripts.prepare_candidate_runtime_smoke.runtime_verifier._latest_active_task_definition",
                return_value="base:4",
            ),
            patch(
                "scripts.prepare_candidate_runtime_smoke.runtime_verifier._aws",
                side_effect=fake_aws,
            ),
        ):
            task_definition = prepare_candidate_task_definition(
                Path("aws/Pulumi.go-prod.yaml"),
                "runtime-1",
                candidate_image,
                "us-east-1",
            )

        self.assertEqual(task_definition, "candidate:1")


if __name__ == "__main__":
    unittest.main()
