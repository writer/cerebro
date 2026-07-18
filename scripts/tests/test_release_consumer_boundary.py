from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CANDIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"
EVENT_SCHEMA = ROOT / "schemas" / "product-release-published.schema.json"


class ReleaseConsumerBoundaryTest(unittest.TestCase):
    def test_event_contract_has_only_portable_release_identity(self) -> None:
        schema = json.loads(EVENT_SCHEMA.read_text(encoding="utf-8"))
        expected = {
            "schema_version",
            "release_tag",
            "release_commit",
            "release_url",
            "manifest_url",
            "manifest_sha256",
        }

        self.assertEqual(schema["properties"].keys(), expected)
        self.assertEqual(set(schema["required"]), expected)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            "cerebro.product-release-published/v1",
        )

    def test_public_release_workflows_exclude_deployment_policy(self) -> None:
        workflows = (
            RELEASE_WORKFLOW.read_text(encoding="utf-8")
            + "\n"
            + CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        ).lower()
        forbidden = {
            "target_environment",
            "apply_mode",
            "credential bootstrap",
            "secrets-action@",
            "/contents/.github/workflows/",
            "propose-image-tag",
            "runtime-contract-",
            "-format contract-json",
            "request_id",
        }

        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, workflows)

    def test_consumer_dispatch_is_minimal_and_fail_closed(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn('event_type:"product-release-published"', workflow)
        self.assertIn("python3 scripts/release/product_release.py validate-event", workflow)
        self.assertIn("RELEASE_CONSUMER_TOKEN", workflow)
        self.assertIn("RELEASE_CONSUMER_REPOSITORY", workflow)
        self.assertIn("configure both RELEASE_CONSUMER_TOKEN and RELEASE_CONSUMER_REPOSITORY", workflow)
        self.assertIn(".client_payload | length' dispatch.json)\" -eq 6", workflow)
        self.assertNotIn("gh run list --repo \"${RELEASE_CONSUMER_REPOSITORY}\"", workflow)

    def test_candidate_scans_every_published_image_platform(self) -> None:
        workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn('for image in "${RUNTIME_IMAGE}" "${WEB_IMAGE}"', workflow)
        self.assertIn("for platform in linux/amd64 linux/arm64", workflow)
        self.assertEqual(workflow.count('--platform "${platform}"'), 2)


if __name__ == "__main__":
    unittest.main()
