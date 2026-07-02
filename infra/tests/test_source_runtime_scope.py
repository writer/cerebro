from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aws import source_runtime_scope


class SourceRuntimeScopeTest(unittest.TestCase):
    def test_runtime_ids_from_command_accepts_singular_and_grouped_filters(self) -> None:
        self.assertEqual(
            source_runtime_scope.runtime_ids_from_command([
                "orchestrator",
                "run",
                "runtime_id=writer-okta-audit",
                "runtime_ids=writer-cosmo-session, writer-cosmo-message",
            ]),
            ["writer-okta-audit", "writer-cosmo-session", "writer-cosmo-message"],
        )
        self.assertEqual(
            source_runtime_scope.runtime_id_from_command(["orchestrator", "run", "runtime_ids=runtime-a,runtime-b"]),
            "runtime-a",
        )

    def test_declared_runtime_ids_filter_by_source_requested_and_family(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint"}},
                {"id": "aws-asset", "sourceId": "aws", "config": {"family": "asset_metadata"}},
                {"id": "panopticon-alerts", "sourceId": "panopticon", "config": {"family": "alert"}},
            ]
        }

        self.assertEqual(
            source_runtime_scope.declared_runtime_ids(config, "aws", {"aws-public", "panopticon-alerts"}, {"public_endpoint"}),
            ["aws-public"],
        )

    def test_observability_runtime_ids_filter_enabled_state(self) -> None:
        config = {
            "sourceRuntimeObservability": [
                {"sourceSystem": "panopticon", "sourceRuntimeId": "writer-panopticon-alerts", "runtimeClass": "alert", "enabled": True},
                {"sourceSystem": "panopticon", "sourceRuntimeId": "writer-panopticon-cases", "runtimeClass": "case", "enabled": False},
            ]
        }

        self.assertEqual(source_runtime_scope.observability_runtime_ids(config, "panopticon"), ["writer-panopticon-alerts"])
        self.assertEqual(
            source_runtime_scope.observability_runtime_ids(config, "panopticon", enabled=False),
            ["writer-panopticon-cases"],
        )

    def test_recursive_env_refs_and_scope_config(self) -> None:
        config = {
            "sourceSecretKeys": ["AWS_TOKEN", "PANOPTICON_TOKEN"],
            "sourceRuntimes": [
                {"id": "aws-public", "config": {"auth": {"token": "env:AWS_TOKEN"}}},
                {"id": "panopticon-alerts", "config": {"token": "env:PANOPTICON_TOKEN"}},
            ],
        }

        scoped = source_runtime_scope.config_for_runtime_scope(config, {"aws-public"})

        self.assertEqual([runtime["id"] for runtime in scoped["sourceRuntimes"]], ["aws-public"])
        self.assertEqual(scoped["sourceSecretKeys"], ["AWS_TOKEN"])

    def test_s3_prefix_covers_child_prefixes(self) -> None:
        self.assertTrue(source_runtime_scope.s3_prefix_covers("exports/alerts/", "exports/alerts/daily/"))
        self.assertFalse(source_runtime_scope.s3_prefix_covers("exports/cases/", "exports/alerts/daily/"))


if __name__ == "__main__":
    unittest.main()
