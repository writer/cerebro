from __future__ import annotations

import unittest

from aws.source_rollouts import expand_source_runtime_rollouts


class SourceRuntimeRolloutsTest(unittest.TestCase):
    def test_expands_secrets_runtimes_and_schedules(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example_source",
                "tokenKey": "EXAMPLE_TOKEN",
                "perPage": "100",
                "commonConfig": {"base_url": "env:EXAMPLE_BASE_URL"},
                "families": [
                    "user",
                    {"name": "api_key", "config": {"path": "env:EXAMPLE_API_KEY_PATH"}},
                ],
            }
        ])

        self.assertEqual(expansion.source_secret_keys, ["EXAMPLE_BASE_URL", "EXAMPLE_TOKEN", "EXAMPLE_API_KEY_PATH"])
        self.assertEqual([runtime["id"] for runtime in expansion.source_runtimes], ["writer-example-source-user", "writer-example-source-api-key"])
        self.assertEqual(expansion.source_runtimes[1]["config"]["path"], "env:EXAMPLE_API_KEY_PATH")
        self.assertEqual([schedule["command"][2] for schedule in expansion.orchestrator_schedules], [
            "runtime_id=writer-example-source-user",
            "runtime_id=writer-example-source-api-key",
        ])

    def test_family_token_override(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "families": [
                    {"name": "user", "tokenKey": "EXAMPLE_USER_TOKEN", "tokenConfigKey": "api_token"},
                ],
            }
        ])

        self.assertEqual(expansion.source_secret_keys, ["EXAMPLE_USER_TOKEN"])
        self.assertEqual(expansion.source_runtimes[0]["config"]["api_token"], "env:EXAMPLE_USER_TOKEN")

    def test_family_schedule_name_override(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "families": [
                    {"name": "very_long_family_name", "schedule": {"name": "short-family-inventory"}},
                ],
            }
        ])

        self.assertEqual(expansion.source_runtimes[0]["id"], "writer-example-very-long-family-name")
        self.assertEqual(expansion.orchestrator_schedules[0]["name"], "short-family-inventory")

    def test_schedule_name_max_length_shortens_default_name(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "runtimePrefix": "writer-example-very-long-prefix",
                "schedule": {"nameMaxLength": 29},
                "families": ["organizations_account"],
            }
        ])

        schedule_name = expansion.orchestrator_schedules[0]["name"]
        self.assertLessEqual(len(schedule_name), 29)
        self.assertTrue(schedule_name.startswith("example-very-long"))

    def test_disabled_rollout_does_not_expand_secrets_runtimes_or_schedules(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "enabled": False,
                "tokenKey": "EXAMPLE_TOKEN",
                "families": ["user"],
            }
        ])

        self.assertEqual(expansion.source_secret_keys, [])
        self.assertEqual(expansion.source_runtimes, [])
        self.assertEqual(expansion.orchestrator_schedules, [])


if __name__ == "__main__":
    unittest.main()
