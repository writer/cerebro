from __future__ import annotations

import unittest

from aws.source_rollouts import apply_source_runtime_rollouts, expand_source_runtime_rollouts


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
        self.assertTrue(all(schedule["backend"] == "scheduler" for schedule in expansion.orchestrator_schedules))
        self.assertTrue(all(schedule["flexibleWindowMinutes"] == 60 for schedule in expansion.orchestrator_schedules))

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

    def test_schedule_backend_can_use_eventbridge_scheduler(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "schedule": {"backend": "scheduler", "flexibleWindowMinutes": 10, "state": "DISABLED"},
                "families": ["user"],
            }
        ])

        self.assertEqual(expansion.orchestrator_schedules[0]["backend"], "scheduler")
        self.assertEqual(expansion.orchestrator_schedules[0]["flexibleWindowMinutes"], 10)
        self.assertEqual(expansion.orchestrator_schedules[0]["state"], "DISABLED")

    def test_schedule_group_size_chunks_compatible_runtimes(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "runtimePrefix": "writer-example",
                "schedule": {"cadenceHours": 6, "groupSize": 2, "minuteStep": 5, "nameMaxLength": 32},
                "families": ["user", "group", "application"],
            }
        ])

        self.assertEqual([schedule["name"] for schedule in expansion.orchestrator_schedules], [
            "example-inventory-group-01",
            "example-application-inventory",
        ])
        self.assertEqual(expansion.orchestrator_schedules[0]["scheduleExpression"], "cron(0 0/6 * * ? *)")
        self.assertEqual(expansion.orchestrator_schedules[0]["command"][2], "runtime_ids=writer-example-user,writer-example-group")
        self.assertEqual(expansion.orchestrator_schedules[1]["command"][2], "runtime_id=writer-example-application")

    def test_schedule_group_size_keeps_different_limits_separate(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "runtimePrefix": "writer-example",
                "schedule": {"expression": "rate(1 hour)", "groupSize": 10},
                "families": [
                    {"name": "user", "schedule": {"pageLimit": 5}},
                    {"name": "group", "schedule": {"pageLimit": 5}},
                    "application",
                    "policy",
                ],
            }
        ])

        self.assertEqual([schedule["command"][2] for schedule in expansion.orchestrator_schedules], [
            "runtime_ids=writer-example-user,writer-example-group",
            "runtime_ids=writer-example-application,writer-example-policy",
        ])
        self.assertEqual(expansion.orchestrator_schedules[0]["command"][3], "page_limit=5")
        self.assertEqual(expansion.orchestrator_schedules[1]["command"][3], "page_limit=20")

    def test_schedule_task_profile_is_preserved_and_keeps_groups_separate(self) -> None:
        expansion = expand_source_runtime_rollouts([
            {
                "sourceId": "example",
                "runtimePrefix": "writer-example",
                "schedule": {"expression": "rate(1 hour)", "groupSize": 10, "taskProfile": "small"},
                "families": [
                    "user",
                    {"name": "group", "schedule": {"taskProfile": "default"}},
                    "application",
                ],
            }
        ])

        self.assertEqual([schedule["command"][2] for schedule in expansion.orchestrator_schedules], [
            "runtime_ids=writer-example-user,writer-example-application",
            "runtime_id=writer-example-group",
        ])
        self.assertEqual([schedule["taskProfile"] for schedule in expansion.orchestrator_schedules], ["small", "default"])

    def test_schedule_backend_must_be_known(self) -> None:
        with self.assertRaisesRegex(ValueError, "schedule.backend"):
            expand_source_runtime_rollouts([
                {
                    "sourceId": "example",
                    "schedule": {"backend": "cronbox"},
                    "families": ["user"],
                }
            ])

    def test_schedule_state_must_be_known(self) -> None:
        with self.assertRaisesRegex(ValueError, "schedule.state"):
            expand_source_runtime_rollouts([
                {
                    "sourceId": "example",
                    "schedule": {"state": "paused"},
                    "families": ["user"],
                }
            ])

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

    def test_apply_rollouts_deduplicates_source_secret_keys(self) -> None:
        config = apply_source_runtime_rollouts({
            "sourceSecretKeys": ["EXAMPLE_BASE_URL"],
            "sourceRuntimes": [],
            "orchestratorSchedules": [],
            "sourceRuntimeRollouts": [
                {
                    "sourceId": "example",
                    "tokenKey": "EXAMPLE_TOKEN",
                    "commonConfig": {"base_url": "env:EXAMPLE_BASE_URL"},
                    "families": [
                        "user",
                        "group",
                    ],
                }
            ],
        })

        self.assertEqual(config["sourceSecretKeys"], ["EXAMPLE_BASE_URL", "EXAMPLE_TOKEN"])


if __name__ == "__main__":
    unittest.main()
