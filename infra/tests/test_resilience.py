from __future__ import annotations

import base64
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("resilience", Path(__file__).resolve().parents[1] / "aws" / "resilience.py")
resilience = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resilience)


class ResilienceTest(unittest.TestCase):
    def test_runtime_controls_are_disabled_by_default(self) -> None:
        self.assertEqual(resilience.create_runtime_controls("cerebro-test", "test"), {})

    def test_state_machine_definition_runs_orchestrator_task_with_retry(self) -> None:
        definition = resilience._state_machine_definition("cluster", "task-def", ["subnet-a"], "sg-a")

        task = definition["States"]["RunOrchestratorTask"]
        self.assertEqual(task["Resource"], "arn:aws:states:::ecs:runTask.sync")
        self.assertEqual(task["Parameters"]["Overrides"]["ContainerOverrides"][0]["Command.$"], "$.command")
        self.assertEqual(task["Parameters"]["NetworkConfiguration"]["AwsvpcConfiguration"]["SecurityGroups"], ["sg-a"])
        self.assertEqual(task["Retry"][0]["MaxAttempts"], 2)

    def test_buffer_requires_step_function_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires a Step Functions state machine target"):
            resilience.create_orchestrator_buffer("cerebro-test", enabled=True)

    def test_canary_zip_targets_health_endpoint(self) -> None:
        archive = base64.b64decode(resilience._canary_zip_file("https://cerebro.example.com"))
        with zipfile.ZipFile(io.BytesIO(archive)) as zip_file:
            source = zip_file.read("index.js").decode("utf-8")

        self.assertIn("https://cerebro.example.com/health", source)
        self.assertIn("Cerebro health probe failed", source)

    def test_synthetics_canary_name_fits_aws_limit(self) -> None:
        self.assertEqual(resilience._synthetics_canary_name("cerebro-go-production-api"), "cerebro-go-production")
        self.assertLessEqual(len(resilience._synthetics_canary_name("cerebro-go-production-api")), 21)

    def test_cost_controls_create_nothing_without_notification_route(self) -> None:
        self.assertEqual(
            resilience.create_cost_controls(
                "cerebro-test",
                monthly_budget_usd=100,
                anomaly_detection_enabled=True,
            ),
            {},
        )

    def test_cost_controls_wire_budget_and_anomaly_subscriber(self) -> None:
        calls = []

        def fake_monitor(*args, **kwargs):
            calls.append(("monitor", args, kwargs))
            return SimpleNamespace(arn="monitor-arn")

        def fake_subscription(*args, **kwargs):
            calls.append(("subscription", args, kwargs))
            return SimpleNamespace()

        def fake_budget(*args, **kwargs):
            calls.append(("budget", args, kwargs))
            return SimpleNamespace()

        with patch.object(resilience.aws.costexplorer, "AnomalyMonitor", fake_monitor), \
             patch.object(resilience.aws.costexplorer, "AnomalySubscription", fake_subscription), \
             patch.object(resilience.aws.budgets, "Budget", fake_budget):
            resources = resilience.create_cost_controls(
                "cerebro-test",
                sns_topic_arns=["arn:aws:sns:us-east-1:123456789012:cerebro-alerts"],
                monthly_budget_usd=100,
                anomaly_detection_enabled=True,
            )

        self.assertEqual(set(resources), {"anomaly_monitor", "anomaly_subscription", "budget"})
        subscription = next(call for call in calls if call[0] == "subscription")
        self.assertEqual(subscription[2]["monitor_arn_lists"], ["monitor-arn"])
        budget = next(call for call in calls if call[0] == "budget")
        self.assertEqual(budget[2]["limit_amount"], "100")
        self.assertEqual(budget[2]["notifications"][0].threshold, 80)

    def test_step_function_definition_serializes(self) -> None:
        definition = resilience._state_machine_definition("cluster", "task-def", ["subnet-a"], "sg-a")
        self.assertIn("RunOrchestratorTask", json.dumps(definition))
