import copy
import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import scripts.agent_onboard as onboard


def valid_plan():
    return {
        "version": "2026-06-28",
        "name": "test-onboarding",
        "tenant_id": "local",
        "runtime_profile": "graph-enabled",
        "base_url": "http://127.0.0.1:8080",
        "api_key_env": "CEREBRO_API_KEY",
        "environment": {
            "CEREBRO_API_KEYS": "env:CEREBRO_API_KEYS",
            "CEREBRO_POSTGRES_DSN": "env:CEREBRO_POSTGRES_DSN",
            "CEREBRO_JETSTREAM_URL": "env:CEREBRO_JETSTREAM_URL",
            "CEREBRO_NEO4J_URI": "env:CEREBRO_NEO4J_URI",
            "CEREBRO_NEO4J_USERNAME": "neo4j",
            "CEREBRO_NEO4J_PASSWORD": "env:CEREBRO_NEO4J_PASSWORD",
        },
        "source_runtimes": [
            {
                "id": "local-sdk-demo",
                "source_id": "sdk",
                "tenant_id": "local",
                "config": {
                    "integration": "demo",
                    "inventory_urns": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api",
                },
                "preview": {"check": True, "discover": True},
                "sync": {"enabled": True, "page_limit": 1},
                "graph_ingest": {"enabled": True, "page_limit": 1},
                "claims": [
                    {
                        "subject_urn": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api",
                        "predicate": "owner",
                        "object_value": "platform",
                        "claim_type": "attribute",
                        "source_event_id": "claim-1",
                    }
                ],
            }
        ],
        "compliance": {"enabled": True, "profiles": ["soc2-security-core"]},
    }


class AgentOnboardTests(unittest.TestCase):
    def env(self):
        return {
            "CEREBRO_API_KEY": "local-dev-key",
            "CEREBRO_API_KEYS": "local-dev-key:local:local",
            "CEREBRO_POSTGRES_DSN": "postgres://cerebro:cerebro@127.0.0.1:5432/cerebro?sslmode=disable",
            "CEREBRO_JETSTREAM_URL": "nats://127.0.0.1:4222",
            "CEREBRO_NEO4J_URI": "bolt://127.0.0.1:7687",
            "CEREBRO_NEO4J_PASSWORD": "local-password",
            "GITHUB_OWNER": "writer",
            "GITHUB_TOKEN": "ghp_test",
        }

    def test_validate_plan_rejects_literal_runtime_secret(self):
        plan = valid_plan()
        plan["source_runtimes"][0]["config"]["api_key"] = "literal"
        with self.assertRaisesRegex(onboard.OnboardingError, "api_key"):
            onboard.validate_plan(plan)

    def test_validate_plan_rejects_literal_environment_secret(self):
        plan = valid_plan()
        plan["environment"]["CEREBRO_POSTGRES_DSN"] = "postgres://user:pass@host/db"
        with self.assertRaisesRegex(onboard.OnboardingError, "CEREBRO_POSTGRES_DSN"):
            onboard.validate_plan(plan)

    def test_redact_url_masks_credentials(self):
        self.assertEqual(
            onboard.redact_url("postgres://user:pass@db.example/cerebro?sslmode=require"),
            "postgres://redacted@db.example/cerebro?sslmode=require",
        )

    def test_validate_base_url_rejects_credentials_and_paths(self):
        for value in [
            "https://user:pass@cerebro.example.com",
            "https://cerebro.example.com/app",
            "file:///tmp/cerebro",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(onboard.OnboardingError):
                    onboard.validate_base_url(value)

    def test_redact_message_masks_secret_assignments(self):
        self.assertEqual(
            onboard.redact_message("failed password=local-password token=abc123"),
            "failed password=redacted token=redacted",
        )

    def test_resolved_config_values_resolves_env_refs(self):
        with unittest.mock.patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test"}, clear=True):
            self.assertEqual(
                onboard.resolved_config_values({"owner": "writer", "token": "env:GITHUB_TOKEN"}),
                {"owner": "writer", "token": "ghp_test"},
            )

    def test_runner_writes_passed_receipt(self):
        plan = valid_plan()
        plan["source_runtimes"][0]["config"]["owner"] = "env:GITHUB_OWNER"
        plan["source_runtimes"][0]["config"]["token"] = "env:GITHUB_TOKEN"
        requested = []

        def fake_cmd(argv, env, cwd, timeout):
            self.assertEqual(argv, ["./bin/cerebro", "deploy", "preflight", "--format", "json"])
            self.assertIn("CEREBRO_POSTGRES_DSN", env)
            return onboard.CommandResult(
                0,
                json.dumps(
                    {
                        "status": "pass",
                        "runtime_profile": "graph-enabled",
                        "enabled_capabilities": ["api_auth", "postgres", "jetstream", "neo4j"],
                        "required_backing_services": [{"name": "postgres", "required_for": "state"}],
                        "required_secret_names": ["CEREBRO_API_KEYS", "CEREBRO_POSTGRES_DSN"],
                        "operator_actions": ["Add runtime schedules outside the API service."],
                    }
                ),
                "",
            )

        def fake_http(method, url, headers, body, timeout):
            requested.append((method, url, headers, body))
            parsed = url.split("http://127.0.0.1:8080", 1)[1]
            self.assertNotIn("local-dev-key", json.dumps(body.decode("utf-8") if body else ""))
            if parsed == "/health":
                return 200, json.dumps({"status": "ok"})
            if parsed == "/sources":
                self.assertEqual(headers["Authorization"], "Bearer local-dev-key")
                return 200, json.dumps({"sources": [{"id": "sdk"}]})
            if parsed.startswith("/sources/sdk/check"):
                source_config = json.loads(headers["X-Cerebro-Source-Config"])
                self.assertEqual(source_config["inventory_urns"], "urn:cerebro:local:runtime:local-sdk-demo:service:example-api")
                self.assertEqual(source_config["owner"], "writer")
                self.assertEqual(source_config["token"], "ghp_test")
                return 200, json.dumps({"status": "ok"})
            if parsed.startswith("/sources/sdk/discover"):
                source_config = json.loads(headers["X-Cerebro-Source-Config"])
                self.assertEqual(source_config["integration"], "demo")
                self.assertEqual(source_config["owner"], "writer")
                self.assertEqual(source_config["token"], "ghp_test")
                return 200, json.dumps({"items": [{"urn": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api"}]})
            if parsed == "/source-runtimes/local-sdk-demo" and method == "PUT":
                payload = json.loads(body.decode("utf-8"))
                self.assertEqual(payload["runtime"]["id"], "local-sdk-demo")
                self.assertEqual(payload["runtime"]["config"]["owner"], "writer")
                self.assertEqual(payload["runtime"]["config"]["token"], "ghp_test")
                self.assertNotIn("env:GITHUB", json.dumps(payload))
                return 200, json.dumps({"runtime": payload["runtime"]})
            if parsed == "/source-runtimes/local-sdk-demo/claims" and method == "POST":
                return 200, json.dumps({"claims": [{}]})
            if parsed == "/source-runtimes/local-sdk-demo/claims?limit=20":
                return 200, json.dumps({"claims": [{}]})
            if parsed == "/source-runtimes/local-sdk-demo/sync?page_limit=1":
                return 200, json.dumps({"id": "local-sdk-demo", "status": "synced"})
            if parsed == "/source-runtimes/health?tenant_id=local&limit=20":
                return 200, json.dumps({"runtimes": [{"id": "local-sdk-demo"}]})
            if parsed == "/source-runtimes/local-sdk-demo/graph-ingest-runs?page_limit=1":
                return 200, json.dumps({"id": "graph-run-1"})
            if parsed == "/grc/control-coverage?profile=soc2-security-core":
                return 200, json.dumps({"selected_control_count": 5, "mapped_rule_count": 4})
            return 404, json.dumps({"error": parsed})

        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(os.environ, self.env(), clear=True):
            receipt_path = Path(tmp) / "receipt.json"
            receipt = onboard.AgentOnboardRunner(plan, receipt_path, cmd=fake_cmd, http=fake_http).run()
            self.assertEqual(receipt["status"], "passed")
            self.assertTrue(receipt_path.exists())
            saved = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "passed")
            self.assertIn("CEREBRO_POSTGRES_DSN", saved["required_env"])
            preflight = next(check for check in saved["checks"] if check["name"] == "deploy preflight")
            self.assertIn("CEREBRO_POSTGRES_DSN", preflight["required_secret_names"])
            self.assertEqual(saved["source_runtimes"][0]["id"], "local-sdk-demo")
            self.assertTrue(any(check["name"] == "compliance coverage" for check in saved["checks"]))
            self.assertGreaterEqual(len(requested), 9)

    def test_runner_records_failed_receipt(self):
        plan = copy.deepcopy(valid_plan())
        plan["compliance"]["enabled"] = False

        def fake_cmd(argv, env, cwd, timeout):
            return onboard.CommandResult(0, json.dumps({"status": "pass"}), "")

        def fake_http(method, url, headers, body, timeout):
            if url.endswith("/health"):
                return 503, json.dumps({"status": "down"})
            return 200, "{}"

        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(os.environ, self.env(), clear=True):
            receipt_path = Path(tmp) / "receipt.json"
            with self.assertRaises(onboard.OnboardingError):
                onboard.AgentOnboardRunner(plan, receipt_path, cmd=fake_cmd, http=fake_http).run()
            saved = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "failed")
            self.assertTrue(saved["next_actions"])


if __name__ == "__main__":
    unittest.main()
