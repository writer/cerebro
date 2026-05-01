import unittest
from unittest.mock import patch

import cerebro_sdk.jira as jira
from cerebro_sdk.client import Client
from cerebro_sdk.jira import build_jira_workspace_claims


class JiraPostureTests(unittest.TestCase):
    def setUp(self) -> None:
        client = Client(base_url="https://cerebro.example.com")
        self.integration = client.integration(runtime_id="writer-jira", tenant_id="writer", integration="jira")

    def test_build_jira_workspace_claims_rejects_object_coerced_identifiers(self) -> None:
        with self.assertRaisesRegex(ValueError, "workspace_key is required"):
            build_jira_workspace_claims(self.integration, {"workspace_key": {"id": "writer"}})

        with self.assertRaisesRegex(ValueError, "workspace_key is required"):
            build_jira_workspace_claims(self.integration, {"workspace_key": ["writer"]})

        with self.assertRaisesRegex(ValueError, r"projects\[\]\.key is required"):
            build_jira_workspace_claims(
                self.integration,
                {
                    "workspace_key": "writer",
                    "projects": [{"key": {"id": "ENG"}}],
                },
            )

        with self.assertRaisesRegex(ValueError, r"apps\[\]\.key is required"):
            build_jira_workspace_claims(
                self.integration,
                {
                    "workspace_key": "writer",
                    "apps": [{"key": ["slack"]}],
                },
            )

    def test_build_jira_workspace_claims_rejects_boolean_identifiers(self) -> None:
        with self.assertRaisesRegex(ValueError, "workspace_key is required"):
            build_jira_workspace_claims(self.integration, {"workspace_key": True})

    def test_build_jira_workspace_claims_rejects_malformed_array_entries(self) -> None:
        with self.assertRaisesRegex(ValueError, r"admins\[0\] must be an object"):
            build_jira_workspace_claims(self.integration, {"workspace_key": "writer", "admins": ["alice@writer.com"]})

        with self.assertRaisesRegex(ValueError, r"projects\[1\] must be an object"):
            build_jira_workspace_claims(
                self.integration,
                {"workspace_key": "writer", "projects": [{"key": "ENG"}, "SEC"]},
            )

    def test_build_jira_workspace_claims_rejects_unknown_boolean_strings(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid boolean string"):
            build_jira_workspace_claims(
                self.integration,
                {"workspace_key": "writer", "public_signup_enabled": "falsee"},
            )

    def test_build_jira_workspace_claims_rejects_non_boolean_flag_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid boolean value"):
            build_jira_workspace_claims(
                self.integration,
                {"workspace_key": "writer", "public_signup_enabled": {"bad": 1}},
            )

    def test_onboard_jira_workspace_posture_validates_before_runtime_upsert(self) -> None:
        class FakeIntegration:
            ensure_calls = 0

            def ref(self, kind, key, label=None):
                return {"urn": f"urn:cerebro:writer:jira:{kind}:{key}", "label": label or key}

            def ensure_runtime(self, config=None):
                self.ensure_calls += 1

        fake_integration = FakeIntegration()

        class FakeClient:
            def __init__(self, base_url, api_key=None):
                pass

            def integration(self, runtime_id, tenant_id, integration):
                return fake_integration

        with patch.object(jira, "Client", FakeClient):
            with self.assertRaisesRegex(ValueError, r"projects\[0\] must be an object"):
                jira.onboard_jira_workspace_posture(
                    "https://cerebro.example.com",
                    "writer",
                    "writer-jira",
                    {"workspace_key": "writer", "projects": ["SEC"]},
                )

        self.assertEqual(fake_integration.ensure_calls, 0)

    def test_build_jira_posture_findings_uses_posture_admin_count(self) -> None:
        findings = jira.build_jira_posture_findings(
            self.integration,
            {
                "workspace_key": "writer",
                "admins": [
                    {"email": "admin1@writer.com"},
                    {"email": "admin2@writer.com"},
                    {"email": "admin3@writer.com"},
                    {"email": "admin4@writer.com"},
                    {"email": "admin5@writer.com"},
                    {"email": "admin6@writer.com"},
                ],
            },
            {"relation_counts_by_type": {}},
        )

        self.assertTrue(any(finding["id"] == "jira_workspace_admin_sprawl" for finding in findings))

    def test_build_jira_posture_findings_ignores_admins_without_email_for_sprawl(self) -> None:
        findings = jira.build_jira_posture_findings(
            self.integration,
            {"workspace_key": "writer", "admins": [{}, {}, {}, {}, {}, {}]},
            {"relation_counts_by_type": {}},
        )

        self.assertFalse(any(finding["id"] == "jira_workspace_admin_sprawl" for finding in findings))


if __name__ == "__main__":
    unittest.main()
