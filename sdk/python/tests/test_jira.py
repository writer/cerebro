import unittest

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


if __name__ == "__main__":
    unittest.main()
