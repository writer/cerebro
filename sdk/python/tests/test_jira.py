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


if __name__ == "__main__":
    unittest.main()
