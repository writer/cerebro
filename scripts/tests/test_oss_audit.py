import tempfile
import unittest
from pathlib import Path

import scripts.oss_audit as oss_audit


class OSSAuditTests(unittest.TestCase):
    def test_fixture_host_allows_exact_public_provider_origins(self):
        for host in (
            "api.datadoghq.com",
            "docs.datadoghq.com",
            "fivetran.com",
            "nvd.nist.gov",
            "ok11static.oktacdn.com",
            "ok12static.oktacdn.com",
        ):
            with self.subTest(host=host):
                self.assertTrue(oss_audit.fixture_host_allowed(host))
                self.assertFalse(oss_audit.fixture_host_allowed("tenant." + host))

    def test_fixture_url_scan_ignores_markdown_closing_punctuation(self):
        findings = oss_audit.check_fixture_value(
            "sources/docker_hub/testdata/read_repositories.json",
            "$.description",
            "[Release notes](https://ubuntu.com)",
        )

        self.assertEqual(findings, [])

    def test_fixture_url_scan_still_rejects_sensitive_query_keys(self):
        findings = oss_audit.check_fixture_value(
            "sources/fivetran/testdata/read_public_connector_types.json",
            "$.link",
            "https://fivetran.com/docs?token=secret",
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive query key", findings[0])

    def test_fixture_email_scan_recognizes_public_provider_ssh_urls(self):
        allowed = oss_audit.check_fixture_value(
            "sources/github/testdata/api/repository/repository/response.json",
            "$.ssh_url",
            "git@github.com:writer/cerebro.git",
        )
        rejected = oss_audit.check_fixture_value(
            "sources/example/testdata/read_repositories.json",
            "$.ssh_url",
            "git@tenant.invalid:organization/repository.git",
        )

        self.assertEqual(allowed, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("non-synthetic fixture email domain", rejected[0])

    def test_file_scan_skips_cargo_target_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target" / "debug"
            target.mkdir(parents=True)
            (target / "generated.txt").write_text("private build output\n", encoding="utf-8")

            self.assertEqual(list(oss_audit.iter_files(root)), [])

    def test_public_doc_infrastructure_markers_reject_private_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs" / "operations"
            docs.mkdir(parents=True)
            (docs / "hosting.md").write_text(
                "Deploy to sec-dev in account 123456789012.\n",
                encoding="utf-8",
            )

            findings = oss_audit.scan_public_doc_infrastructure_markers(root)

        self.assertEqual(len(findings), 2)
        self.assertTrue(any("deployment marker" in finding for finding in findings))
        self.assertTrue(any("account id" in finding for finding in findings))

    def test_public_doc_infrastructure_markers_allow_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs" / "operations"
            docs.mkdir(parents=True)
            (docs / "cloud-deployment.md").write_text(
                "Use arn:aws:secretsmanager:us-east-1:111122223333:secret:cerebro/postgres.\n",
                encoding="utf-8",
            )

            findings = oss_audit.scan_public_doc_infrastructure_markers(root)

        self.assertEqual(findings, [])

    def test_public_doc_infrastructure_markers_deduplicate_overlapping_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs" / "operations"
            docs.mkdir(parents=True)
            (docs / "hosting.md").write_text(
                "Do not publish cerebro-sec-dev here.\n",
                encoding="utf-8",
            )

            findings = oss_audit.scan_public_doc_infrastructure_markers(root)

        self.assertEqual(len(findings), 1)
        self.assertIn("deployment marker", findings[0])

    def test_public_doc_infrastructure_markers_scan_pulumi_stacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pulumi = root / "deploy" / "pulumi"
            pulumi.mkdir(parents=True)
            (pulumi / "Pulumi.aws.yaml").write_text(
                "config:\n  account: 123456789012\n",
                encoding="utf-8",
            )

            findings = oss_audit.scan_public_doc_infrastructure_markers(root)

        self.assertEqual(len(findings), 1)
        self.assertIn("account id", findings[0])

    def test_public_doc_infrastructure_markers_ignore_code_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "internal" / "example"
            fixture.mkdir(parents=True)
            (fixture / "example_test.go").write_text(
                'package example\nconst fixture = "sec-dev"\n',
                encoding="utf-8",
            )

            findings = oss_audit.scan_public_doc_infrastructure_markers(root)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
