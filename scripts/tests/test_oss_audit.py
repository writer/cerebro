import tempfile
import unittest
from pathlib import Path

import scripts.oss_audit as oss_audit


class OSSAuditTests(unittest.TestCase):
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
