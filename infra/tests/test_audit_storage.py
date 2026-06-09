from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("audit_storage", Path(__file__).resolve().parents[1] / "aws" / "audit_storage.py")
audit_storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_storage)


class FakeOutput:
    def __init__(self, value):
        self.value = value

    def apply(self, callback):
        return callback(self.value)


class FakeOutputAll:
    def __init__(self, values: tuple):
        self.values = tuple(value.value if isinstance(value, FakeOutput) else value for value in values)

    def apply(self, callback):
        return callback(self.values)


class AuditStoragePolicyTest(unittest.TestCase):
    def test_audit_bucket_policy_keeps_closeout_write_and_allows_access_archive_reads(self) -> None:
        role_policies: list[dict] = []

        def fake_bucket(*args, **kwargs):
            return SimpleNamespace(
                id=kwargs["bucket"],
                bucket=kwargs["bucket"],
                arn=FakeOutput(f"arn:aws:s3:::{kwargs['bucket']}"),
            )

        def fake_resource(*args, **kwargs):
            return SimpleNamespace(name=args[0], **kwargs)

        def fake_role_policy(*args, **kwargs):
            role_policies.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs["name"])

        with (
            patch.object(audit_storage.aws.s3, "Bucket", side_effect=fake_bucket),
            patch.object(audit_storage.aws.s3, "BucketPublicAccessBlock", side_effect=fake_resource),
            patch.object(audit_storage.aws.s3, "BucketServerSideEncryptionConfiguration", side_effect=fake_resource),
            patch.object(
                audit_storage.aws.s3,
                "BucketServerSideEncryptionConfigurationRuleArgs",
                side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
            ),
            patch.object(
                audit_storage.aws.s3,
                "BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs",
                side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
            ),
            patch.object(audit_storage.aws.iam, "RolePolicy", side_effect=fake_role_policy),
            patch.object(audit_storage.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            audit_storage.create_audit_bucket(
                name="cerebro-sec-dev",
                bucket_name="cerebro-sec-dev-audit",
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/abc",
                task_role=SimpleNamespace(name="cerebro-sec-dev-task-role"),
            )

        policy = json.loads(role_policies[0]["policy"])
        statements_by_sid = {statement["Sid"]: statement for statement in policy["Statement"]}

        self.assertEqual(
            statements_by_sid["PutCloseoutAudit"]["Resource"],
            "arn:aws:s3:::cerebro-sec-dev-audit/closeout/*",
        )
        self.assertEqual(
            statements_by_sid["ReadAccessAuditArchives"]["Resource"],
            "arn:aws:s3:::cerebro-sec-dev-audit/access/*",
        )
        self.assertEqual(
            statements_by_sid["ListAccessAuditArchives"]["Condition"]["StringLike"]["s3:prefix"],
            ["access/", "access/*"],
        )
        self.assertIn("kms:Decrypt", statements_by_sid["DecryptAccessAuditArchivesWithKms"]["Action"])


if __name__ == "__main__":
    unittest.main()
