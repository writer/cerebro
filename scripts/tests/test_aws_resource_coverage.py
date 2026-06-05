from __future__ import annotations

import unittest

from scripts import aws_resource_coverage


class AWSResourceCoverageTests(unittest.TestCase):
    def test_taggability_resources_normalizes_mixed_and_untaggable_rows(self) -> None:
        rows = aws_resource_coverage.taggability_resources(
            {
                "mixed_services_detail": [
                    {
                        "name": "Amazon DynamoDB",
                        "taggable": ["table"],
                        "conditionally_taggable": ["backup"],
                        "untaggable": ["stream"],
                    }
                ],
                "untaggable_resources": [
                    {
                        "service": "Amazon DynamoDB",
                        "resource": "export",
                        "reason": "no_tag_api",
                    }
                ],
            }
        )
        by_resource = {row["resource"]: row for row in rows}
        self.assertEqual(by_resource["table"]["service_slug"], "dynamodb")
        self.assertEqual(by_resource["table"]["taggability"], "taggable")
        self.assertEqual(by_resource["backup"]["taggability"], "conditionally_taggable")
        self.assertEqual(by_resource["stream"]["taggability"], "untaggable")
        self.assertEqual(by_resource["export"]["reason"], "no_tag_api")

    def test_validate_dump_catches_small_or_missing_sources(self) -> None:
        failures = aws_resource_coverage.validate_dump(
            {
                "sources": {},
                "aws_api_model_services": ["s3"],
                "aws_sdk_go_v2_model_services": ["s3"],
                "taggability_resources": [],
                "deep_coverage_batches": {},
            }
        )
        self.assertIn("aws_sdk_go_v2_model_services unexpectedly small", failures)
        self.assertIn("taggability_resources unexpectedly small", failures)


if __name__ == "__main__":
    unittest.main()
