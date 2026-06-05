from __future__ import annotations

import unittest

from scripts import aws_sdk_coverage


class AWSSDKCoverageTests(unittest.TestCase):
    def test_parse_go_list_json_reads_concatenated_objects(self) -> None:
        modules = aws_sdk_coverage.parse_go_list_json('{"Path":"a"}\n{"Path":"b"}\n')
        self.assertEqual([module["Path"] for module in modules], ["a", "b"])

    def test_build_dump_covers_explicit_generic_and_non_inventory_services(self) -> None:
        dump = aws_sdk_coverage.build_dump(
            [
                {"Path": "github.com/aws/aws-sdk-go-v2/service/s3", "Version": "v1"},
                {"Path": "github.com/aws/aws-sdk-go-v2/service/dynamodb", "Version": "v1"},
                {"Path": "github.com/aws/aws-sdk-go-v2/service/sts", "Version": "v1"},
                {"Path": "github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding", "Version": "v1"},
            ]
        )
        rows = {row["service"]: row for row in dump["services"]}
        self.assertEqual(rows["s3"]["coverage_status"], "explicit")
        self.assertEqual(rows["dynamodb"]["coverage_status"], "generic_asset_metadata")
        self.assertEqual(rows["sts"]["coverage_status"], "non_inventory")
        self.assertNotIn("internal", rows)
        self.assertEqual(dump["uncovered_services"], [])


if __name__ == "__main__":
    unittest.main()
