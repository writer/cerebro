from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.import_existing_query_cache as importer


STACK = """\
config:
  aws:region: us-east-1
  cerebro:environment: sec-dev
  cerebro:cacheEnabled: true
"""


class ImportExistingQueryCacheTests(unittest.TestCase):
    def _stack_file(self, body: str = STACK) -> Path:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        stack = root / "Pulumi.sec-dev.yaml"
        stack.write_text(body, encoding="utf-8")
        return stack

    def test_skips_when_cache_disabled(self) -> None:
        stack = self._stack_file("config:\n  cerebro:environment: sec-dev\n  cerebro:cacheEnabled: false\n")
        with patch.object(importer, "_run") as run:
            self.assertEqual(importer.import_existing_query_cache(stack, "us-east-1"), "cache_disabled")
        run.assert_not_called()

    def test_skips_when_cache_already_in_state(self) -> None:
        stack = self._stack_file()

        def fake_run(command: list[str], **kwargs):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="urn:pulumi:sec-dev::cerebro::aws:elasticache/serverlessCache:ServerlessCache::cerebro-sec-dev-query-cache\n",
                stderr="",
            )

        with patch.object(importer, "_run", side_effect=fake_run):
            self.assertEqual(importer.import_existing_query_cache(stack, "us-east-1"), "already_managed")

    def test_imports_existing_cache_missing_from_state(self) -> None:
        stack = self._stack_file()
        calls: list[list[str]] = []

        def fake_run(command: list[str], **kwargs):
            calls.append(command)
            if command[:2] == ["pulumi", "stack"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            if command[:3] == ["aws", "elasticache", "describe-serverless-caches"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps({"ServerlessCaches": [{"ServerlessCacheName": "cerebro-sec-dev-query-cache"}]}),
                    stderr="",
                )
            if command[:2] == ["pulumi", "import"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            raise AssertionError(f"unexpected command: {command}")

        with patch.object(importer, "_run", side_effect=fake_run):
            self.assertEqual(importer.import_existing_query_cache(stack, "us-east-1"), "imported")
        self.assertIn(
            [
                "pulumi",
                "import",
                "--yes",
                "--stack",
                "sec-dev",
                "aws:elasticache/serverlessCache:ServerlessCache",
                "cerebro-sec-dev-query-cache",
                "cerebro-sec-dev-query-cache",
            ],
            calls,
        )

    def test_skips_when_cache_absent(self) -> None:
        stack = self._stack_file()

        def fake_run(command: list[str], **kwargs):
            if command[:2] == ["pulumi", "stack"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(command, 255, stdout="", stderr="ServerlessCacheNotFoundFault")

        with patch.object(importer, "_run", side_effect=fake_run):
            self.assertEqual(importer.import_existing_query_cache(stack, "us-east-1"), "absent")


if __name__ == "__main__":
    unittest.main()
