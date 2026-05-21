from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.detect_public_endpoint_refresh import (
    _has_public_endpoint_runtime,
    _should_refresh_public_endpoint_runtimes,
)


class DetectPublicEndpointRefreshTest(unittest.TestCase):
    def test_has_public_endpoint_runtime(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint"}},
                {"id": "cosmo-session", "sourceId": "cosmo", "config": {"family": "session"}},
            ]
        }

        self.assertTrue(_has_public_endpoint_runtime(config))

    def test_should_refresh_only_for_pre_attack_path_upgrade(self) -> None:
        config = {
            "imageTag": "v2.1.50",
            "sourceRuntimes": [{"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint"}}],
        }

        self.assertTrue(_should_refresh_public_endpoint_runtimes(config, "v2.1.45"))
        self.assertFalse(_should_refresh_public_endpoint_runtimes(config, "v2.1.46"))
        self.assertFalse(_should_refresh_public_endpoint_runtimes({**config, "imageTag": "v2.1.45"}, "v2.1.44"))

    def test_should_refresh_requires_public_endpoint_runtime(self) -> None:
        config = {
            "imageTag": "v2.1.50",
            "sourceRuntimes": [{"id": "aws-iam", "sourceId": "aws", "config": {"family": "iam_user"}}],
        }

        self.assertFalse(_should_refresh_public_endpoint_runtimes(config, "v2.1.45"))


if __name__ == "__main__":
    unittest.main()
