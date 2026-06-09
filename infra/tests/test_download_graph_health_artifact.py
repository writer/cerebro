from __future__ import annotations

from datetime import UTC, datetime
import io
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch


import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import download_graph_health_artifact


class DownloadGraphHealthArtifactTest(unittest.TestCase):
    def test_archive_download_http_error_is_cache_miss(self) -> None:
        artifact = {
            "expired": False,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "archive_download_url": "https://example.invalid/archive.zip",
        }
        error = urllib.error.HTTPError(
            artifact["archive_download_url"],
            410,
            "Gone",
            hdrs={},
            fp=io.BytesIO(b"expired"),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "graph-health.tsv"
            with (
                patch.dict(
                    "os.environ",
                    {"GITHUB_TOKEN": "token", "GITHUB_REPOSITORY": "WriterInternal/cerebro"},
                ),
                patch("scripts.download_graph_health_artifact._request_json", return_value={"artifacts": [artifact]}),
                patch("scripts.download_graph_health_artifact._request_bytes", side_effect=error),
            ):
                status = download_graph_health_artifact.main(
                    [
                        "--artifact-name",
                        "graph-health-sec-dev",
                        "--output",
                        str(output),
                        "--max-age-seconds",
                        "3600",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
