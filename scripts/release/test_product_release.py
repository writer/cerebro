from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from scripts.release.product_release import ManifestError, build_manifest, validate_manifest


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


class ProductReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        for name in ("slack.tgz", "sdk.tgz", "contracts/openapi.yaml", "contracts/lifecycle.json"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            channel="candidate",
            version=f"candidate-{COMMIT}",
            commit=COMMIT,
            runtime_image=f"ghcr.io/writer/cerebro:candidate-{COMMIT}",
            runtime_digest=DIGEST,
            web_image=f"ghcr.io/writer/cerebro-web:candidate-{COMMIT}",
            web_digest=DIGEST,
            slack_archive=self.root / "slack.tgz",
            slack_version="0.1.0",
            sdk_archive=self.root / "sdk.tgz",
            sdk_version="0.1.0",
            openapi=self.root / "contracts/openapi.yaml",
            lifecycle_schema=self.root / "contracts/lifecycle.json",
            bundle_root=self.root,
        )

    def test_build_is_deterministic_and_validates_bundle_digests(self) -> None:
        manifest = build_manifest(self.args())
        validate_manifest(manifest, self.root)
        first = json.dumps(manifest, indent=2, sort_keys=True)
        second = json.dumps(build_manifest(self.args()), indent=2, sort_keys=True)
        self.assertEqual(first, second)

    def test_rejects_archive_digest_mismatch(self) -> None:
        manifest = build_manifest(self.args())
        (self.root / "slack.tgz").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "artifact digest does not match"):
            validate_manifest(manifest, self.root)

    def test_rejects_candidate_version_for_another_commit(self) -> None:
        manifest = build_manifest(self.args())
        manifest["version"] = "candidate-" + "c" * 40
        with self.assertRaisesRegex(ManifestError, "candidate version"):
            validate_manifest(manifest)

    def test_rejects_bundle_path_traversal(self) -> None:
        manifest = build_manifest(self.args())
        manifest["contracts"]["openapi"]["file"] = "../openapi.yaml"
        with self.assertRaisesRegex(ManifestError, "inside the bundle"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
