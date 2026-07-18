import json
import tempfile
import unittest
from pathlib import Path

from scripts.app_workspace_contract import (
    CANONICAL_REPOSITORY,
    is_app_dockerfile,
    validate_app_workspaces,
)


DIGEST = "a" * 64


class AppWorkspaceContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.write_json(
            "package.json",
            {"name": "monorepo", "workspaces": ["apps/*", "sdk/typescript"]},
        )
        self.write_json(
            "apps/web/package.json",
            {
                "name": "@writer/cerebro-web",
                "private": True,
                "license": "MIT",
                "repository": {
                    "type": "git",
                    "url": CANONICAL_REPOSITORY,
                    "directory": "apps/web",
                },
                "scripts": {"build": "build", "check": "check", "test": "test"},
            },
        )
        self.write_json(
            "package-lock.json",
            {
                "packages": {
                    "": {"workspaces": ["apps/*", "sdk/typescript"]},
                    "apps/web": {"name": "@writer/cerebro-web"},
                }
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, path: str, value: object) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value), encoding="utf-8")

    def manifest(self) -> dict:
        return json.loads((self.repo / "apps/web/package.json").read_text(encoding="utf-8"))

    def messages(self) -> list[str]:
        return [failure.message for failure in validate_app_workspaces(self.repo)]

    def test_accepts_owned_application_workspace(self):
        self.assertEqual(validate_app_workspaces(self.repo), [])

    def test_accepts_digest_pinned_multistage_dockerfile_with_platform_flag(self):
        dockerfile = self.repo / "apps/web/Dockerfile"
        dockerfile.write_text(
            "\n".join(
                (
                    f"FROM --platform=linux/amd64 node:22-alpine@sha256:{DIGEST} AS build",
                    f"FROM node:22-alpine@sha256:{DIGEST} AS runtime",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.assertEqual(validate_app_workspaces(self.repo), [])

    def test_rejects_mutable_or_malformed_base_images(self):
        cases = (
            ("node:22-alpine", "tag only"),
            (f"node:latest@sha256:{DIGEST}", "latest tag"),
            (f"node@sha256:{DIGEST}", "digest without tag"),
            ("${BASE_IMAGE}", "variable"),
            (f"node:22-alpine@sha256:{'A' * 64}", "uppercase digest"),
            (f"node:22-alpine@sha256:{'a' * 63}", "short digest"),
            ("scratch", "scratch"),
        )
        for image, label in cases:
            with self.subTest(label=label):
                dockerfile = self.repo / "apps/web/Dockerfile"
                dockerfile.write_text(f"FROM {image}\n", encoding="utf-8")
                self.assertIn(
                    "base image must use name:tag@sha256 with a 64-character lowercase digest",
                    self.messages(),
                )

    def test_rejects_missing_or_malformed_from_instruction(self):
        dockerfile = self.repo / "apps/web/Dockerfile"
        dockerfile.write_text("RUN echo ready\n", encoding="utf-8")
        self.assertIn(
            "Dockerfile must declare at least one digest-pinned FROM instruction",
            self.messages(),
        )

        dockerfile.write_text(f"FROM --platform linux/amd64 node:22@sha256:{DIGEST}\n", encoding="utf-8")
        self.assertIn("FROM flags must use --name=value syntax", self.messages())

    def test_excludes_dockerfile_ignore_files_from_base_validation(self):
        for name in ("Dockerfile.dockerignore", "Dockerfile.prod.dockerignore", "build.Dockerfile.dockerignore"):
            ignored = self.repo / "apps/web" / name
            ignored.write_text("node_modules\n", encoding="utf-8")
            self.assertFalse(is_app_dockerfile(ignored))
        self.assertEqual(validate_app_workspaces(self.repo), [])

    def test_rejects_non_private_or_publishable_application(self):
        manifest = self.manifest()
        manifest["private"] = False
        manifest["publishConfig"] = {"access": "public"}
        manifest["scripts"]["prepublishOnly"] = "build"
        self.write_json("apps/web/package.json", manifest)

        messages = self.messages()
        self.assertIn("application packages must be private", messages)
        self.assertIn("application packages must not declare publishConfig", messages)
        self.assertIn("application packages must not declare publish scripts", messages)

    def test_rejects_repository_or_directory_drift(self):
        manifest = self.manifest()
        manifest["repository"]["url"] = "https://example.invalid/other.git"
        manifest["repository"]["directory"] = "web"
        self.write_json("apps/web/package.json", manifest)

        messages = self.messages()
        self.assertIn("repository must point to the canonical monorepo", messages)
        self.assertIn("repository.directory must be apps/web", messages)

    def test_rejects_nested_lock_and_missing_root_lock_entry(self):
        (self.repo / "apps/web/package-lock.json").write_text("{}", encoding="utf-8")
        lock = json.loads((self.repo / "package-lock.json").read_text(encoding="utf-8"))
        del lock["packages"]["apps/web"]
        self.write_json("package-lock.json", lock)

        messages = self.messages()
        self.assertIn("use the root workspace lockfile", messages)
        self.assertIn("missing workspace entry for apps/web", messages)

    def test_rejects_missing_owned_scripts(self):
        manifest = self.manifest()
        del manifest["scripts"]["check"]
        self.write_json("apps/web/package.json", manifest)
        self.assertIn("scripts.check must be declared", self.messages())

    def test_rejects_root_lock_workspace_drift(self):
        lock = json.loads((self.repo / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"][""]["workspaces"] = ["apps/*"]
        self.write_json("package-lock.json", lock)
        self.assertIn("root workspace declarations must match package.json", self.messages())


if __name__ == "__main__":
    unittest.main()
