from __future__ import annotations

import ast
import os
import re
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.validate_stack_config as validator


LEGACY_CLAIMS_PATTERNS = (
    re.compile(r"claims[-_]ndjson", re.IGNORECASE),
    re.compile(r"legacy_claims_ndjson", re.IGNORECASE),
)


class PanopticonCrossRepoContractTest(unittest.TestCase):
    def _repo(self, env_name: str, default: str) -> Path:
        repo = Path(os.environ.get(env_name, default))
        if not repo.exists():
            self.skipTest(f"{env_name} repo is not available at {repo}")
        return repo

    def _panopticon_repo(self) -> Path:
        return self._repo("PANOPTICON_REPO", "/Users/jonathan/panopticon")

    def _writer_cerebro_repo(self) -> Path:
        return self._repo("WRITER_CEREBRO_REPO", "/Users/jonathan/writer-cerebro-panopticon")

    def _ops_repo(self) -> Path:
        return Path(__file__).resolve().parents[2]

    def test_ops_config_uses_panopticon_api_mode(self) -> None:
        for ops_stack in ("Pulumi.sec-dev.yaml", "Pulumi.go-prod.yaml"):
            with self.subTest(stack=ops_stack):
                ops_config = self._pulumi_config(self._ops_repo() / "infra" / "aws" / ops_stack, "cerebro:")
                panopticon_s3 = [source for source in ops_config["s3Sources"] if source.get("name") == "panopticon"]
                self.assertEqual(panopticon_s3, [])

                runtimes = {runtime["id"]: runtime for runtime in ops_config["sourceRuntimes"]}
                for runtime_id, family in validator.PANOPTICON_RUNTIME_FAMILIES.items():
                    runtime_config = runtimes[runtime_id]["config"]
                    self.assertEqual(runtime_config["mode"], "api")
                    self.assertEqual(runtime_config["family"], family)
                    self.assertEqual(runtime_config["base_url"], "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL")
                    self.assertEqual(runtime_config["private_endpoint_allowlist"], "env:CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST")
                    self.assertEqual(runtime_config["runtime_id"], runtime_id)
                    self.assertEqual(runtime_config["tenant_id"], "writer")
                    self.assertEqual(runtime_config["token"], "env:CEREBRO_SOURCE_PANOPTICON_TOKEN")

    def test_unsupported_claims_ndjson_paths_are_absent_across_repos(self) -> None:
        repos = {
            "panopticon": self._panopticon_repo(),
            "writer-cerebro": self._writer_cerebro_repo(),
            "ops-cerebro": self._ops_repo(),
        }
        active_hits: list[str] = []
        historical_hits: list[str] = []
        for name, repo in repos.items():
            for path in self._iter_scannable_files(repo):
                text = path.read_text(encoding="utf-8", errors="ignore")
                if not any(pattern.search(text) for pattern in LEGACY_CLAIMS_PATTERNS):
                    continue
                relative = path.relative_to(repo)
                hit = f"{name}:{relative}"
                if self._is_active_runtime_path(relative):
                    active_hits.append(hit)
                else:
                    historical_hits.append(hit)

        self.assertEqual(active_hits, [])
        self.assertTrue(
            all(self._is_historical_reference_path(Path(hit.split(":", 1)[1])) for hit in historical_hits),
            f"unexpected non-active legacy claims-NDJSON references: {historical_hits}",
        )

    def _python_constants(self, path: Path, names: set[str]) -> dict[str, object]:
        module = ast.parse(path.read_text(encoding="utf-8"))
        constants: dict[str, object] = {}
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in names:
                        constants[target.id] = self._literal_constant(node.value, constants)
        missing = names - constants.keys()
        if missing:
            raise AssertionError(f"{path} missing constants {sorted(missing)}")
        return constants

    def _literal_constant(self, node: ast.AST, constants: dict[str, object]) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Dict):
            return {
                self._literal_constant(key, constants): self._literal_constant(value, constants)
                for key, value in zip(node.keys, node.values)
            }
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                    parts.append(str(constants[value.value.id]))
                else:
                    raise AssertionError(f"unsupported formatted constant in {ast.dump(node)}")
            return "".join(parts)
        return ast.literal_eval(node)

    def _pulumi_config(self, path: Path, prefix: str) -> dict:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return {
            key.removeprefix(prefix): value
            for key, value in raw.get("config", {}).items()
            if isinstance(key, str) and key.startswith(prefix)
        }

    def _account_id_from_admin_role(self, arn: str) -> str:
        match = re.match(r"^arn:aws:iam::([0-9]{12}):role/", arn)
        if not match:
            raise AssertionError(f"cannot derive account id from {arn!r}")
        return match.group(1)

    def _iter_scannable_files(self, repo: Path):
        ignored_dirs = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", "vendor"}
        allowed_suffixes = {".go", ".py", ".yaml", ".yml", ".json", ".md", ".toml", ".sh"}
        for path in repo.rglob("*"):
            if not path.is_file() or path.suffix not in allowed_suffixes:
                continue
            if any(part in ignored_dirs for part in path.relative_to(repo).parts):
                continue
            yield path

    def _is_active_runtime_path(self, relative: Path) -> bool:
        parts = set(relative.parts)
        if self._is_historical_reference_path(relative):
            return False
        return bool(parts & {"source", "sources", "internal", "cmd", "api", "sdk", "scripts", "infra", ".github", "deploy"})

    def _is_historical_reference_path(self, relative: Path) -> bool:
        parts = set(relative.parts)
        return (
            relative.name == "README.md"
            or bool(parts & {"tests", "docs", ".factory"})
            or relative.name.endswith("_test.go")
            or relative.name.startswith("test_")
        )


if __name__ == "__main__":
    unittest.main()
