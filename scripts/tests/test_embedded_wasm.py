import os
import stat
import tempfile
import tomllib
import unittest
import unittest.mock
from pathlib import Path

import scripts.embedded_wasm as embedded_wasm


ROOT = Path(__file__).resolve().parents[2]


class EmbeddedWasmTests(unittest.TestCase):
    def test_registry_names_packages_artifacts_and_targets_are_unique(self):
        attributes = (
            "name",
            "package",
            "build_artifact",
            "embedded_artifact",
            "generate_target",
            "check_target",
        )
        for attribute in attributes:
            with self.subTest(attribute=attribute):
                values = [getattr(module, attribute) for module in embedded_wasm.EMBEDDED_WASM_MODULES]
                self.assertEqual(len(values), len(set(values)))

    def test_registered_sources_and_artifacts_exist(self):
        for module in embedded_wasm.EMBEDDED_WASM_MODULES:
            with self.subTest(module=module.name):
                self.assertTrue((ROOT / module.embedded_artifact).is_file())
                cargo_toml = ROOT / module.changed_prefixes[0] / "Cargo.toml"
                self.assertTrue(cargo_toml.is_file())
                self.assertIn(f'name = "{module.package}"', cargo_toml.read_text(encoding="utf-8"))

    def test_registry_covers_every_workspace_cdylib(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        cdylib_packages = set()
        for member in workspace["workspace"]["members"]:
            cargo_toml = ROOT / member / "Cargo.toml"
            package = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
            if "cdylib" in package.get("lib", {}).get("crate-type", []):
                cdylib_packages.add(package["package"]["name"])

        registered = {module.package for module in embedded_wasm.EMBEDDED_WASM_MODULES}
        self.assertEqual(registered, cdylib_packages)

    def test_generate_builds_and_installs_each_registered_artifact(self):
        for module in embedded_wasm.EMBEDDED_WASM_MODULES:
            with self.subTest(module=module.name), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                built = module.build_path(repo)
                built.parent.mkdir(parents=True)
                built.write_bytes(module.name.encode("utf-8"))
                destination = module.embedded_path(repo)
                destination.parent.mkdir(parents=True)

                with unittest.mock.patch.object(embedded_wasm.subprocess, "run") as run:
                    embedded_wasm.generate_module(
                        module,
                        repo,
                        current_platform=embedded_wasm.CANONICAL_PLATFORM,
                    )

                self.assertEqual(destination.read_bytes(), built.read_bytes())
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)
                self.assertEqual(run.call_count, 1)
                command = run.call_args.args[0]
                self.assertEqual(command[-2:], ["-p", module.package])
                self.assertIn("build", command)

    def test_generate_preserves_static_validator_cross_platform_policy(self):
        module = embedded_wasm.MODULES_BY_NAME["graphagent-static-validator"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            built = module.build_path(repo)
            built.parent.mkdir(parents=True)
            built.write_bytes(b"module")
            module.embedded_path(repo).parent.mkdir(parents=True)

            with unittest.mock.patch.object(embedded_wasm.subprocess, "run"):
                embedded_wasm.generate_module(module, repo, current_platform="Darwin-arm64")

            self.assertEqual(module.embedded_path(repo).read_bytes(), b"module")

    def test_generate_rejects_noncanonical_platform_for_restricted_modules(self):
        restricted = [
            module for module in embedded_wasm.EMBEDDED_WASM_MODULES if module.canonical_generate_only
        ]
        for module in restricted:
            with self.subTest(module=module.name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(embedded_wasm.EmbeddedWasmError, embedded_wasm.CANONICAL_PLATFORM):
                    embedded_wasm.generate_module(module, Path(tmp), current_platform="Darwin-arm64")

    def test_check_runs_module_clippy_and_release_build(self):
        for module in embedded_wasm.EMBEDDED_WASM_MODULES:
            with self.subTest(module=module.name), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                built = module.build_path(repo)
                built.parent.mkdir(parents=True)
                built.write_bytes(b"module")
                embedded = module.embedded_path(repo)
                embedded.parent.mkdir(parents=True)
                embedded.write_bytes(b"module")

                with unittest.mock.patch.object(embedded_wasm.subprocess, "run") as run:
                    embedded_wasm.check_module(
                        module,
                        repo,
                        current_platform=embedded_wasm.CANONICAL_PLATFORM,
                    )

                self.assertEqual(run.call_count, 2)
                clippy = run.call_args_list[0].args[0]
                build = run.call_args_list[1].args[0]
                self.assertIn("clippy", clippy)
                self.assertEqual(clippy[-4:], [module.package, "--", "-D", "warnings"])
                self.assertIn("build", build)
                self.assertEqual(build[-2:], ["-p", module.package])
                build_env = run.call_args_list[1].kwargs["env"]
                self.assertIn(f"--remap-path-prefix={repo}=/workspace", build_env["RUSTFLAGS"])

    def test_check_defers_restricted_artifact_comparison_off_canonical_platform(self):
        restricted = [
            module for module in embedded_wasm.EMBEDDED_WASM_MODULES if module.canonical_compare_only
        ]
        for module in restricted:
            with self.subTest(module=module.name), tempfile.TemporaryDirectory() as tmp:
                with unittest.mock.patch.object(embedded_wasm, "build_module"):
                    embedded_wasm.check_module(module, Path(tmp), current_platform="Darwin-arm64")

    def test_check_rejects_stale_artifact_where_comparison_is_required(self):
        module = embedded_wasm.MODULES_BY_NAME["graphagent-static-validator"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            built = module.build_path(repo)
            built.parent.mkdir(parents=True)
            built.write_bytes(b"new")
            embedded = module.embedded_path(repo)
            embedded.parent.mkdir(parents=True)
            embedded.write_bytes(b"old")

            with unittest.mock.patch.object(embedded_wasm, "build_module"):
                with self.assertRaisesRegex(embedded_wasm.EmbeddedWasmError, module.generate_target):
                    embedded_wasm.check_module(module, repo, current_platform="Darwin-arm64")

    def test_cargo_command_honors_make_override(self):
        with unittest.mock.patch.dict(os.environ, {"CARGO": "/opt/cargo wrapper"}, clear=False):
            self.assertEqual(embedded_wasm.cargo_command(), ["/opt/cargo", "wrapper"])

    def test_ci_sets_up_rust_and_release_consumes_a_ci_gated_candidate(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "command: make graph-action-check rust-wasm-check\n            setup_rust: true",
            ci,
        )
        self.assertIn("if: matrix.setup_rust == true", ci)
        self.assertNotIn("if: matrix.name == 'graph-actions'", ci)

        candidate = (ROOT / ".github/workflows/cut-release.yml").read_text(encoding="utf-8")
        self.assertIn("- name: Require successful CI for candidate commit", candidate)
        self.assertIn('if [ "${status}" = completed ] && [ "${conclusion}" = success ]; then', candidate)

        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('workflow_path="$(jq -r .path <<< "${run}")"', release)
        self.assertIn(
            'if [ "${workflow_path}" != ".github/workflows/cut-release.yml" ] || [ "${conclusion}" != success ]; then',
            release,
        )


if __name__ == "__main__":
    unittest.main()
