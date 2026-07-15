#!/usr/bin/env python3
"""Build and verify Cerebro's embedded Rust Wasm modules."""

from __future__ import annotations

import argparse
import filecmp
import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


WASM_TARGET = "wasm32-unknown-unknown"
CANONICAL_PLATFORM = "Linux-x86_64"
COMMON_CHANGED_PATHS = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
        "scripts/embedded_wasm.py",
    }
)


@dataclass(frozen=True)
class EmbeddedWasmModule:
    """Build, artifact, and changed-path contract for one embedded module."""

    name: str
    label: str
    package: str
    build_artifact: str
    embedded_artifact: str
    generate_target: str
    check_target: str
    changed_prefixes: tuple[str, ...]
    changed_paths: frozenset[str]
    changed_reason: str
    canonical_generate_only: bool = True
    canonical_compare_only: bool = True

    def build_path(self, repo: Path) -> Path:
        return repo / "target" / WASM_TARGET / "release" / self.build_artifact

    def embedded_path(self, repo: Path) -> Path:
        return repo / self.embedded_artifact

    def matches_changed_path(self, path: str) -> bool:
        return (
            path in COMMON_CHANGED_PATHS
            or path in self.changed_paths
            or any(path.startswith(prefix) for prefix in self.changed_prefixes)
        )


EMBEDDED_WASM_MODULES = (
    EmbeddedWasmModule(
        name="graphagent-static-validator",
        label="static Cypher validator",
        package="cerebro-graphagent-staticvalidator",
        build_artifact="cerebro_graphagent_staticvalidator.wasm",
        embedded_artifact="internal/graphagent/staticvalidator.wasm",
        generate_target="graphagent-static-validator-generate",
        check_target="graphagent-static-validator-check",
        changed_prefixes=("internal/graphagent/staticvalidator/",),
        changed_paths=frozenset(
            {
                "internal/graphagent/staticvalidator.go",
                "internal/graphagent/staticvalidator.wasm",
            }
        ),
        changed_reason="Static Cypher validator source, host, or embedded module changed.",
        canonical_generate_only=False,
        canonical_compare_only=False,
    ),
    EmbeddedWasmModule(
        name="sourcecoverage-evaluator",
        label="source coverage",
        package="cerebro-sourcecoverage-evaluator",
        build_artifact="cerebro_sourcecoverage_evaluator.wasm",
        embedded_artifact="internal/sourcecoverage/evaluator.wasm",
        generate_target="sourcecoverage-evaluator-generate",
        check_target="sourcecoverage-evaluator-check",
        changed_prefixes=("internal/sourcecoverage/evaluator/",),
        changed_paths=frozenset(
            {
                "internal/sourcecoverage/evaluator.go",
                "internal/sourcecoverage/evaluator.wasm",
            }
        ),
        changed_reason="Source coverage evaluator source, host, or embedded module changed.",
    ),
    EmbeddedWasmModule(
        name="panopticon-resource-extractor",
        label="Panopticon resource",
        package="cerebro-panopticon-resources",
        build_artifact="cerebro_panopticon_resources.wasm",
        embedded_artifact="internal/sourceprojection/panopticonresources.wasm",
        generate_target="panopticon-resource-extractor-generate",
        check_target="panopticon-resource-extractor-check",
        changed_prefixes=("internal/sourceprojection/panopticonresources/",),
        changed_paths=frozenset(
            {
                "internal/sourceprojection/panopticon_resources_host.go",
                "internal/sourceprojection/panopticonresources.wasm",
            }
        ),
        changed_reason="Panopticon resource extractor source, host, or embedded module changed.",
    ),
    EmbeddedWasmModule(
        name="mitre-context-evaluator",
        label="MITRE context",
        package="cerebro-mitre-evaluator",
        build_artifact="cerebro_mitre_evaluator.wasm",
        embedded_artifact="internal/mitre/evaluator.wasm",
        generate_target="mitre-context-evaluator-generate",
        check_target="mitre-context-evaluator-check",
        changed_prefixes=("internal/mitre/evaluator/",),
        changed_paths=frozenset(
            {
                "internal/mitre/evaluator.go",
                "internal/mitre/evaluator.wasm",
                "internal/mitre/mitre.go",
            }
        ),
        changed_reason="MITRE context normalization source, host, or embedded module changed.",
    ),
)

MODULES_BY_NAME = {module.name: module for module in EMBEDDED_WASM_MODULES}


class EmbeddedWasmError(RuntimeError):
    """Raised when an embedded module cannot be generated or verified."""


def host_platform() -> str:
    return f"{platform.system()}-{platform.machine()}"


def cargo_command() -> list[str]:
    return shlex.split(os.environ.get("CARGO", "cargo"))


def rustflags(repo: Path) -> str:
    cargo_home = os.environ.get("CARGO_HOME") or str(Path.home() / ".cargo")
    return f"--remap-path-prefix={repo}=/workspace --remap-path-prefix={cargo_home}=/cargo"


def build_module(module: EmbeddedWasmModule, repo: Path, *, lint: bool) -> None:
    cargo = cargo_command()
    if lint:
        subprocess.run(
            [*cargo, "clippy", "--locked", "--target", WASM_TARGET, "-p", module.package, "--", "-D", "warnings"],
            cwd=repo,
            check=True,
        )
    env = os.environ.copy()
    env["RUSTFLAGS"] = rustflags(repo)
    subprocess.run(
        [*cargo, "build", "--locked", "--release", "--target", WASM_TARGET, "-p", module.package],
        cwd=repo,
        env=env,
        check=True,
    )


def generate_module(module: EmbeddedWasmModule, repo: Path, *, current_platform: str | None = None) -> None:
    current_platform = current_platform or host_platform()
    if module.canonical_generate_only and current_platform != CANONICAL_PLATFORM:
        raise EmbeddedWasmError(
            f"{module.label} artifact generation requires {CANONICAL_PLATFORM}; current platform is {current_platform}"
        )
    build_module(module, repo, lint=False)
    destination = module.embedded_path(repo)
    shutil.copyfile(module.build_path(repo), destination)
    destination.chmod(0o644)


def check_module(module: EmbeddedWasmModule, repo: Path, *, current_platform: str | None = None) -> None:
    current_platform = current_platform or host_platform()
    build_module(module, repo, lint=True)
    if module.canonical_compare_only and current_platform != CANONICAL_PLATFORM:
        print(
            f"{module.label} artifact byte comparison runs on {CANONICAL_PLATFORM}; "
            f"current platform is {current_platform}"
        )
        return
    if not filecmp.cmp(module.build_path(repo), module.embedded_path(repo), shallow=False):
        platform_instruction = f" on {CANONICAL_PLATFORM}" if module.canonical_generate_only else ""
        raise EmbeddedWasmError(
            f"{module.embedded_artifact} is stale; run make {module.generate_target}{platform_instruction}"
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "check"))
    parser.add_argument("module", choices=(*MODULES_BY_NAME, "all"))
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).resolve()
    modules = EMBEDDED_WASM_MODULES if args.module == "all" else (MODULES_BY_NAME[args.module],)
    try:
        current_platform = host_platform()
        if args.action == "generate" and current_platform != CANONICAL_PLATFORM:
            restricted = next((module for module in modules if module.canonical_generate_only), None)
            if restricted is not None:
                raise EmbeddedWasmError(
                    f"{restricted.label} artifact generation requires {CANONICAL_PLATFORM}; "
                    f"current platform is {current_platform}"
                )
        for module in modules:
            if args.action == "generate":
                generate_module(module, repo, current_platform=current_platform)
            else:
                check_module(module, repo, current_platform=current_platform)
    except (EmbeddedWasmError, OSError, subprocess.CalledProcessError) as exc:
        print(f"embedded-wasm: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
