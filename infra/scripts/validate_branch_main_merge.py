from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


VALIDATION_COMMANDS = (
    ("uv", "run", "python", "-m", "compileall", "aws", "gcp", "scripts", "tests"),
    ("uv", "run", "python", "scripts/validate_pulumi_project_config.py"),
    ("uv", "run", "python", "scripts/validate_stack_config.py"),
    ("uv", "run", "python", "-m", "unittest", "discover", "-s", "tests"),
)


def _run(
    args: tuple[str, ...] | list[str],
    cwd: Path,
    *,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def _changed_infra_paths(repo_root: Path, base_ref: str, head_ref: str) -> list[str]:
    result = _run(
        ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"],
        cwd=repo_root,
        capture_output=True,
    )
    return [path for path in result.stdout.splitlines() if path.startswith("infra/")]


def _run_validators(worktree: Path) -> None:
    infra_dir = worktree / "infra"
    for command in VALIDATION_COMMANDS:
        _run(command, cwd=infra_dir)


def validate_branch_main_merge(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
    *,
    fetch: bool,
    remote: str,
    remote_branch: str,
) -> int:
    repo_root = repo_root.resolve()

    if fetch:
        _run(["git", "fetch", remote, f"{remote_branch}:refs/remotes/{remote}/{remote_branch}"], cwd=repo_root)

    changed_infra_paths = _changed_infra_paths(repo_root, base_ref, head_ref)
    if not changed_infra_paths:
        print(f"No infra changes found relative to {base_ref}; skipping virtual merge validation.")
        return 0

    print(f"Validating {len(changed_infra_paths)} infra path(s) after virtual merge with {base_ref}.")

    with tempfile.TemporaryDirectory(prefix="cerebro-branch-main-") as temp_dir:
        worktree = Path(temp_dir) / "merge-worktree"
        _run(["git", "worktree", "add", "--detach", str(worktree), base_ref], cwd=repo_root)
        try:
            merge = _run(
                ["git", "merge", "--no-commit", "--no-ff", head_ref],
                cwd=worktree,
                check=False,
                capture_output=True,
            )
            if merge.returncode != 0:
                sys.stderr.write(merge.stdout)
                sys.stderr.write(merge.stderr)
                return merge.returncode

            _run_validators(worktree)
        finally:
            _run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo_root, check=False)

    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".", help="repository root containing .git")
    parser.add_argument("--base", default="origin/main", help="base ref to merge onto")
    parser.add_argument("--head", default="HEAD", help="head ref to validate")
    parser.add_argument("--remote", default="origin", help="remote to fetch")
    parser.add_argument("--remote-branch", default="main", help="remote branch to refresh before validating")
    parser.add_argument("--skip-fetch", action="store_true", help="skip refreshing origin/main before validating")
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    return validate_branch_main_merge(
        Path(args.repo_root),
        args.base,
        args.head,
        fetch=not args.skip_fetch,
        remote=args.remote,
        remote_branch=args.remote_branch,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
