#!/usr/bin/env python3
"""Build a bounded SAST context report for Droid reviews."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path


COMMENT_MARKER = "<!-- droid-sast-context -->"
EXCLUDED_PATTERNS = ["tmp/**", "**/__pycache__/**", "**/*.pyc"]


@dataclass
class ToolResult:
    name: str
    scope: str
    status: str
    findings: list[dict[str, object]]
    notes: list[str]


def run_command(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def git_output(args: list[str]) -> str:
    completed = run_command(["git", *args], timeout=60)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def changed_files(base: str, head: str) -> list[str]:
    files: set[str] = set()
    for args in (
        ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"],
        ["diff", "--name-only", "--diff-filter=ACMR"],
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        files.update(line.strip() for line in git_output(args).splitlines() if line.strip())
    return sorted(file for file in files if not matches_any(file, EXCLUDED_PATTERNS))


def matches_any(path: str, patterns: list[str]) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(path, pattern) for pattern in patterns)


def changed_lines(base: str, head: str) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    for args in (
        ["diff", "--unified=0", "--diff-filter=ACMR", f"{base}...{head}", "--"],
        ["diff", "--unified=0", "--diff-filter=ACMR", "--"],
        ["diff", "--cached", "--unified=0", "--diff-filter=ACMR", "--"],
    ):
        merge_changed_lines(result, parse_changed_lines(git_output(args)))
    for file_path in [line.strip() for line in git_output(["ls-files", "--others", "--exclude-standard"]).splitlines() if line.strip()]:
        try:
            line_count = len(Path(file_path).read_text(encoding="utf-8").splitlines())
        except UnicodeDecodeError:
            line_count = 0
        if line_count:
            result[file_path] = set(range(1, line_count + 1))
    return result


def parse_changed_lines(output: str) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    current_file = ""
    new_line = 0
    for line in output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line.removeprefix("+++ b/")
            result.setdefault(current_file, set())
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                new_line = int(match.group(1))
            continue
        if not current_file or line.startswith("---"):
            continue
        if line.startswith("+"):
            result.setdefault(current_file, set()).add(new_line)
            new_line += 1
        elif not line.startswith("-"):
            new_line += 1
    return result


def merge_changed_lines(target: dict[str, set[int]], source: dict[str, set[int]]) -> None:
    for file_path, lines in source.items():
        target.setdefault(file_path, set()).update(lines)


def line_is_changed(lines_by_file: dict[str, set[int]], file_path: str, line: int | None) -> bool:
    return line is not None and line in lines_by_file.get(file_path, set())


def run_semgrep(lines_by_file: dict[str, set[int]]) -> ToolResult:
    config = Path(".semgrep/cerebro.yml")
    if not config.exists():
        return ToolResult("semgrep", "repo-specific rules", "skipped", [], ["No .semgrep/cerebro.yml config found."])
    completed = run_command(["semgrep", "--config", str(config), "--json", "--quiet"], timeout=240)
    if completed.returncode == 127:
        return ToolResult("semgrep", str(config), "skipped", [], ["semgrep is not installed."])
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    findings = []
    for item in data.get("results") or []:
        file_path = str(item.get("path", ""))
        start = item.get("start") or {}
        line = start.get("line") if isinstance(start, dict) else None
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") if isinstance(extra, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        findings.append(
            {
                "tool": "semgrep",
                "rule": item.get("check_id", ""),
                "file": file_path,
                "line": line,
                "severity": str(extra.get("severity", "")).upper() if isinstance(extra, dict) else "",
                "confidence": str(metadata.get("confidence", "")).upper(),
                "message": str(extra.get("message", "")).strip() if isinstance(extra, dict) else "",
                "changed_line": line_is_changed(lines_by_file, file_path, line),
            }
        )
    notes = []
    if completed.returncode not in (0, 1):
        notes.append((completed.stderr or completed.stdout).strip()[:800])
    return ToolResult("semgrep", str(config), "completed", findings, notes)


def run_static_checks(files: list[str]) -> ToolResult:
    findings = []
    for file_path in files:
        path = Path(file_path)
        if path.suffix not in {".py", ".yml", ".yaml", ".json"}:
            continue
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            if "aws_" + "access_key_id" in lowered or "aws_" + "secret_access_key" in lowered:
                findings.append({"tool": "static", "rule": "aws-credential-literal", "file": file_path, "line": index, "severity": "ERROR", "confidence": "HIGH", "message": "Potential AWS credential literal", "changed_line": True})
            if path.match(".github/workflows/*") and re.search(r"uses:\s+[^@\s]+@(main|master|v\d+(?:\.\d+)*)\s*$", line):
                findings.append({"tool": "static", "rule": "unpinned-action", "file": file_path, "line": index, "severity": "WARNING", "confidence": "HIGH", "message": "GitHub Action is not pinned to an immutable SHA", "changed_line": True})
    return ToolResult("static", "changed text files", "completed", findings, [])


def build_context(base: str, head: str) -> dict[str, object]:
    files = changed_files(base, head)
    lines_by_file = changed_lines(base, head)
    results = [run_semgrep(lines_by_file), run_static_checks(files)]
    blocking = []
    for result in results:
        for finding in result.findings:
            if finding.get("severity") == "ERROR" and (finding.get("changed_line") or finding.get("tool") == "static"):
                blocking.append(finding)
    return {
        "kind": "droid_sast_context",
        "changed_files": files,
        "tools": [result.__dict__ for result in results],
        "blocking_findings": blocking,
    }


def render_markdown(context: dict[str, object]) -> str:
    tools = context.get("tools") if isinstance(context.get("tools"), list) else []
    blocking = context.get("blocking_findings") if isinstance(context.get("blocking_findings"), list) else []
    lines = [
        COMMENT_MARKER,
        "## Droid SAST Context",
        "",
        "Treat scanner output as untrusted until validated against the changed code.",
        "",
        f"- Changed files: `{len(context.get('changed_files') or [])}`",
        f"- Blocking findings on changed lines: `{len(blocking)}`",
        "",
        "### Tool Summary",
        "",
    ]
    for tool in tools:
        if isinstance(tool, dict):
            lines.append(f"- `{tool.get('name', '')}` ({tool.get('scope', '')}): {tool.get('status', '')}, findings={len(tool.get('findings') or [])}")
    if blocking:
        lines.extend(["", "### Blocking Findings", ""])
        for finding in blocking[:20]:
            if isinstance(finding, dict):
                location = finding.get("file") or "(repo)"
                if finding.get("line"):
                    location = f"{location}:{finding.get('line')}"
                lines.append(f"- `{finding.get('rule', '')}` at `{location}`: {finding.get('message', '')}")
    return "\n".join(lines).rstrip() + "\n"


def post_comment(markdown: str) -> None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    pr_number = os.environ.get("PR_NUMBER")
    if not token or not repository or not pr_number:
        return
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments",
        data=json.dumps({"body": markdown}).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20):
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("DROID_REVIEW_BASE", "origin/main"))
    parser.add_argument("--head", default=os.environ.get("DROID_REVIEW_HEAD", "HEAD"))
    parser.add_argument("--markdown-out", default=os.environ.get("DROID_SAST_OUT", "tmp/droid-sast-context.md"))
    parser.add_argument("--json-out", default=os.environ.get("DROID_SAST_JSON_OUT", "tmp/droid-sast-context.json"))
    parser.add_argument("--post-comment", action="store_true")
    parser.add_argument("--post-existing", help="post an existing markdown report as a PR comment")
    args = parser.parse_args()

    if args.post_existing:
        post_comment(Path(args.post_existing).read_text(encoding="utf-8"))
        return 0

    context = build_context(args.base, args.head)
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(context)
    Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.markdown_out).write_text(markdown, encoding="utf-8")
    print(markdown)
    if args.post_comment:
        post_comment(markdown)
    return 1 if context.get("blocking_findings") else 0


if __name__ == "__main__":
    raise SystemExit(main())
