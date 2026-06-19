#!/usr/bin/env python3
"""Build a concise SAST context report for Droid PR reviews."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

COMMENT_MARKER = "<!-- droid-sast-context -->"
GOSEC_CMD = [
    "go",
    "run",
    "github.com/securego/gosec/v2/cmd/gosec@v2.24.7",
]
GOVULNCHECK_CMD = [
    "go",
    "run",
    "golang.org/x/vuln/cmd/govulncheck@v1.1.4",
]
DEFAULT_DEEPSEC_WORKSPACE = ".deepsec"
DEFAULT_DEEPSEC_PROJECT_ID = "cerebro"
DEFAULT_DEEPSEC_CONTEXT_LIMIT = 30


@dataclass
class ToolResult:
    name: str
    scope: str
    status: str
    findings: list[dict[str, object]]
    notes: list[str]


def run_command(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def git_output(args: list[str]) -> str:
    completed = run_command(["git", *args], timeout=60)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def changed_files(base: str, head: str) -> list[str]:
    files: set[str] = set()
    for args in [
        ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"],
        ["diff", "--name-only", "--diff-filter=ACMR"],
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ["ls-files", "--others", "--exclude-standard"],
    ]:
        output = git_output(args)
        files.update(line.strip() for line in output.splitlines() if line.strip())
    return sorted(files)


def changed_lines(base: str, head: str) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    for args in [
        ["diff", "--unified=0", "--diff-filter=ACMR", f"{base}...{head}", "--"],
        ["diff", "--unified=0", "--diff-filter=ACMR", "--"],
        ["diff", "--cached", "--unified=0", "--diff-filter=ACMR", "--"],
    ]:
        merge_changed_lines(result, parse_changed_lines(git_output(args)))
    untracked = git_output(["ls-files", "--others", "--exclude-standard"])
    for file_path in [line.strip() for line in untracked.splitlines() if line.strip()]:
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
            if not match:
                continue
            new_line = int(match.group(1))
            continue
        if not current_file or line.startswith("---"):
            continue
        if line.startswith("+"):
            result.setdefault(current_file, set()).add(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        else:
            new_line += 1
    return result


def merge_changed_lines(target: dict[str, set[int]], source: dict[str, set[int]]) -> None:
    for file_path, lines in source.items():
        target.setdefault(file_path, set()).update(lines)


def changed_go_packages(files: list[str]) -> list[str]:
    dirs = sorted({str(Path(path).parent) for path in files if path.endswith(".go")})
    packages: set[str] = set()
    for directory in dirs:
        package_arg = "." if directory == "." else f"./{directory}"
        completed = run_command(["go", "list", "-f", "{{.ImportPath}}", package_arg], timeout=60)
        if completed.returncode == 0:
            package = completed.stdout.strip()
            if package:
                packages.add(package)
    return sorted(packages)


def relpath(path: str) -> str:
    try:
        return Path(path).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def line_is_changed(lines_by_file: dict[str, set[int]], file_path: str, line: int | None) -> bool:
    if line is None:
        return False
    return line in lines_by_file.get(file_path, set())


def run_gosec(packages: list[str], lines_by_file: dict[str, set[int]]) -> ToolResult:
    if not packages:
        return ToolResult("gosec", "changed Go packages", "skipped", [], ["No changed Go packages."])
    package_args = [package.replace("github.com/writer/cerebro", ".") for package in packages]
    with tempfile.NamedTemporaryFile(prefix="gosec-", suffix=".json", delete=False) as handle:
        report_path = handle.name
    try:
        completed = run_command(
            [
                *GOSEC_CMD,
                "-severity",
                "medium",
                "-confidence",
                "medium",
                "-exclude-generated",
                "-fmt=json",
                "-out",
                report_path,
                *package_args,
            ],
            timeout=240,
        )
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            data = {"Issues": []}
        findings: list[dict[str, object]] = []
        for issue in data.get("Issues") or []:
            file_path = relpath(str(issue.get("file", "")))
            try:
                line = int(issue.get("line", 0))
            except (TypeError, ValueError):
                line = None
            severity = str(issue.get("severity", "")).upper()
            confidence = str(issue.get("confidence", "")).upper()
            finding = {
                "tool": "gosec",
                "rule": issue.get("rule_id", ""),
                "file": file_path,
                "line": line,
                "severity": severity,
                "confidence": confidence,
                "message": str(issue.get("details", "")).strip(),
                "changed_line": line_is_changed(lines_by_file, file_path, line),
            }
            findings.append(finding)
        notes = []
        if completed.returncode not in (0, 1):
            notes.append((completed.stderr or completed.stdout).strip()[:800])
        return ToolResult("gosec", ", ".join(package_args), "completed", findings, notes)
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


def run_govulncheck(packages: list[str]) -> ToolResult:
    if not packages:
        return ToolResult("govulncheck", "changed Go packages", "skipped", [], ["No changed Go packages."])
    package_args = [package.replace("github.com/writer/cerebro", ".") for package in packages]
    completed = run_command([*GOVULNCHECK_CMD, *package_args], timeout=240)
    findings: list[dict[str, object]] = []
    combined = "\n".join(part for part in [completed.stdout, completed.stderr] if part).strip()
    if completed.returncode == 3:
        findings.append(
            {
                "tool": "govulncheck",
                "rule": "reachable-vulnerability",
                "file": "",
                "line": None,
                "severity": "UNKNOWN",
                "confidence": "HIGH",
                "message": first_nonempty_line(combined) or "govulncheck reported reachable vulnerabilities",
                "changed_line": False,
            }
        )
    notes = trim_lines(combined, 30)
    if completed.returncode not in (0, 3):
        notes.insert(0, f"govulncheck exited {completed.returncode}; treating as tool error, not a confirmed vulnerability.")
    return ToolResult("govulncheck", ", ".join(package_args), "completed", findings, notes)


def run_semgrep(lines_by_file: dict[str, set[int]]) -> ToolResult:
    config = Path(".semgrep/cerebro.yml")
    if not config.exists():
        return ToolResult("semgrep", "repo-specific rules", "skipped", [], ["No .semgrep/cerebro.yml config found."])
    completed = run_command(
        ["semgrep", "--config", str(config), "--json", "--quiet"],
        timeout=240,
    )
    if completed.returncode == 127:
        return ToolResult("semgrep", str(config), "skipped", [], ["semgrep is not installed."])
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    findings: list[dict[str, object]] = []
    for item in data.get("results") or []:
        file_path = relpath(str(item.get("path", "")))
        start = item.get("start") or {}
        line = start.get("line") if isinstance(start, dict) else None
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") if isinstance(extra, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        severity = str(extra.get("severity", "")).upper() if isinstance(extra, dict) else ""
        confidence = str(metadata.get("confidence", "")).upper()
        finding = {
            "tool": "semgrep",
            "rule": item.get("check_id", ""),
            "file": file_path,
            "line": line,
            "severity": severity,
            "confidence": confidence,
            "message": str(extra.get("message", "")).strip() if isinstance(extra, dict) else "",
            "changed_line": line_is_changed(lines_by_file, file_path, line),
        }
        if finding["changed_line"]:
            findings.append(finding)
    notes = []
    if completed.returncode not in (0, 1):
        notes.append((completed.stderr or completed.stdout).strip()[:800])
    return ToolResult("semgrep", str(config), "completed", findings, notes)


def run_deepsec_scan(files: list[str], lines_by_file: dict[str, set[int]]) -> ToolResult:
    workspace = Path(os.environ.get("DROID_DEEPSEC_WORKSPACE", DEFAULT_DEEPSEC_WORKSPACE))
    project_id = os.environ.get("DROID_DEEPSEC_PROJECT_ID", DEFAULT_DEEPSEC_PROJECT_ID)
    context_limit = max(0, env_int("DROID_DEEPSEC_CONTEXT_LIMIT", DEFAULT_DEEPSEC_CONTEXT_LIMIT))
    scope = f"project `{project_id}` candidate scan"
    if not (workspace / "package.json").exists():
        return ToolResult("deepsec", scope, "skipped", [], [f"No DeepSec workspace found at {workspace}."])
    if not (workspace / "node_modules" / ".bin" / "deepsec").exists():
        return ToolResult(
            "deepsec",
            scope,
            "skipped",
            [],
            [f"DeepSec is not installed; run `pnpm -C {workspace} install --frozen-lockfile`."],
        )
    completed = run_command(
        [
            "pnpm",
            "-C",
            str(workspace),
            "exec",
            "deepsec",
            "scan",
            "--project-id",
            project_id,
        ],
        timeout=360,
    )
    if completed.returncode != 0:
        notes = trim_lines("\n".join(part for part in [completed.stderr, completed.stdout] if part), 12)
        notes.insert(0, f"deepsec scan exited {completed.returncode}; treating as tool error, not a confirmed vulnerability.")
        return ToolResult("deepsec", scope, "error", [], notes)
    run_id = parse_deepsec_run_id(completed.stdout) or parse_deepsec_run_id(completed.stderr)
    run = latest_deepsec_scan_run(workspace, project_id, run_id)
    if not run:
        return ToolResult("deepsec", scope, "error", [], ["DeepSec scan completed but no scan run record was found."])
    effective_run_id = str(run.get("runId") or run_id or "").strip()
    if not effective_run_id:
        return ToolResult(
            "deepsec",
            scope,
            "error",
            [],
            ["DeepSec scan completed but no concrete scan run id was found; refusing to mix historical candidates."],
        )
    findings, notes = collect_deepsec_scan_context(
        workspace,
        project_id,
        effective_run_id,
        files,
        lines_by_file,
        context_limit,
    )
    return ToolResult("deepsec", scope, "completed", findings, notes)


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def parse_deepsec_run_id(value: str) -> str:
    match = re.search(r"Run ID:\s*([A-Za-z0-9_-]+)", value)
    return match.group(1) if match else ""


def latest_deepsec_scan_run(workspace: Path, project_id: str, preferred_run_id: str = "") -> dict[str, object] | None:
    runs_dir = workspace / "data" / project_id / "runs"
    if not runs_dir.is_dir():
        return None
    runs: list[dict[str, object]] = []
    for path in sorted(runs_dir.glob("*.json")):
        data = read_json_object(path)
        if not data or data.get("type") != "scan":
            continue
        if preferred_run_id and data.get("runId") == preferred_run_id:
            return data
        runs.append(data)
    if not runs:
        return None
    return max(runs, key=lambda item: str(item.get("completedAt") or item.get("createdAt") or item.get("runId") or ""))


def collect_deepsec_scan_context(
    workspace: Path,
    project_id: str,
    run_id: str,
    files: list[str],
    lines_by_file: dict[str, set[int]],
    limit: int = DEFAULT_DEEPSEC_CONTEXT_LIMIT,
) -> tuple[list[dict[str, object]], list[str]]:
    files_dir = workspace / "data" / project_id / "files"
    run_id = str(run_id).strip()
    if not run_id:
        return [], ["DeepSec scan run id is missing; no historical candidates were included."]
    if not files_dir.is_dir():
        return [], [f"Run {run_id}: no DeepSec candidate file records found."]
    changed_files = {normalize_repo_path(path) for path in files}
    total_candidates = 0
    files_with_candidates = 0
    changed_file_candidates = 0
    review_findings_by_key: dict[tuple[str, str, str], dict[str, object]] = {}
    for path in sorted(files_dir.rglob("*.json")):
        record = read_json_object(path)
        if not record:
            continue
        if record.get("lastScannedRunId") != run_id:
            continue
        file_path = normalize_repo_path(str(record.get("filePath") or ""))
        candidates = record.get("candidates") if isinstance(record.get("candidates"), list) else []
        if candidates:
            files_with_candidates += 1
        total_candidates += len(candidates)
        file_changed = file_path in changed_files
        if file_changed:
            changed_file_candidates += len(candidates)
        for candidate in candidates:
            if not isinstance(candidate, dict) or not file_changed:
                continue
            candidate_lines = deepsec_candidate_lines(candidate)
            changed_candidate_lines = sorted(set(candidate_lines).intersection(lines_by_file.get(file_path, set())))
            line = min(candidate_lines) if candidate_lines else None
            changed_line = bool(changed_candidate_lines)
            rule = deepsec_rule_id(candidate)
            base_message = deepsec_candidate_message(candidate)
            message = base_message
            if changed_candidate_lines and line not in changed_candidate_lines:
                changed_refs = ", ".join(str(item) for item in changed_candidate_lines[:3])
                if len(changed_candidate_lines) > 3:
                    changed_refs = f"{changed_refs}, ..."
                message = f"{message} (spans changed line(s): {changed_refs})"[:240]
            finding = {
                "tool": "deepsec",
                "rule": rule,
                "file": file_path,
                "line": line,
                "severity": "INFO",
                "confidence": "SIGNAL",
                "message": message,
                "changed_line": changed_line,
            }
            key = (file_path, rule, base_message)
            existing = review_findings_by_key.get(key)
            if existing:
                if changed_line and not existing.get("changed_line"):
                    existing["changed_line"] = True
                    existing["line"] = line
                    existing["message"] = message
                continue
            review_findings_by_key[key] = finding
    review_findings = list(review_findings_by_key.values())
    review_findings.sort(
        key=lambda finding: (
            not bool(finding.get("changed_line")),
            str(finding.get("file") or ""),
            int(finding.get("line") or 0),
            str(finding.get("rule") or ""),
        )
    )
    notes = [
        f"Run {run_id}: {total_candidates} candidate(s) across {files_with_candidates} file(s); "
        f"{changed_file_candidates} candidate(s) on changed files."
    ]
    if len(review_findings) > limit:
        notes.append(f"DeepSec changed-file candidates truncated to {limit} of {len(review_findings)}.")
    return review_findings[:limit], notes


def read_json_object(path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def normalize_repo_path(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def deepsec_candidate_lines(candidate: dict[str, object]) -> list[int]:
    raw_lines = candidate.get("lineNumbers")
    if not isinstance(raw_lines, list):
        return []
    lines: list[int] = []
    for raw_line in raw_lines:
        try:
            line = int(raw_line)
        except (TypeError, ValueError):
            continue
        if line > 0:
            lines.append(line)
    return lines


def deepsec_candidate_message(candidate: dict[str, object]) -> str:
    rule = deepsec_rule_id(candidate)
    return f"DeepSec candidate signal for `{rule}`; source snippets withheld from AI context."


def deepsec_rule_id(candidate: dict[str, object]) -> str:
    slug = compact_text(str(candidate.get("vulnSlug") or ""))
    if not slug:
        return f"candidate-{deepsec_candidate_fingerprint(candidate)}"
    value = slug
    value = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-")
    return value[:80] if value else "candidate"


def deepsec_candidate_fingerprint(candidate: dict[str, object]) -> str:
    encoded = json.dumps(candidate, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return f"{zlib.crc32(encoded) & 0xFFFFFFFF:08x}"


def compact_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        line = line.strip()
        if line:
            return line[:240]
    return ""


def trim_lines(value: str, limit: int) -> list[str]:
    lines = [line.rstrip() for line in value.splitlines() if line.strip()]
    if len(lines) <= limit:
        return lines
    return [*lines[:limit], f"... truncated {len(lines) - limit} line(s)"]


def blocking_findings(results: list[ToolResult]) -> list[dict[str, object]]:
    blockers: list[dict[str, object]] = []
    for result in results:
        for finding in result.findings:
            severity = str(finding.get("severity", "")).upper()
            confidence = str(finding.get("confidence", "")).upper()
            if finding.get("changed_line") and severity in {"HIGH", "ERROR"} and confidence == "HIGH":
                blockers.append(finding)
    return blockers


def render_markdown(base: str, head: str, files: list[str], packages: list[str], results: list[ToolResult]) -> str:
    blockers = blocking_findings(results)
    lines = [
        COMMENT_MARKER,
        "## Droid SAST Context",
        "",
        "Use this as scanner context for review. Validate findings before commenting.",
        "",
        f"- Base: `{base}`",
        f"- Head: `{head}`",
        f"- Changed files: `{len(files)}`",
        f"- Changed Go packages: `{len(packages)}`",
        f"- Blocking changed-line findings: `{len(blockers)}`",
        "",
        "### Tool Summary",
        "",
        "| Tool | Scope | Status | Findings | Notes |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for result in results:
        note = "; ".join(result.notes[:2]) if result.notes else ""
        lines.append(
            f"| `{result.name}` | {escape_pipe(result.scope)} | {result.status} | {len(result.findings)} | {escape_pipe(note[:160])} |"
        )
    if blockers:
        lines.extend(["", "### Blocking Findings", ""])
        for finding in blockers:
            lines.append(format_finding(finding))
    review_findings = [
        finding
        for result in results
        for finding in result.findings
        if finding not in blockers
    ]
    if review_findings:
        lines.extend(["", "### Review Context Findings", ""])
        for finding in review_findings[:20]:
            lines.append(format_finding(finding))
        if len(review_findings) > 20:
            lines.append(f"- ... truncated {len(review_findings) - 20} finding(s)")
    if not blockers and not review_findings:
        lines.extend(["", "### Review Context Findings", "", "No changed-line SAST findings."])
    return "\n".join(lines).rstrip() + "\n"


def render_json_context(base: str, head: str, files: list[str], packages: list[str], results: list[ToolResult]) -> dict[str, object]:
    return {
        "kind": "droid_sast_context",
        "base": base,
        "head": head,
        "changed_files": files,
        "changed_go_packages": packages,
        "blocking_findings": blocking_findings(results),
        "tools": [
            {
                "name": result.name,
                "scope": result.scope,
                "status": result.status,
                "findings": result.findings,
                "notes": result.notes,
            }
            for result in results
        ],
    }


def escape_pipe(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def format_finding(finding: dict[str, object]) -> str:
    file_path = str(finding.get("file") or "")
    line = finding.get("line")
    location = f"{file_path}:{line}" if file_path and line else file_path or "(repo)"
    return (
        f"- `{finding.get('tool')}` `{finding.get('rule')}` at `{location}` "
        f"({finding.get('severity')}/{finding.get('confidence')}): {finding.get('message')}"
    )


def post_sticky_comment(markdown: str) -> None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    pr_number = os.environ.get("PR_NUMBER")
    if not token or not repository or not pr_number:
        raise RuntimeError("GH_TOKEN/GITHUB_REPOSITORY/PR_NUMBER are required to post SAST context")
    marker = COMMENT_MARKER
    first_line = markdown.splitlines()[0].strip() if markdown.splitlines() else ""
    if first_line.startswith("<!--") and first_line.endswith("-->"):
        marker = first_line

    def request_json(method: str, path: str, payload: dict[str, object] | None = None) -> object:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"https://api.github.com/{path.lstrip('/')}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    page = 1
    while True:
        comments = request_json(
            "GET",
            f"/repos/{repository}/issues/{pr_number}/comments?per_page=100&page={page}",
        )
        if not isinstance(comments, list) or not comments:
            break
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            body = str(comment.get("body") or "")
            if marker in body:
                request_json(
                    "PATCH",
                    f"/repos/{repository}/issues/comments/{comment['id']}",
                    {"body": markdown},
                )
                return
        page += 1
    request_json(
        "POST",
        f"/repos/{repository}/issues/{pr_number}/comments",
        {"body": markdown},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("DROID_REVIEW_BASE", "origin/main"))
    parser.add_argument("--head", default=os.environ.get("DROID_REVIEW_HEAD", "HEAD"))
    parser.add_argument("--markdown-out", default=os.environ.get("DROID_SAST_OUT", "tmp/droid-sast-context.md"))
    parser.add_argument("--json-out", default=os.environ.get("DROID_SAST_JSON_OUT", ""))
    parser.add_argument("--post-comment", action="store_true")
    parser.add_argument("--post-existing", help="post an existing SAST markdown report and exit")
    args = parser.parse_args()

    if args.post_existing:
        markdown = Path(args.post_existing).read_text(encoding="utf-8")
        post_sticky_comment(markdown)
        return 0

    files = changed_files(args.base, args.head)
    lines_by_file = changed_lines(args.base, args.head)
    packages = changed_go_packages(files)
    results = [
        run_gosec(packages, lines_by_file),
        run_govulncheck(packages),
        run_semgrep(lines_by_file),
        run_deepsec_scan(files, lines_by_file),
    ]
    markdown = render_markdown(args.base, args.head, files, packages, results)
    out_path = Path(args.markdown_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(render_json_context(args.base, args.head, files, packages, results), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(markdown)
    if args.post_comment:
        post_sticky_comment(markdown)
    return 1 if blocking_findings(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
