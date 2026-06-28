#!/usr/bin/env python3
"""Public-repository hygiene checks for Cerebro."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse


EXCLUDED_DIRS = {
    ".git",
    ".idea",
    ".venv",
    ".vscode",
    "bin",
    "dist",
    "node_modules",
    "tmp",
    "vendor",
}

EXCLUDED_FILES = {
    "go.sum",
    "scripts/leak_patterns.txt",
}

PUBLIC_DOC_PREFIXES = (
    "README.md",
    "docs/",
    "deploy/pulumi/",
)

PUBLIC_DOC_ALLOWED_ACCOUNT_IDS = {
    "111122223333",
}

PUBLIC_DOC_FORBIDDEN_MARKERS = tuple(sorted((
    "WriterInternal",
    "writerinternal",
    "sec-dev",
    "go-prod",
    "cerebro-sec-dev",
    "cerebro-go-production",
    "writer-sec",
    "adm.prod.writer.com",
    "prod.writer.com",
), key=len, reverse=True))

ALLOWED_FIXTURE_EMAIL_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "example.test",
    "gmail.com",
    "tenant.example",
    "writer.com",
}

ALLOWED_FIXTURE_HOST_SUFFIXES = (
    ".example.com",
    ".example.net",
    ".example.org",
    ".example.test",
    ".github.com",
    ".googleapis.com",
    ".gserviceaccount.com",
    ".okta.com",
    ".writer.com",
)

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "key",
    "password",
    "secret",
    "token",
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")
ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?[^)]*(?:\+|\*|\{\d+(?:,\d*)?\})[^)]*\)(?:\+|\*|\{\d+(?:,\d*)?\})"
)


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return Path(result.stdout.strip()).resolve()
    return Path.cwd().resolve()


def load_patterns(root: Path) -> list[re.Pattern[str]]:
    pattern_files = [root / "scripts" / "leak_patterns.txt"]
    user_file = os.environ.get("CEREBRO_LEAK_USER_PATTERNS")
    if user_file:
        pattern_files.append(Path(user_file).expanduser())

    patterns: list[re.Pattern[str]] = []
    for path in pattern_files:
        if path.is_symlink():
            raise SystemExit(f"{path}: symlinked leak pattern files are not allowed")
        if not path.exists():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            value = value.replace("[[:space:]]", r"\s")
            reason = unsafe_regex_reason(value)
            if reason:
                raise SystemExit(f"{path}:{line_number}: unsafe leak pattern: {reason}")
            try:
                patterns.append(re.compile(value))
            except re.error as exc:
                raise SystemExit(f"{path}:{line_number}: invalid leak pattern: {exc}") from exc
    return patterns


def unsafe_regex_reason(value: str) -> str:
    if NESTED_QUANTIFIER_RE.search(value):
        return "nested quantifiers can cause catastrophic backtracking"
    if re.search(r"\\[1-9]", value):
        return "backreferences can cause non-linear matching"
    return ""


def iter_files(root: Path):
    for current_root, dirs, files in os.walk(root):
        kept_dirs = []
        for item in dirs:
            if item in EXCLUDED_DIRS:
                continue
            path = Path(current_root) / item
            if path.is_symlink():
                if item == "testdata":
                    rel = path.relative_to(root).as_posix()
                    raise SystemExit(f"{rel}: symlinked testdata directories are not allowed")
                continue
            kept_dirs.append(item)
        dirs[:] = kept_dirs
        for filename in files:
            path = Path(current_root) / filename
            rel = path.relative_to(root).as_posix()
            if rel in EXCLUDED_FILES:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            yield path, rel


def is_probably_text(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\0" not in chunk


def redact(value: str) -> str:
    return f"<REDACTED:len={len(value)}>"


def scan(root: Path, patterns: list[re.Pattern[str]]) -> list[str]:
    findings: list[str] = []
    for path, rel in iter_files(root):
        if not is_probably_text(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            findings.append(f"{rel}: read failed: {exc}")
            continue
        for line_number, line in enumerate(lines, start=1):
            for pattern in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                redacted = pattern.sub(lambda m: redact(m.group(0)), line)
                findings.append(f"{rel}:{line_number}: {redacted}")
    return findings


def iter_json_fixtures(root: Path):
    for path, rel in iter_files(root):
        if path.suffix != ".json":
            continue
        parts = set(path.relative_to(root).parts)
        if "testdata" not in parts:
            continue
        yield path, rel


def scan_fixture_semantics(root: Path) -> list[str]:
    findings: list[str] = []
    for path, rel in iter_json_fixtures(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            parsed = json.loads(text)
        except (OSError, json.JSONDecodeError):
            continue
        for value_path, value in walk_json_strings(parsed):
            findings.extend(check_fixture_value(rel, value_path, value))
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in IPV4_RE.finditer(line):
                findings.extend(check_fixture_ip(rel, f"line {line_number}", match.group(0)))
    return findings


def scan_public_doc_infrastructure_markers(root: Path) -> list[str]:
    findings: list[str] = []
    for path, rel in iter_files(root):
        if not is_public_doc_path(rel) or not is_probably_text(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            findings.append(f"{rel}: read failed: {exc}")
            continue
        for line_number, line in enumerate(lines, start=1):
            for marker in PUBLIC_DOC_FORBIDDEN_MARKERS:
                if marker in line:
                    findings.append(f"{rel}:{line_number}: public docs must not include deployment marker {redact(marker)}")
                    break
            for match in ACCOUNT_ID_RE.finditer(line):
                account_id = match.group(0)
                if account_id not in PUBLIC_DOC_ALLOWED_ACCOUNT_IDS:
                    findings.append(f"{rel}:{line_number}: public docs must not include account id {redact(account_id)}")
    return findings


def is_public_doc_path(rel: str) -> bool:
    for prefix in PUBLIC_DOC_PREFIXES:
        if prefix.endswith("/"):
            if rel.startswith(prefix):
                return True
        elif rel == prefix:
            return True
    return False


def walk_json_strings(value, prefix: str = "$"):
    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}"
            yield from walk_json_strings(item, next_prefix)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json_strings(item, f"{prefix}[{index}]")
    elif isinstance(value, str):
        yield prefix, value


def check_fixture_value(rel: str, value_path: str, value: str) -> list[str]:
    findings: list[str] = []
    for match in EMAIL_RE.finditer(value):
        domain = match.group(1).lower()
        if not fixture_email_domain_allowed(domain):
            findings.append(f"{rel}:{value_path}: non-synthetic fixture email domain {redact(match.group(0))}")
    for match in URL_RE.finditer(value):
        parsed = urlparse(match.group(0))
        host = (parsed.hostname or "").lower()
        if host and not fixture_host_allowed(host):
            findings.append(f"{rel}:{value_path}: non-allowlisted fixture URL host {redact(host)}")
        query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
        sensitive_keys = sorted(query_keys & SENSITIVE_QUERY_KEYS)
        if sensitive_keys:
            findings.append(f"{rel}:{value_path}: fixture URL contains sensitive query key(s): {','.join(sensitive_keys)}")
    for match in IPV4_RE.finditer(value):
        findings.extend(check_fixture_ip(rel, value_path, match.group(0)))
    return findings


def check_fixture_ip(rel: str, value_path: str, value: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return []
    if ip.version != 4:
        return []
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return []
    documentation_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    if any(ip in network for network in documentation_ranges):
        return []
    return [f"{rel}:{value_path}: fixture uses public IPv4 address {redact(value)}"]


def fixture_email_domain_allowed(domain: str) -> bool:
    return domain in ALLOWED_FIXTURE_EMAIL_DOMAINS or domain.endswith(ALLOWED_FIXTURE_HOST_SUFFIXES)


def fixture_host_allowed(host: str) -> bool:
    if host in {"localhost", "127.0.0.1"}:
        return True
    return any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in ALLOWED_FIXTURE_HOST_SUFFIXES)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None, help="repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve() if args.root else repo_root()
    patterns = load_patterns(root)
    findings: list[str] = []
    if patterns:
        findings.extend(scan(root, patterns))
    else:
        print("oss-audit: no leak patterns configured", file=sys.stderr)
    findings.extend(scan_fixture_semantics(root))
    findings.extend(scan_public_doc_infrastructure_markers(root))
    if findings:
        print("oss-audit: public hygiene findings detected", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print("oss-audit: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
