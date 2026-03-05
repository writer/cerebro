from pathlib import Path
import re
import sys


repo = Path(__file__).resolve().parents[1]
roots = [
    repo / "api",
    repo / "cmd",
    repo / "internal",
    repo / "policies",
    repo / ".env.example",
    repo / "docker-compose.yml",
    repo / "README.md",
    repo / "docs",
]

checks = [
    ("internal_hostname", re.compile(r"\.internal\.|\.corp\.", re.IGNORECASE)),
    (
        "secret_pattern",
        re.compile(
            r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}"
        ),
    ),
    ("aws_account_id", re.compile(r"\b\d{12}\b")),
]

violations = []

for root in roots:
    if not root.exists():
        continue
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    for path in files:
        rel = path.relative_to(repo)
        rels = str(rel)
        if any(part in {".git", "vendor", ".factory", "infra"} for part in rel.parts):
            continue
        if rels.startswith(".github/"):
            continue
        if rel.name.endswith("_test.go") or "/testdata/" in rels:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue

        for idx, line in enumerate(text.splitlines(), start=1):
            for name, pattern in checks:
                if name == "aws_account_id" and rels.startswith("docs/"):
                    continue
                if pattern.search(line):
                    violations.append((name, rels, idx, line.strip()))

if violations:
    print(f"Found {len(violations)} sensitive-reference matches:")
    for name, rels, idx, line in violations[:200]:
        print(f"[{name}] {rels}:{idx}: {line}")
    sys.exit(1)

print("OSS audit passed with no sensitive-reference matches.")
