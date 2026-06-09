#!/usr/bin/env python3
"""Smoke-test finding candidate APIs against a deployed Cerebro service."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import NoReturn


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


BASE_URL = env("CEREBRO_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
API_KEY = env("CEREBRO_API_KEY") or env("CEREBRO_AUTH_TOKEN")
RUNTIME_ID = env("CEREBRO_CANDIDATE_SMOKE_RUNTIME_ID") or env("RUNTIME_ID")
RULE_ID = env("CEREBRO_CANDIDATE_SMOKE_RULE_ID") or env("RULE_ID")
EVENT_LIMIT = env("CEREBRO_CANDIDATE_SMOKE_EVENT_LIMIT", "25")
ALLOW_EMPTY = env("CEREBRO_CANDIDATE_SMOKE_ALLOW_EMPTY", "false").lower() in {"1", "true", "yes"}


def fail(message: str) -> NoReturn:
    print(f"candidate-smoke: {message}", file=sys.stderr)
    raise SystemExit(1)


def request(method: str, path: str, query: dict[str, str] | None = None, body: dict | None = None) -> dict:
    url = BASE_URL + path
    if query:
        filtered = {key: value for key, value in query.items() if value}
        if filtered:
            url += "?" + urllib.parse.urlencode(filtered, doseq=True)
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if API_KEY:
        headers["Authorization"] = "Bearer " + API_KEY
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        fail(f"{method} {url} failed with HTTP {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        fail(f"{method} {url} failed: {exc}")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"{method} {url} returned invalid JSON: {exc}")


def require_runtime() -> None:
    if not RUNTIME_ID:
        fail("CEREBRO_CANDIDATE_SMOKE_RUNTIME_ID or RUNTIME_ID is required")
    if not EVENT_LIMIT.isdigit() or int(EVENT_LIMIT) <= 0:
        fail("CEREBRO_CANDIDATE_SMOKE_EVENT_LIMIT must be a positive integer")


def finding_ids(payload: dict) -> set[str]:
    return {
        str(finding.get("id") or "")
        for finding in payload.get("findings", [])
        if finding.get("id")
    }


def candidates(payload: dict) -> list[dict]:
    return [candidate for candidate in payload.get("candidates", []) if isinstance(candidate, dict)]


def candidate_id(candidate: dict) -> str:
    return str(candidate.get("id") or candidate.get("candidateId") or "")


def main() -> None:
    require_runtime()
    runtime_path = "/source-runtimes/" + urllib.parse.quote(RUNTIME_ID, safe="")
    candidate_query = {"rule_id": RULE_ID, "status": "candidate", "limit": "10"}
    finding_query = {"rule_id": RULE_ID, "limit": "100"}

    request("GET", "/health")
    before_findings = finding_ids(request("GET", runtime_path + "/findings", finding_query))

    request(
        "POST",
        runtime_path + "/finding-candidates/evaluate",
        {"rule_id": RULE_ID, "event_limit": EVENT_LIMIT},
        {},
    )

    listed = candidates(request("GET", runtime_path + "/finding-candidates", candidate_query))
    if not listed and not ALLOW_EMPTY:
        fail(
            "candidate evaluation produced no persisted candidates; set "
            "CEREBRO_CANDIDATE_SMOKE_ALLOW_EMPTY=true only for known quiet runtimes"
        )
    if listed:
        first_id = candidate_id(listed[0])
        if not first_id:
            fail("listed candidate is missing id")
        response = request("GET", "/finding-candidates/" + urllib.parse.quote(first_id, safe=""))
        if not response.get("candidate"):
            fail(f"get candidate {first_id} returned no candidate")

    after_findings = finding_ids(request("GET", runtime_path + "/findings", finding_query))
    if before_findings != after_findings:
        fail("production findings changed during candidate-only evaluation")

    print(
        json.dumps(
            {
                "status": "ok",
                "base_url": BASE_URL,
                "runtime_id": RUNTIME_ID,
                "rule_id": RULE_ID,
                "event_limit": int(EVENT_LIMIT),
                "candidates_checked": len(listed),
                "production_findings_unchanged": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
