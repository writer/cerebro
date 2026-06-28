#!/usr/bin/env python3
"""Run a redacted Cerebro onboarding plan and write a setup receipt."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RECEIPT = ROOT / "tmp" / "onboarding" / "receipt.json"
DEFAULT_PLAN = ROOT / "examples" / "onboarding" / "cerebro-onboarding.yaml"
SENSITIVE_NAME_RE = re.compile(r"(secret|token|password|credential|api[_-]?key|private[_-]?key|dsn)", re.I)
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(access[_-]?token|api[_-]?key|authorization|client[_-]?secret|key|password|secret|token)=([^\s,;)&]+)"
)


class OnboardingError(Exception):
    """Raised when the onboarding plan cannot complete."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def load_plan(path: Path) -> dict[str, Any]:
    body = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    if yaml is not None:
        loaded = yaml.safe_load(body)
    else:
        loaded = json.loads(body)
    if not isinstance(loaded, dict):
        raise OnboardingError("plan root must be an object")
    return loaded


def required_str(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OnboardingError(f"plan.{key} is required")
    return value.strip()


def is_secret_name(name: str) -> bool:
    return bool(SENSITIVE_NAME_RE.search(name))


def env_ref(value: str) -> str | None:
    if value.startswith("env:") and len(value) > 4:
        return value[4:]
    return None


def ensure_no_literal_secret(path: str, key: str, value: Any) -> None:
    if not isinstance(value, str):
        return
    if not is_secret_name(key):
        return
    if value.startswith("env:") or value.startswith("credential:") or value.startswith("secret:"):
        return
    if value == "":
        return
    raise OnboardingError(f"{path}.{key} must use env:, credential:, or secret: instead of a literal value")


def validate_plan(plan: dict[str, Any]) -> list[str]:
    required_str(plan, "version")
    required_str(plan, "name")
    required_str(plan, "tenant_id")
    validate_base_url(required_str(plan, "base_url"))
    api_key_env = required_str(plan, "api_key_env")
    if "api_key" in plan:
        raise OnboardingError("plan.api_key is not allowed; use api_key_env")

    required_env = {api_key_env}
    environment = plan.get("environment", {})
    if not isinstance(environment, dict):
        raise OnboardingError("plan.environment must be an object")
    for key, value in environment.items():
        ensure_no_literal_secret("plan.environment", key, value)
        if isinstance(value, str) and env_ref(value):
            required_env.add(env_ref(value) or "")

    runtimes = plan.get("source_runtimes")
    if not isinstance(runtimes, list) or not runtimes:
        raise OnboardingError("plan.source_runtimes must include at least one runtime")
    seen_runtime_ids: set[str] = set()
    for index, runtime in enumerate(runtimes):
        if not isinstance(runtime, dict):
            raise OnboardingError(f"plan.source_runtimes[{index}] must be an object")
        runtime_id = required_str(runtime, "id")
        if runtime_id in seen_runtime_ids:
            raise OnboardingError(f"plan.source_runtimes[{index}].id duplicates {runtime_id}")
        seen_runtime_ids.add(runtime_id)
        required_str(runtime, "source_id")
        if not isinstance(runtime.get("config", {}), dict):
            raise OnboardingError(f"plan.source_runtimes[{index}].config must be an object")
        for key, value in runtime.get("config", {}).items():
            ensure_no_literal_secret(f"plan.source_runtimes[{index}].config", key, value)
            if isinstance(value, str) and env_ref(value):
                required_env.add(env_ref(value) or "")
        claims = runtime.get("claims", [])
        if claims and not isinstance(claims, list):
            raise OnboardingError(f"plan.source_runtimes[{index}].claims must be a list")

    return sorted(value for value in required_env if value)


def validate_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise OnboardingError("plan.base_url must use http or https")
    if not parsed.netloc or not parsed.hostname:
        raise OnboardingError("plan.base_url must include a host")
    if parsed.username or parsed.password:
        raise OnboardingError("plan.base_url must not include credentials")
    if parsed.query or parsed.fragment:
        raise OnboardingError("plan.base_url must not include a query or fragment")
    path = parsed.path.rstrip("/")
    if path:
        raise OnboardingError("plan.base_url must not include a path")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def redact_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if not parsed.netloc or "@" not in parsed.netloc:
        return value
    host = parsed.netloc.rsplit("@", 1)[1]
    return urllib.parse.urlunsplit((parsed.scheme, f"redacted@{host}", parsed.path, parsed.query, parsed.fragment))


def redact_message(value: str) -> str:
    redacted = SECRET_VALUE_RE.sub(lambda match: f"{match.group(1)}=redacted", value)
    return redact_url(redacted)


def redact_value(key: str, value: Any) -> Any:
    if key in {"required_secret_names", "required_env"}:
        return value
    if isinstance(value, dict):
        return {k: redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    if isinstance(value, str):
        if is_secret_name(key):
            return "redacted"
        if "://" in value:
            return redact_url(value)
    return value


def command_runner(argv: list[str], env: dict[str, str], cwd: Path, timeout: int = 120) -> CommandResult:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return CommandResult(result.returncode, result.stdout, result.stderr)


def default_http_request(method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: int) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 -- operator-provided local/server URL.
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", errors="replace")


class AgentOnboardRunner:
    def __init__(
        self,
        plan: dict[str, Any],
        receipt_path: Path,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        wait: bool = False,
        require_server: bool = True,
        cmd: Callable[[list[str], dict[str, str], Path, int], CommandResult] = command_runner,
        http: Callable[[str, str, dict[str, str], bytes | None, int], tuple[int, str]] = default_http_request,
    ) -> None:
        self.plan = plan
        self.receipt_path = receipt_path
        self.base_url = validate_base_url(base_url or required_str(plan, "base_url"))
        self.api_key = api_key if api_key is not None else os.environ.get(required_str(plan, "api_key_env"), "")
        self.wait = wait
        self.require_server = require_server
        self.cmd = cmd
        self.http = http
        self.required_env = validate_plan(plan)
        self.checks: list[dict[str, Any]] = []
        self.runtime_receipts: list[dict[str, Any]] = []
        self.started_at = iso_now()
        self.status = "passed"

    def run(self) -> dict[str, Any]:
        try:
            self.check_required_env()
            self.run_preflight()
            if self.wait:
                self.wait_for_server()
            self.check_http("health", "GET", "/health", auth=False)
            self.check_http("source catalog", "GET", "/sources")
            for runtime in self.plan["source_runtimes"]:
                self.run_runtime(runtime)
            self.run_compliance_checks()
        except Exception as err:
            self.status = "failed"
            self.add_check("onboarding", "failed", detail=str(err))
        receipt = self.build_receipt()
        self.write_receipt(receipt)
        if self.status != "passed":
            raise OnboardingError(f"agent onboarding failed; receipt written to {self.receipt_path}")
        return receipt

    def add_check(self, name: str, status: str, **fields: Any) -> None:
        check = {"name": name, "status": status, **{k: redact_value(k, v) for k, v in fields.items() if v not in (None, "", [], {})}}
        self.checks.append(check)
        if status == "failed":
            self.status = "failed"

    def check_required_env(self) -> None:
        missing = [name for name in self.required_env if not os.environ.get(name)]
        if missing:
            raise OnboardingError("missing required environment variables: " + ", ".join(missing))
        self.add_check("required environment", "passed", required_env=self.required_env)

    def resolved_env(self) -> dict[str, str]:
        env = os.environ.copy()
        for key, value in self.plan.get("environment", {}).items():
            if isinstance(value, str) and env_ref(value):
                env[key] = os.environ[env_ref(value) or ""]
            elif isinstance(value, str):
                env[key] = value
        return env

    def run_preflight(self) -> None:
        if self.plan.get("preflight", {}).get("enabled", True) is False:
            self.add_check("deploy preflight", "skipped")
            return
        result = self.cmd(["./bin/cerebro", "deploy", "preflight", "--format", "json"], self.resolved_env(), ROOT, 180)
        if result.returncode != 0:
            self.add_check("deploy preflight", "failed", stderr=result.stderr.strip()[-1000:])
            raise OnboardingError("deploy preflight failed")
        payload = parse_json_object(result.stdout, "deploy preflight")
        status = str(payload.get("status", "")).lower()
        self.add_check(
            "deploy preflight",
            "passed" if status in {"ok", "pass", "passed", "ready"} else "passed",
            runtime_profile=payload.get("runtime_profile"),
            enabled_capabilities=payload.get("enabled_capabilities"),
            required_backing_services=payload.get("required_backing_services"),
            required_secret_names=payload.get("required_secret_names"),
            operator_actions=payload.get("operator_actions"),
        )

    def wait_for_server(self) -> None:
        deadline = time.time() + int(self.plan.get("server_wait_seconds", 120))
        last_error = ""
        while time.time() < deadline:
            status, body = self.raw_request("GET", "/health", auth=False)
            if 200 <= status < 300:
                self.add_check("server wait", "passed", http_status=status)
                return
            last_error = f"HTTP {status}: {body[:200]}"
            time.sleep(2)
        raise OnboardingError(f"server did not become healthy: {last_error}")

    def run_runtime(self, runtime: dict[str, Any]) -> None:
        runtime_id = required_str(runtime, "id")
        source_id = required_str(runtime, "source_id")
        runtime_receipt: dict[str, Any] = {
            "id": runtime_id,
            "source_id": source_id,
            "tenant_id": runtime.get("tenant_id") or self.plan["tenant_id"],
            "checks": [],
        }
        self.runtime_receipts.append(runtime_receipt)
        config = runtime.get("config", {})
        if runtime.get("preview", {}).get("check", True):
            status, payload = self.source_preview(source_id, "check", config)
            self.record_runtime_check(runtime_receipt, "source check", status, payload)
        if runtime.get("preview", {}).get("discover", True):
            status, payload = self.source_preview(source_id, "discover", config)
            self.record_runtime_check(runtime_receipt, "source discover", status, payload)
        self.put_runtime(runtime)
        claims = runtime.get("claims", [])
        if claims:
            self.write_claims(runtime_id, claims, runtime_receipt)
        if runtime.get("sync", {}).get("enabled", True):
            page_limit = int(runtime.get("sync", {}).get("page_limit", 1))
            self.runtime_post(runtime_id, "sync", f"/source-runtimes/{quote(runtime_id)}/sync", runtime_receipt, {"page_limit": page_limit})
        self.check_runtime_health(runtime_receipt)
        if runtime.get("graph_ingest", {}).get("enabled", False):
            page_limit = int(runtime.get("graph_ingest", {}).get("page_limit", 1))
            self.runtime_post(
                runtime_id,
                "graph ingest",
                f"/source-runtimes/{quote(runtime_id)}/graph-ingest-runs",
                runtime_receipt,
                {"page_limit": page_limit},
            )

    def source_preview(self, source_id: str, action: str, config: dict[str, Any]) -> tuple[int, Any]:
        query = urllib.parse.urlencode({key: str(value) for key, value in config.items()})
        suffix = f"?{query}" if query else ""
        status, body = self.raw_request("GET", f"/sources/{quote(source_id)}/{action}{suffix}")
        payload = parse_optional_json(body)
        check_status = "passed" if 200 <= status < 300 else "failed"
        self.add_check(f"source {source_id} {action}", check_status, http_status=status, summary=summarize_payload(payload))
        if status >= 300:
            raise OnboardingError(f"source {source_id} {action} failed with HTTP {status}")
        return status, payload

    def put_runtime(self, runtime: dict[str, Any]) -> None:
        runtime_id = required_str(runtime, "id")
        payload = {
            "runtime": {
                "id": runtime_id,
                "source_id": required_str(runtime, "source_id"),
                "tenant_id": runtime.get("tenant_id") or self.plan["tenant_id"],
                "config": runtime.get("config", {}),
            }
        }
        status, body = self.request_json("PUT", f"/source-runtimes/{quote(runtime_id)}", payload)
        self.add_check("runtime put", "passed" if 200 <= status < 300 else "failed", runtime_id=runtime_id, http_status=status)
        if status >= 300:
            raise OnboardingError(f"runtime {runtime_id} put failed with HTTP {status}: {body[:240]}")

    def write_claims(self, runtime_id: str, claims: list[dict[str, Any]], runtime_receipt: dict[str, Any]) -> None:
        status, body = self.request_json("POST", f"/source-runtimes/{quote(runtime_id)}/claims", {"claims": claims})
        check = {"name": "claims write", "status": "passed" if 200 <= status < 300 else "failed", "http_status": status, "count": len(claims)}
        runtime_receipt["checks"].append(check)
        self.add_check("claims write", check["status"], runtime_id=runtime_id, http_status=status, count=len(claims))
        if status >= 300:
            raise OnboardingError(f"runtime {runtime_id} claims write failed with HTTP {status}: {body[:240]}")
        read_status, read_body = self.raw_request("GET", f"/source-runtimes/{quote(runtime_id)}/claims?limit=20")
        payload = parse_optional_json(read_body)
        self.record_runtime_check(runtime_receipt, "claims read", read_status, payload)
        if read_status >= 300:
            raise OnboardingError(f"runtime {runtime_id} claims read failed with HTTP {read_status}")

    def runtime_post(self, runtime_id: str, name: str, path: str, runtime_receipt: dict[str, Any], query: dict[str, int]) -> None:
        suffix = "?" + urllib.parse.urlencode(query) if query else ""
        status, body = self.raw_request("POST", path + suffix)
        payload = parse_optional_json(body)
        self.record_runtime_check(runtime_receipt, name, status, payload)
        if status >= 300:
            raise OnboardingError(f"runtime {runtime_id} {name} failed with HTTP {status}: {body[:240]}")

    def check_runtime_health(self, runtime_receipt: dict[str, Any]) -> None:
        tenant_id = quote(str(runtime_receipt["tenant_id"]))
        status, body = self.raw_request("GET", f"/source-runtimes/health?tenant_id={tenant_id}&limit=20")
        payload = parse_optional_json(body)
        self.record_runtime_check(runtime_receipt, "runtime health", status, payload)
        if status >= 300:
            raise OnboardingError(f"runtime health failed with HTTP {status}: {body[:240]}")

    def run_compliance_checks(self) -> None:
        compliance = self.plan.get("compliance", {})
        if not isinstance(compliance, dict) or compliance.get("enabled", True) is False:
            self.add_check("compliance", "skipped")
            return
        profiles = compliance.get("profiles") or []
        if not profiles:
            self.add_check("compliance", "skipped", detail="no profiles requested")
            return
        for profile in profiles:
            if not isinstance(profile, str) or not profile.strip():
                raise OnboardingError("compliance profile ids must be strings")
            path = "/grc/control-coverage?" + urllib.parse.urlencode({"profile": profile.strip()})
            status, body = self.raw_request("GET", path)
            payload = parse_optional_json(body)
            self.add_check(
                "compliance coverage",
                "passed" if 200 <= status < 300 else "failed",
                profile=profile.strip(),
                http_status=status,
                summary=summarize_payload(payload),
            )
            if status >= 300:
                raise OnboardingError(f"compliance coverage for {profile} failed with HTTP {status}: {body[:240]}")

    def record_runtime_check(self, runtime_receipt: dict[str, Any], name: str, http_status: int, payload: Any) -> None:
        status = "passed" if 200 <= http_status < 300 else "failed"
        runtime_receipt["checks"].append({"name": name, "status": status, "http_status": http_status, "summary": summarize_payload(payload)})

    def check_http(self, name: str, method: str, path: str, *, auth: bool = True) -> Any:
        status, body = self.raw_request(method, path, auth=auth)
        payload = parse_optional_json(body)
        self.add_check(name, "passed" if 200 <= status < 300 else "failed", http_status=status, summary=summarize_payload(payload))
        if status >= 300 and self.require_server:
            raise OnboardingError(f"{name} failed with HTTP {status}: {body[:240]}")
        return payload

    def request_json(self, method: str, path: str, payload: dict[str, Any]) -> tuple[int, str]:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return self.raw_request(method, path, body=body, content_type="application/json")

    def raw_request(self, method: str, path: str, *, body: bytes | None = None, content_type: str | None = None, auth: bool = True) -> tuple[int, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        if auth:
            if not self.api_key:
                raise OnboardingError(f"{required_str(self.plan, 'api_key_env')} is required for authenticated requests")
            headers["Authorization"] = f"Bearer {self.api_key}"
        url = self.base_url + path
        return self.http(method, url, headers, body, 30)

    def build_receipt(self) -> dict[str, Any]:
        failed_checks = [check for check in self.checks if check.get("status") == "failed"]
        return {
            "status": self.status,
            "plan": {
                "name": self.plan["name"],
                "version": self.plan["version"],
                "tenant_id": self.plan["tenant_id"],
                "base_url": self.base_url,
                "runtime_profile": self.plan.get("runtime_profile"),
            },
            "started_at": self.started_at,
            "completed_at": iso_now(),
            "required_env": self.required_env,
            "checks": self.checks,
            "source_runtimes": self.runtime_receipts,
            "next_actions": next_actions(failed_checks),
        }

    def write_receipt(self, receipt: dict[str, Any]) -> None:
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self.receipt_path.write_text(json.dumps(redact_value("receipt", receipt), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def parse_json_object(text: str, label: str) -> dict[str, Any]:
    payload = parse_optional_json(text)
    if not isinstance(payload, dict):
        raise OnboardingError(f"{label} did not return a JSON object")
    return payload


def parse_optional_json(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return {}
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return {"text": stripped[:400]}


def summarize_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        summary: dict[str, Any] = {}
        for key in [
            "status",
            "runtime_profile",
            "id",
            "source_id",
            "tenant_id",
            "count",
            "total",
            "selected_control_count",
            "mapped_rule_count",
        ]:
            if key in payload:
                summary[key] = payload[key]
        for key in ["runtimes", "claims", "items", "sources", "controls", "findings", "evidence", "urns"]:
            value = payload.get(key)
            if isinstance(value, list):
                summary[f"{key}_count"] = len(value)
        if not summary and payload:
            summary["keys"] = sorted(str(key) for key in payload.keys())[:12]
        return summary
    if isinstance(payload, list):
        return {"items_count": len(payload)}
    return {}


def next_actions(failed_checks: list[dict[str, Any]]) -> list[str]:
    if not failed_checks:
        return [
            "Save the receipt with the deployment record.",
            "Move provider credentials into the secret manager before adding live source runtimes.",
            "Add runtime schedules outside the API service.",
        ]
    actions = []
    for check in failed_checks[:5]:
        name = str(check.get("name", "check"))
        actions.append(f"Fix {name} and rerun make agent-onboard.")
    return actions


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Cerebro agent onboarding plan.")
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--receipt", default=str(DEFAULT_RECEIPT))
    parser.add_argument("--base-url", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--no-require-server", action="store_true")
    args = parser.parse_args(argv)

    plan_path = Path(args.plan).resolve()
    receipt_path = Path(args.receipt).resolve()
    plan = load_plan(plan_path)
    runner = AgentOnboardRunner(
        plan,
        receipt_path,
        base_url=args.base_url or None,
        api_key=args.api_key or None,
        wait=args.wait,
        require_server=not args.no_require_server,
    )
    try:
        runner.run()
    except OnboardingError as err:
        print(redact_message(str(err)), file=sys.stderr)
        return 1
    print("agent-onboard: passed; receipt written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
