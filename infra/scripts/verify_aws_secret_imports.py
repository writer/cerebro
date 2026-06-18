from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Any

try:
    from aws import source_runtime_scope
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/verify_aws_secret_imports.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws import source_runtime_scope


EXPECTED_STACK_ACCOUNTS = {
    "sec-dev": "944130631940",
    "go-prod": "837279440628",
}


@dataclass(frozen=True)
class SecretImport:
    env_name: str
    source: str
    prefix: str
    category: str

    @property
    def secret_id(self) -> str:
        prefix = self.prefix.strip("/")
        source = self.source.strip("/")
        return f"{prefix}/{source}" if prefix else source

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.env_name.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class SecretFinding:
    index: int
    category: str
    fingerprint: str
    reason: str


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_config(path: Path) -> dict[str, Any]:
    return source_runtime_scope.load_cerebro_config(path)


def _bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_ref(value: Any) -> str:
    return source_runtime_scope.env_ref(value)


def _source_runtime_env_refs(source_runtimes: list[Any]) -> list[str]:
    return source_runtime_scope.source_runtime_env_refs(source_runtimes)


def _secret_import(env_name: str, source: str | None, prefix: str, category: str) -> SecretImport:
    env = str(env_name).strip()
    src = str(source or env_name).strip()
    pfx = str(prefix or "").strip()
    if not env or not src:
        raise ValueError("secret imports must include non-empty env and source names")
    return SecretImport(env_name=env, source=src, prefix=pfx, category=category)


def _infisical_source_secret(secret_key: Any, infisical_prefix: str) -> SecretImport:
    if isinstance(secret_key, dict):
        name = str(secret_key.get("name", "")).strip()
        return _secret_import(
            name,
            str(secret_key.get("source") or name).strip(),
            str(secret_key.get("prefix") or infisical_prefix).strip(),
            "runtime-import",
        )
    name = str(secret_key).strip()
    return _secret_import(name, name, infisical_prefix, "runtime-import")


def expected_secret_imports(config: dict[str, Any], stack: str) -> list[SecretImport]:
    environment = str(config.get("environment") or stack).strip()
    external_prefix = str(config.get("externalSecretsPrefix") or f"cerebro-{environment}").strip()
    infisical_prefix = str(config.get("infisicalSecretsPrefix") or external_prefix).strip()
    is_production = "prod" in environment.lower()
    api_auth_enabled = _bool_value(config.get("apiAuthEnabled"), is_production)
    device_auth_enabled = _bool_value(config.get("deviceAuthEnabled"), False)
    mcp_oauth_enabled = _bool_value(config.get("mcpOauthEnabled"), False)

    imports = [
        _secret_import("CEREBRO_POSTGRES_DSN", None, external_prefix, "generated"),
        _secret_import("CEREBRO_NEO4J_URI", None, external_prefix, "generated"),
        _secret_import("CEREBRO_NEO4J_USERNAME", None, external_prefix, "generated"),
        _secret_import("CEREBRO_NEO4J_PASSWORD", None, external_prefix, "generated"),
    ]
    if api_auth_enabled:
        imports.append(_secret_import("CEREBRO_API_KEYS", None, external_prefix, "generated"))
        api_credentials_secret = str(config.get("apiCredentialsSecretName") or "CEREBRO_API_CREDENTIALS_JSON").strip()
        imports.append(_secret_import("CEREBRO_API_CREDENTIALS_JSON", api_credentials_secret, external_prefix, "generated"))
        capability_secret = str(config.get("capabilityTokenSecretName") or "CEREBRO_CAPABILITY_TOKEN_SECRETS").strip()
        imports.append(_secret_import("CEREBRO_CAPABILITY_TOKEN_SECRETS", capability_secret, infisical_prefix, "runtime-import"))
    if device_auth_enabled:
        signing_secret = str(config.get("deviceAuthSigningKeysSecretName") or "").strip()
        imports.append(_secret_import("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", signing_secret, infisical_prefix, "runtime-import"))
    if mcp_oauth_enabled:
        client_id_secret = str(config.get("mcpOauthUpstreamClientIdSecretName") or "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID").strip()
        client_secret = str(config.get("mcpOauthUpstreamClientSecretName") or "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET").strip()
        imports.append(_secret_import("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", client_id_secret, infisical_prefix, "runtime-import"))
        imports.append(_secret_import("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", client_secret, infisical_prefix, "runtime-import"))
    if _bool_value(config.get("otelCollectorEnabled"), False):
        collector_secret = str(config.get("otelCollectorConfigSecretName") or "CEREBRO_OTEL_COLLECTOR_CONFIG").strip()
        collector_prefix = str(config.get("otelCollectorConfigSecretPrefix") or infisical_prefix).strip()
        imports.append(_secret_import("AOT_CONFIG_CONTENT", collector_secret, collector_prefix, "otel-collector"))
    imports.extend(_infisical_source_secret(secret_key, infisical_prefix) for secret_key in (config.get("sourceSecretKeys") or []))

    openrouter_secret = str(config.get("openrouterApiKeySecret") or "").strip()
    if openrouter_secret:
        imports.append(_secret_import("CEREBRO_OPENROUTER_API_KEY", openrouter_secret, external_prefix, "runtime-import"))

    if _bool_value(config.get("webEnabled"), False):
        web_secret = str(config.get("webApiKeySecretName") or "CEREBRO_API_KEYS").strip()
        imports.append(_secret_import("CEREBRO_API_KEYS", web_secret, external_prefix, "web"))

    seen: set[str] = set()
    unique: list[SecretImport] = []
    for item in imports:
        if item.secret_id in seen:
            continue
        seen.add(item.secret_id)
        unique.append(item)
    return unique


def missing_env_ref_findings(config: dict[str, Any], imports: list[SecretImport]) -> list[SecretFinding]:
    declared = {item.env_name for item in imports}
    findings = []
    for index, env_name in enumerate(_source_runtime_env_refs(config.get("sourceRuntimes") or []), start=1):
        if env_name not in declared:
            findings.append(
                SecretFinding(
                    index=index,
                    category="runtime-env-ref",
                    fingerprint=hashlib.sha256(env_name.encode("utf-8")).hexdigest()[:12],
                    reason="undeclared",
                )
            )
    return findings


def _aws_json(args: list[str], region: str) -> tuple[int, dict[str, Any] | None, str]:
    command = ["aws", *args, "--region", region, "--output", "json"]
    completed = subprocess.run(command, text=True, capture_output=True)
    payload = None
    if completed.stdout.strip():
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            payload = None
    return completed.returncode, payload, (completed.stderr or completed.stdout or "").strip()


def _caller_account(region: str) -> str:
    code, payload, detail = _aws_json(["sts", "get-caller-identity"], region)
    if code != 0 or not isinstance(payload, dict):
        raise RuntimeError(f"could not determine AWS caller identity: {detail}")
    return str(payload.get("Account") or "")


def _verify_stack_account(stack: str, region: str) -> None:
    expected = EXPECTED_STACK_ACCOUNTS.get(stack)
    if not expected:
        return
    actual = _caller_account(region)
    if actual != expected:
        raise RuntimeError(f"{stack} guard is authenticated to unexpected AWS account")


def verify_secret_imports(imports: list[SecretImport], region: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for index, item in enumerate(imports, start=1):
        code, payload, detail = _aws_json(["secretsmanager", "describe-secret", "--secret-id", item.secret_id], region)
        if code != 0:
            reason = "missing" if "ResourceNotFoundException" in detail else "describe-failed"
            findings.append(SecretFinding(index, item.category, item.fingerprint, reason))
            continue
        if not isinstance(payload, dict):
            findings.append(SecretFinding(index, item.category, item.fingerprint, "invalid-response"))
            continue
        if payload.get("DeletedDate"):
            findings.append(SecretFinding(index, item.category, item.fingerprint, "pending-delete"))
            continue
        versions = payload.get("VersionIdsToStages") or {}
        if not any("AWSCURRENT" in stages for stages in versions.values() if isinstance(stages, list)):
            findings.append(SecretFinding(index, item.category, item.fingerprint, "no-current-version"))
    return findings


def _print_findings(findings: list[SecretFinding]) -> None:
    print("index\tcategory\tfingerprint\treason")
    for finding in findings:
        print(f"{finding.index}\t{finding.category}\t{finding.fingerprint}\t{finding.reason}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify AWS Secrets Manager imports needed by the ECS task before deployment.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    _verify_stack_account(stack, args.region)
    imports = expected_secret_imports(config, stack)
    findings = [*missing_env_ref_findings(config, imports), *verify_secret_imports(imports, args.region)]
    if findings:
        print(f"{stack} AWS secret import guard failed for {len(findings)} import(s).")
        _print_findings(findings)
        return 1
    print(f"{stack} AWS secret import guard passed for {len(imports)} import(s).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
