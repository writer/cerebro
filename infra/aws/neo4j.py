"""Neo4j Aura and runtime secret resources."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from typing import Any

import pulumi
import pulumi.dynamic as dynamic
import pulumi_aws as aws
import pulumi_random as random


PATCHABLE_INSTANCE_KEYS = ("name", "memory")
REPLACEMENT_INSTANCE_KEYS = (
    "project_id",
    "cloud_provider",
    "region",
    "version",
    "type",
    "vector_optimized",
    "existing_instance_id",
)
STATE_ONLY_INSTANCE_KEYS = ("client_id", "client_secret", "timeout_seconds")

API_CREDENTIAL_REQUIRED_FIELDS = frozenset(
    {"credential_id", "client_id", "principal", "tenant_id", "key_sha256"}
)
API_CREDENTIAL_OPTIONAL_FIELDS = frozenset({"kind", "name", "scopes"})
API_CREDENTIAL_ALLOWED_FIELDS = API_CREDENTIAL_REQUIRED_FIELDS | API_CREDENTIAL_OPTIONAL_FIELDS


def _api_credentials_json_from_api_keys(raw: str) -> str:
    credentials = []
    for index, item in enumerate(str(raw or "").split(","), start=1):
        parts = [part.strip() for part in item.strip().split(":")]
        token = parts[0] if parts else ""
        if not token:
            continue
        principal = parts[1] if len(parts) > 1 and parts[1] else f"legacy-api-key-{index}"
        tenant_id = parts[2] if len(parts) > 2 and parts[2] else "writer"
        credentials.append(
            {
                "credential_id": f"legacy-api-key-{index}",
                "client_id": "legacy-api-key",
                "principal": principal,
                "tenant_id": tenant_id,
                "key_sha256": hashlib.sha256(token.encode()).hexdigest(),
            }
        )
    return json.dumps(credentials, separators=(",", ":"), sort_keys=True)


def _normalize_api_credentials_json(configured: str) -> str:
    try:
        parsed = json.loads(configured)
    except json.JSONDecodeError as error:
        raise ValueError("apiCredentialsJson must be valid JSON") from error

    if not isinstance(parsed, list) or not parsed:
        raise ValueError("apiCredentialsJson must be a non-empty JSON array")

    normalized: list[dict[str, Any]] = []
    credential_ids: set[str] = set()
    key_digests: set[str] = set()
    for index, entry in enumerate(parsed):
        label = f"apiCredentialsJson[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object")

        fields = set(entry)
        missing_fields = sorted(API_CREDENTIAL_REQUIRED_FIELDS - fields)
        if missing_fields:
            raise ValueError(f"{label} is missing required fields: {', '.join(missing_fields)}")
        unsupported_fields = sorted(fields - API_CREDENTIAL_ALLOWED_FIELDS)
        if unsupported_fields:
            raise ValueError(f"{label} has unsupported fields: {', '.join(unsupported_fields)}")

        credential: dict[str, Any] = {}
        for field in sorted(API_CREDENTIAL_REQUIRED_FIELDS | {"kind", "name"}):
            if field not in entry:
                continue
            value = entry[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label}.{field} must be a non-empty string")
            credential[field] = value.strip()

        digest = credential["key_sha256"].lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError(f"{label}.key_sha256 must be a 64-character hexadecimal SHA-256 digest")
        credential["key_sha256"] = digest

        if "scopes" in entry:
            scopes = entry["scopes"]
            if not isinstance(scopes, list) or not scopes:
                raise ValueError(f"{label}.scopes must be a non-empty array of strings")
            normalized_scopes: list[str] = []
            for scope_index, scope in enumerate(scopes):
                if not isinstance(scope, str) or not scope.strip():
                    raise ValueError(f"{label}.scopes[{scope_index}] must be a non-empty string")
                normalized_scopes.append(scope.strip())
            if len(normalized_scopes) != len(set(normalized_scopes)):
                raise ValueError(f"{label}.scopes must not contain duplicates")
            credential["scopes"] = sorted(normalized_scopes)

        credential_id = credential["credential_id"]
        if credential_id in credential_ids:
            raise ValueError(f"apiCredentialsJson contains duplicate credential_id at index {index}")
        credential_ids.add(credential_id)
        if digest in key_digests:
            raise ValueError(f"apiCredentialsJson contains duplicate key_sha256 at index {index}")
        key_digests.add(digest)
        normalized.append(credential)

    normalized.sort(key=lambda credential: credential["credential_id"])
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


def _api_credentials_json(legacy_derived: str, configured: str | None) -> str:
    if configured is not None and configured.strip():
        return _normalize_api_credentials_json(configured.strip())
    return legacy_derived


class Neo4jAuraProvider(dynamic.ResourceProvider):
    def _token(self, client_id: str, client_secret: str) -> str:
        request = urllib.request.Request(
            "https://api.neo4j.io/oauth/token",
            data=b"grant_type=client_credentials",
            method="POST",
        )
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("User-Agent", "CerebroPulumi/1")
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())["access_token"]

    def _request(
        self,
        method: str,
        path: str,
        client_id: str,
        client_secret: str,
        body: dict[str, Any] | None = None,
        expected_status: int | tuple[int, ...] = 200,
    ) -> dict[str, Any]:
        token = self._token(client_id, client_secret)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"https://api.neo4j.io/v1/{path}",
            data=data,
            method=method,
        )
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "CerebroPulumi/1")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode()
                expected_statuses = (expected_status,) if isinstance(expected_status, int) else expected_status
                if response.status not in expected_statuses:
                    raise RuntimeError(f"Neo4j Aura returned HTTP {response.status}: {response_body}")
                return json.loads(response_body) if response_body else {}
        except urllib.error.HTTPError as error:
            response_body = error.read().decode()
            raise RuntimeError(f"Neo4j Aura returned HTTP {error.code}: {response_body}") from error

    def _instance(self, instance_id: str, props: dict[str, Any]) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"instances/{instance_id}",
            props["client_id"],
            props["client_secret"],
        )
        data = response["data"]
        return {
            **props,
            "instance_id": data["id"],
            "name": data["name"],
            "project_id": data["tenant_id"],
            "cloud_provider": data["cloud_provider"],
            "region": data["region"],
            "memory": data["memory"],
            "version": data.get("version", props.get("version")),
            "type": data["type"],
            "vector_optimized": data.get("vector_optimized", props.get("vector_optimized")),
            "connection_url": data["connection_url"],
            "username": props.get("username") or "neo4j",
            "password": props.get("password"),
            "status": data["status"],
        }

    def create(self, props: dict[str, Any]) -> dynamic.CreateResult:
        if props.get("existing_instance_id"):
            outs = self._instance(props["existing_instance_id"], props)
            return dynamic.CreateResult(id_=props["existing_instance_id"], outs=outs)

        response = self._request(
            "POST",
            "instances",
            props["client_id"],
            props["client_secret"],
            body={
                "name": props["name"],
                "tenant_id": props["project_id"],
                "cloud_provider": props["cloud_provider"],
                "region": props["region"],
                "memory": props["memory"],
                "version": props["version"],
                "type": props["type"],
                "vector_optimized": props["vector_optimized"],
            },
            expected_status=202,
        )
        data = response["data"]
        props = {
            **props,
            "instance_id": data["id"],
            "connection_url": data["connection_url"],
            "username": data["username"],
            "password": data["password"],
        }
        deadline = time.time() + int(props.get("timeout_seconds") or 900)
        while time.time() < deadline:
            outs = self._instance(data["id"], props)
            if outs["status"] == "running":
                return dynamic.CreateResult(id_=data["id"], outs=outs)
            time.sleep(10)
        raise TimeoutError(f"Timed out waiting for Neo4j Aura instance {data['id']} to run")

    def read(self, id_: str, props: dict[str, Any]) -> dynamic.ReadResult:
        return dynamic.ReadResult(id_=id_, outs=self._instance(id_, props))

    def diff(self, id_: str, olds: dict[str, Any], news: dict[str, Any]) -> dynamic.DiffResult:
        replaces = [key for key in REPLACEMENT_INSTANCE_KEYS if olds.get(key) != news.get(key)]
        changes = bool(replaces) or any(
            olds.get(key) != news.get(key)
            for key in (*PATCHABLE_INSTANCE_KEYS, *STATE_ONLY_INSTANCE_KEYS)
        )
        return dynamic.DiffResult(changes=changes, replaces=replaces)

    def update(self, id_: str, olds: dict[str, Any], news: dict[str, Any]) -> dynamic.UpdateResult:
        patch: dict[str, Any] = {}
        for key in PATCHABLE_INSTANCE_KEYS:
            if olds.get(key) != news.get(key):
                patch[key] = news[key]
        if patch:
            self._request(
                "PATCH",
                f"instances/{id_}",
                news["client_id"],
                news["client_secret"],
                body=patch,
                expected_status=(200, 202),
            )
        return dynamic.UpdateResult(outs=self._instance(id_, news))

    def delete(self, id_: str, props: dict[str, Any]) -> None:
        self._request(
            "DELETE",
            f"instances/{id_}",
            props["client_id"],
            props["client_secret"],
            expected_status=202,
        )


class Neo4jAuraInstance(dynamic.Resource):
    instance_id: pulumi.Output[str]
    connection_url: pulumi.Output[str]
    username: pulumi.Output[str]
    password: pulumi.Output[str]
    status: pulumi.Output[str]

    def __init__(
        self,
        name: str,
        props: dict[str, Any],
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__(Neo4jAuraProvider(), name, props, opts)


def create_aura_instance(
    name: str,
    client_id: pulumi.Input[str],
    client_secret: pulumi.Input[str],
    project_id: pulumi.Input[str],
    instance_name: str,
    cloud_provider: str,
    region: str,
    memory: str,
    version: str,
    instance_type: str,
    vector_optimized: bool,
    import_instance_id: str = "",
) -> Neo4jAuraInstance:
    return Neo4jAuraInstance(
        f"{name}-neo4j",
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "project_id": project_id,
            "name": instance_name,
            "cloud_provider": cloud_provider,
            "region": region,
            "memory": memory,
            "version": version,
            "type": instance_type,
            "vector_optimized": vector_optimized,
            "existing_instance_id": import_instance_id,
            "timeout_seconds": 900,
            "instance_id": import_instance_id or None,
            "connection_url": None,
            "username": None,
            "password": None,
            "status": None,
        },
        pulumi.ResourceOptions(
            protect=True,
            additional_secret_outputs=["password"],
        ),
    )


def create_runtime_secrets(
    name: str,
    external_secrets_prefix: str,
    neo4j_uri: pulumi.Input[str],
    neo4j_password: pulumi.Input[str],
    api_keys: pulumi.Input[str] | None,
    api_credentials_json: pulumi.Input[str] | None = None,
    kms_key_id: pulumi.Input[str] | None = None,
    import_arns: dict[str, str] | None = None,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    import_arns = import_arns or {}

    if api_keys is None:
        # The application rejects any CEREBRO_API_KEYS entry that omits a
        # tenant_id once CEREBRO_ALLOWED_TENANTS is configured. A generated key
        # must therefore carry the same principal/tenant that
        # _api_credentials_json_from_api_keys assigns by default
        # (legacy-api-key-1 / writer) so a tenant-scoped stack can bootstrap
        # without an explicitly supplied apiKeys value.
        api_keys = random.RandomPassword(
            f"{name}-api-key",
            length=48,
            special=False,
        ).result.apply(lambda token: f"{token}:legacy-api-key-1:writer")

    legacy_api_credentials_json = pulumi.Output.secret(api_keys).apply(
        _api_credentials_json_from_api_keys
    )
    if api_credentials_json is None:
        resolved_api_credentials_json = legacy_api_credentials_json
    else:
        resolved_api_credentials_json = pulumi.Output.all(
            legacy_api_credentials_json, api_credentials_json
        ).apply(lambda values: _api_credentials_json(values[0], values[1]))
    resolved_api_credentials_json = pulumi.Output.secret(resolved_api_credentials_json)
    secret_values = {
        "CEREBRO_NEO4J_URI": neo4j_uri,
        "CEREBRO_NEO4J_USERNAME": "neo4j",
        "CEREBRO_NEO4J_PASSWORD": neo4j_password,
        "CEREBRO_API_KEYS": api_keys,
        "CEREBRO_API_CREDENTIALS_JSON": resolved_api_credentials_json,
    }
    secrets = {}
    versions = []
    for key, value in secret_values.items():
        secret = aws.secretsmanager.Secret(
            f"{name}-{key.lower().replace('_', '-')}",
            name=f"{external_secrets_prefix}/{key}",
            kms_key_id=kms_key_id,
            recovery_window_in_days=0,
            tags=tags,
            opts=pulumi.ResourceOptions(import_=import_arns.get(key) or None),
        )
        version = aws.secretsmanager.SecretVersion(
            f"{name}-{key.lower().replace('_', '-')}-version",
            secret_id=secret.id,
            secret_string=value,
        )
        secrets[key] = secret
        versions.append(version)

    return {
        "secrets": secrets,
        "versions": versions,
        "api_keys": api_keys,
    }
