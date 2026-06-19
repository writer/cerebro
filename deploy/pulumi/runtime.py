from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

import pulumi


_NAME_RE = re.compile(r"[^a-z0-9-]+")


@dataclass(frozen=True)
class SecretEnv:
    name: str
    value: pulumi.Output[str]


@dataclass(frozen=True)
class CerebroRuntimeConfig:
    cloud: str
    name: str
    image: str
    container_port: int
    min_replicas: int
    max_replicas: int
    cpu: float
    memory_mib: int
    shutdown_timeout: str
    public_origin: str
    trusted_proxy_cidrs: str
    trusted_proxy_count: int
    api_auth_enabled: bool
    allowed_tenants: str
    extra_env: Mapping[str, str]
    extra_secrets: Mapping[str, pulumi.Output[str]]
    api_keys: pulumi.Output[str] | None
    api_credentials_json: pulumi.Output[str] | None
    postgres_dsn: pulumi.Output[str] | None
    jetstream_url: pulumi.Output[str] | None
    neo4j_uri: pulumi.Output[str] | None
    neo4j_username: pulumi.Output[str] | None
    neo4j_password: pulumi.Output[str] | None
    connector_credential_key: pulumi.Output[str] | None
    connector_transit_private_key: pulumi.Output[str] | None
    capability_token_secrets: pulumi.Output[str] | None
    aws_region: str
    aws_availability_zones: list[str]
    aws_vpc_cidr: str
    aws_public_subnet_cidrs: list[str]
    aws_assign_public_ip: bool
    aws_skip_credentials_validation: bool
    gcp_project: str
    gcp_region: str
    gcp_ingress: str
    gcp_allow_unauthenticated: bool
    azure_location: str
    azure_resource_group_name: str
    azure_external_ingress: bool

    @classmethod
    def from_pulumi(cls) -> "CerebroRuntimeConfig":
        cfg = pulumi.Config("cerebro")
        name = _slug(cfg.get("name") or "cerebro")
        cloud = (cfg.require("cloud")).strip().lower()
        container_port = _positive_int(cfg.get_int("containerPort"), 8080, "containerPort")
        min_replicas = _positive_int(cfg.get_int("minReplicas"), 1, "minReplicas", allow_zero=True)
        max_replicas = _positive_int(cfg.get_int("maxReplicas"), 1, "maxReplicas")
        if max_replicas < min_replicas:
            raise ValueError("cerebro:maxReplicas must be greater than or equal to cerebro:minReplicas")

        cpu = cfg.get_float("cpu") or 1
        if cpu <= 0:
            raise ValueError("cerebro:cpu must be positive")
        memory_mib = _positive_int(cfg.get_int("memoryMiB"), 2048, "memoryMiB")

        extra_env = cfg.get_object("extraEnv") or {}
        if not isinstance(extra_env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in extra_env.items()):
            raise ValueError("cerebro:extraEnv must be an object with string keys and string values")

        extra_secret_values = cfg.get_secret_object("extraSecrets")
        extra_secrets: dict[str, pulumi.Output[str]] = {}
        if extra_secret_values is not None:
            if not isinstance(extra_secret_values, dict):
                raise ValueError("cerebro:extraSecrets must be an object with string keys and values")
            for key, value in extra_secret_values.items():
                if not isinstance(key, str):
                    raise ValueError("cerebro:extraSecrets keys must be strings")
                extra_secrets[key] = pulumi.Output.secret(value)

        return cls(
            cloud=cloud,
            name=name,
            image=cfg.require("image"),
            container_port=container_port,
            min_replicas=min_replicas,
            max_replicas=max_replicas,
            cpu=cpu,
            memory_mib=memory_mib,
            shutdown_timeout=cfg.get("shutdownTimeout") or "10s",
            public_origin=cfg.get("publicOrigin") or "",
            trusted_proxy_cidrs=cfg.get("trustedProxyCIDRs") or "",
            trusted_proxy_count=_positive_int(cfg.get_int("trustedProxyCount"), 1, "trustedProxyCount", allow_zero=True),
            api_auth_enabled=_config_bool(cfg, "apiAuthEnabled", True),
            allowed_tenants=cfg.get("allowedTenants") or "",
            extra_env=extra_env,
            extra_secrets=extra_secrets,
            api_keys=cfg.get_secret("apiKeys"),
            api_credentials_json=cfg.get_secret("apiCredentialsJson"),
            postgres_dsn=cfg.get_secret("postgresDsn"),
            jetstream_url=cfg.get_secret("jetstreamUrl"),
            neo4j_uri=cfg.get_secret("neo4jUri"),
            neo4j_username=cfg.get_secret("neo4jUsername"),
            neo4j_password=cfg.get_secret("neo4jPassword"),
            connector_credential_key=cfg.get_secret("connectorCredentialKey"),
            connector_transit_private_key=cfg.get_secret("connectorTransitPrivateKey"),
            capability_token_secrets=cfg.get_secret("capabilityTokenSecrets"),
            aws_region=cfg.get("awsRegion") or "us-east-1",
            aws_availability_zones=list(cfg.get_object("awsAvailabilityZones") or []),
            aws_vpc_cidr=cfg.get("awsVpcCidr") or "10.42.0.0/16",
            aws_public_subnet_cidrs=list(cfg.get_object("awsPublicSubnetCidrs") or ["10.42.0.0/24", "10.42.1.0/24"]),
            aws_assign_public_ip=_config_bool(cfg, "awsAssignPublicIp", True),
            aws_skip_credentials_validation=_config_bool(cfg, "awsSkipCredentialsValidation", True),
            gcp_project=cfg.get("gcpProject") or "",
            gcp_region=cfg.get("gcpRegion") or "us-central1",
            gcp_ingress=cfg.get("gcpIngress") or "INGRESS_TRAFFIC_ALL",
            gcp_allow_unauthenticated=_config_bool(cfg, "gcpAllowUnauthenticated", True),
            azure_location=cfg.get("azureLocation") or "eastus",
            azure_resource_group_name=cfg.get("azureResourceGroupName") or f"{name}-rg",
            azure_external_ingress=_config_bool(cfg, "azureExternalIngress", True),
        )

    def plain_env(self) -> dict[str, pulumi.Input[str]]:
        env: dict[str, pulumi.Input[str]] = {
            "CEREBRO_HTTP_ADDR": f":{self.container_port}",
            "CEREBRO_SHUTDOWN_TIMEOUT": self.shutdown_timeout,
            "CEREBRO_API_AUTH_ENABLED": _bool_env(self.api_auth_enabled),
            "CEREBRO_TRUSTED_PROXY_COUNT": str(self.trusted_proxy_count),
        }
        if self.public_origin:
            env["CEREBRO_PUBLIC_ORIGIN"] = self.public_origin
        if self.trusted_proxy_cidrs:
            env["CEREBRO_TRUSTED_PROXY_CIDRS"] = self.trusted_proxy_cidrs
        if self.allowed_tenants:
            env["CEREBRO_ALLOWED_TENANTS"] = self.allowed_tenants
        if self.postgres_dsn:
            env["CEREBRO_STATE_STORE_DRIVER"] = "postgres"
        if self.jetstream_url:
            env["CEREBRO_APPEND_LOG_DRIVER"] = "jetstream"
            env["CEREBRO_JETSTREAM_SUBJECT_PREFIX"] = "events"
        if self.neo4j_uri:
            env["CEREBRO_GRAPH_STORE_DRIVER"] = "neo4j"
        env.update(self.extra_env)
        return env

    def secret_env(self) -> list[SecretEnv]:
        pairs = [
            ("CEREBRO_API_KEYS", self.api_keys),
            ("CEREBRO_API_CREDENTIALS_JSON", self.api_credentials_json),
            ("CEREBRO_POSTGRES_DSN", self.postgres_dsn),
            ("CEREBRO_JETSTREAM_URL", self.jetstream_url),
            ("CEREBRO_NEO4J_URI", self.neo4j_uri),
            ("CEREBRO_NEO4J_USERNAME", self.neo4j_username),
            ("CEREBRO_NEO4J_PASSWORD", self.neo4j_password),
            ("CEREBRO_CONNECTOR_CREDENTIAL_KEY", self.connector_credential_key),
            ("CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY", self.connector_transit_private_key),
            ("CEREBRO_CAPABILITY_TOKEN_SECRETS", self.capability_token_secrets),
        ]
        secrets = [SecretEnv(name, value) for name, value in pairs if value is not None]
        secrets.extend(SecretEnv(name, value) for name, value in self.extra_secrets.items())
        return secrets


def normalized_secret_name(name: str) -> str:
    return _slug(name.lower().replace("_", "-"))


def aws_cpu_units(vcpu: float) -> str:
    return str(int(vcpu * 1024))


def _config_bool(config: pulumi.Config, key: str, default: bool) -> bool:
    value = config.get_bool(key)
    return default if value is None else value


def _positive_int(value: int | None, default: int, key: str, *, allow_zero: bool = False) -> int:
    resolved = default if value is None else value
    if resolved < 0 or (resolved == 0 and not allow_zero):
        raise ValueError(f"cerebro:{key} must be {'non-negative' if allow_zero else 'positive'}")
    return resolved


def _slug(value: str) -> str:
    slug = _NAME_RE.sub("-", value.strip().lower()).strip("-")
    if not slug:
        raise ValueError("resource name must contain at least one lowercase letter or number")
    return slug


def _bool_env(value: bool) -> str:
    return "true" if value else "false"
