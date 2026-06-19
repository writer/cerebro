from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

import pulumi


_NAME_RE = re.compile(r"[^a-z0-9-]+")
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass(frozen=True)
class SecretEnv:
    name: str
    value: pulumi.Output[str]


@dataclass(frozen=True)
class ExistingSecretRef:
    name: str
    aws_arn: str = ""
    gcp_secret: str = ""
    gcp_version: str = "latest"
    azure_key_vault_url: str = ""
    azure_secret_name: str = ""


@dataclass(frozen=True)
class ScheduledJob:
    name: str
    schedule: str
    command: list[str]
    time_zone: str = "UTC"
    enabled: bool = True
    description: str = ""
    timeout_seconds: int = 900
    retry_limit: int = 1
    cpu: float | None = None
    memory_mib: int | None = None


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
    deployment_profile: str
    allow_unsafe_production: bool
    unsafe_production_justification: str
    edge_auth_managed: bool
    public_origin: str
    trusted_proxy_cidrs: str
    trusted_proxy_count: int
    ingress_cidrs: list[str]
    api_auth_enabled: bool
    allowed_tenants: str
    extra_env: Mapping[str, str]
    extra_secrets: Mapping[str, pulumi.Output[str]]
    existing_secret_refs: list[ExistingSecretRef]
    scheduled_jobs: list[ScheduledJob]
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
    aws_private_subnet_cidrs: list[str]
    aws_assign_public_ip: bool
    aws_enable_private_subnets: bool
    aws_enable_nat_gateway: bool
    aws_certificate_arn: str
    aws_redirect_http_to_https: bool
    aws_log_retention_days: int
    aws_skip_credentials_validation: bool
    gcp_project: str
    gcp_region: str
    gcp_ingress: str
    gcp_allow_unauthenticated: bool
    gcp_service_account_email: str
    gcp_scheduler_service_account_email: str
    gcp_vpc_connector: str
    azure_location: str
    azure_resource_group_name: str
    azure_external_ingress: bool
    azure_enable_system_identity: bool

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

        deployment_profile = (cfg.get("deploymentProfile") or "preview").strip().lower()
        if deployment_profile not in {"preview", "production"}:
            raise ValueError("cerebro:deploymentProfile must be preview or production")

        ingress_cidrs = _string_list(cfg.get_object("ingressCidrs"), ["0.0.0.0/0"], "ingressCidrs")

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
            deployment_profile=deployment_profile,
            allow_unsafe_production=_config_bool(cfg, "allowUnsafeProduction", False),
            unsafe_production_justification=cfg.get("unsafeProductionJustification") or "",
            edge_auth_managed=_config_bool(cfg, "edgeAuthManaged", False),
            public_origin=cfg.get("publicOrigin") or "",
            trusted_proxy_cidrs=cfg.get("trustedProxyCIDRs") or "",
            trusted_proxy_count=_positive_int(cfg.get_int("trustedProxyCount"), 1, "trustedProxyCount", allow_zero=True),
            ingress_cidrs=ingress_cidrs,
            api_auth_enabled=_config_bool(cfg, "apiAuthEnabled", True),
            allowed_tenants=cfg.get("allowedTenants") or "",
            extra_env=extra_env,
            extra_secrets=extra_secrets,
            existing_secret_refs=_existing_secret_refs(cfg.get_object("existingSecretRefs")),
            scheduled_jobs=_scheduled_jobs(cfg.get_object("scheduledJobs")),
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
            aws_availability_zones=_string_list(cfg.get_object("awsAvailabilityZones"), [], "awsAvailabilityZones"),
            aws_vpc_cidr=cfg.get("awsVpcCidr") or "10.42.0.0/16",
            aws_public_subnet_cidrs=_string_list(
                cfg.get_object("awsPublicSubnetCidrs"),
                ["10.42.0.0/24", "10.42.1.0/24"],
                "awsPublicSubnetCidrs",
            ),
            aws_private_subnet_cidrs=_string_list(
                cfg.get_object("awsPrivateSubnetCidrs"),
                ["10.42.100.0/24", "10.42.101.0/24"],
                "awsPrivateSubnetCidrs",
            ),
            aws_assign_public_ip=_config_bool(cfg, "awsAssignPublicIp", True),
            aws_enable_private_subnets=_config_bool(cfg, "awsEnablePrivateSubnets", False),
            aws_enable_nat_gateway=_config_bool(cfg, "awsEnableNatGateway", False),
            aws_certificate_arn=cfg.get("awsCertificateArn") or "",
            aws_redirect_http_to_https=_config_bool(cfg, "awsRedirectHttpToHttps", True),
            aws_log_retention_days=_positive_int(cfg.get_int("awsLogRetentionDays"), 30, "awsLogRetentionDays"),
            aws_skip_credentials_validation=_config_bool(cfg, "awsSkipCredentialsValidation", True),
            gcp_project=cfg.get("gcpProject") or "",
            gcp_region=cfg.get("gcpRegion") or "us-central1",
            gcp_ingress=cfg.get("gcpIngress") or "INGRESS_TRAFFIC_ALL",
            gcp_allow_unauthenticated=_config_bool(cfg, "gcpAllowUnauthenticated", True),
            gcp_service_account_email=cfg.get("gcpServiceAccountEmail") or "",
            gcp_scheduler_service_account_email=cfg.get("gcpSchedulerServiceAccountEmail") or "",
            gcp_vpc_connector=cfg.get("gcpVpcConnector") or "",
            azure_location=cfg.get("azureLocation") or "eastus",
            azure_resource_group_name=cfg.get("azureResourceGroupName") or f"{name}-rg",
            azure_external_ingress=_config_bool(cfg, "azureExternalIngress", True),
            azure_enable_system_identity=_config_bool(cfg, "azureEnableSystemIdentity", False),
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
        if self.has_secret("CEREBRO_POSTGRES_DSN"):
            env["CEREBRO_STATE_STORE_DRIVER"] = "postgres"
        if self.has_secret("CEREBRO_JETSTREAM_URL"):
            env["CEREBRO_APPEND_LOG_DRIVER"] = "jetstream"
            env["CEREBRO_JETSTREAM_SUBJECT_PREFIX"] = "events"
        if self.has_secret("CEREBRO_NEO4J_URI"):
            env["CEREBRO_GRAPH_STORE_DRIVER"] = "neo4j"
        env.update(self.extra_env)
        return env

    def created_secret_env(self) -> list[SecretEnv]:
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

    def secret_env(self) -> list[SecretEnv]:
        return self.created_secret_env()

    def all_secret_names(self) -> set[str]:
        return {secret.name for secret in self.created_secret_env()} | {ref.name for ref in self.existing_secret_refs}

    def has_secret(self, name: str) -> bool:
        return name in self.all_secret_names()

    def validate_guardrails(self) -> None:
        risks = self.production_risks()
        if not risks:
            return
        if self.deployment_profile == "production":
            if not self.allow_unsafe_production:
                joined = "\n- ".join(risks)
                raise ValueError(
                    "unsafe production deployment config; either fix these settings or set "
                    "cerebro:allowUnsafeProduction=true with cerebro:unsafeProductionJustification:\n- "
                    f"{joined}"
                )
            if not self.unsafe_production_justification.strip():
                raise ValueError(
                    "cerebro:unsafeProductionJustification is required when "
                    "cerebro:allowUnsafeProduction=true"
                )
            for risk in risks:
                pulumi.log.warn(f"unsafe production override accepted: {risk}")
            return
        for risk in risks:
            pulumi.log.warn(f"preview-only deployment risk: {risk}")

    def production_risks(self) -> list[str]:
        risks: list[str] = []
        if not self.api_auth_enabled and not self.edge_auth_managed:
            risks.append("API authentication is disabled and no authenticated edge is declared")
        if _image_uses_latest(self.image):
            risks.append("container image uses the mutable latest tag")
        if self.public_origin and not self.public_origin.startswith("https://"):
            risks.append("public origin is not HTTPS")
        if self.public_ingress_enabled() and not self._public_ingress_has_access_decision():
            risks.append("public ingress is enabled without API auth, edge auth, restricted CIDRs, or IAM-only access")
        if self.cloud == "aws" and self.public_ingress_enabled() and not self.aws_certificate_arn and not self.edge_auth_managed:
            risks.append("AWS public load balancer is HTTP-only without an ACM certificate or upstream edge declaration")
        return risks

    def public_ingress_enabled(self) -> bool:
        if self.cloud == "aws":
            return True
        if self.cloud == "gcp":
            return self.gcp_ingress == "INGRESS_TRAFFIC_ALL"
        if self.cloud == "azure":
            return self.azure_external_ingress
        return False

    def uses_azure_key_vault_refs(self) -> bool:
        return any(ref.azure_key_vault_url for ref in self.existing_secret_refs)

    def _public_ingress_has_access_decision(self) -> bool:
        if self.api_auth_enabled or self.edge_auth_managed:
            return True
        if self.cloud == "gcp" and not self.gcp_allow_unauthenticated:
            return True
        if self.cloud == "aws" and self.ingress_cidrs and not set(self.ingress_cidrs).intersection(_OPEN_CIDRS):
            return True
        return False


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


def _string_list(value: Any, default: list[str], key: str) -> list[str]:
    if value is None:
        return list(default)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"cerebro:{key} must be a list of strings")
    return list(value)


def _existing_secret_refs(value: Any) -> list[ExistingSecretRef]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ValueError("cerebro:existingSecretRefs must be an object keyed by environment variable name")
    refs: list[ExistingSecretRef] = []
    for name, raw in value.items():
        if not isinstance(name, str):
            raise ValueError("cerebro:existingSecretRefs keys must be strings")
        if not isinstance(raw, dict):
            raise ValueError(f"cerebro:existingSecretRefs.{name} must be an object")
        refs.append(
            ExistingSecretRef(
                name=name,
                aws_arn=_optional_string(raw, "awsArn"),
                gcp_secret=_optional_string(raw, "gcpSecret"),
                gcp_version=_optional_string(raw, "gcpVersion") or "latest",
                azure_key_vault_url=_optional_string(raw, "azureKeyVaultUrl"),
                azure_secret_name=_optional_string(raw, "azureSecretName"),
            )
        )
    return refs


def _scheduled_jobs(value: Any) -> list[ScheduledJob]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("cerebro:scheduledJobs must be a list")
    jobs: list[ScheduledJob] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"cerebro:scheduledJobs[{index}] must be an object")
        name = _required_string(raw, "name", f"scheduledJobs[{index}]")
        schedule = _required_string(raw, "schedule", f"scheduledJobs[{index}]")
        command = raw.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
            raise ValueError(f"cerebro:scheduledJobs[{index}].command must be a non-empty list of strings")
        cpu = raw.get("cpu")
        if cpu is not None and not isinstance(cpu, int | float):
            raise ValueError(f"cerebro:scheduledJobs[{index}].cpu must be a number")
        memory_mib = raw.get("memoryMiB")
        if memory_mib is not None and not isinstance(memory_mib, int):
            raise ValueError(f"cerebro:scheduledJobs[{index}].memoryMiB must be an integer")
        jobs.append(
            ScheduledJob(
                name=_slug(name),
                schedule=schedule,
                command=list(command),
                time_zone=_optional_string(raw, "timeZone") or "UTC",
                enabled=bool(raw.get("enabled", True)),
                description=_optional_string(raw, "description"),
                timeout_seconds=_positive_int(_optional_int(raw, "timeoutSeconds"), 900, f"scheduledJobs[{index}].timeoutSeconds"),
                retry_limit=_positive_int(_optional_int(raw, "retryLimit"), 1, f"scheduledJobs[{index}].retryLimit", allow_zero=True),
                cpu=float(cpu) if cpu is not None else None,
                memory_mib=memory_mib,
            )
        )
    return jobs


def _required_string(raw: Mapping[str, Any], key: str, path: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"cerebro:{path}.{key} must be a non-empty string")
    return value


def _optional_string(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _optional_int(raw: Mapping[str, Any], key: str) -> int | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _image_uses_latest(image: str) -> bool:
    last_path_part = image.rsplit("/", 1)[-1]
    if "@" in last_path_part:
        return False
    if ":" not in last_path_part:
        return True
    return last_path_part.rsplit(":", 1)[-1] == "latest"
