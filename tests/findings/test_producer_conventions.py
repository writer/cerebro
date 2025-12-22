from __future__ import annotations

import ast
import inspect
import re
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import get_args, get_origin
from uuid import uuid4

import pytest

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.bucket_cleartext_key import (
    BucketCleartextKeyProducer,
)
from cerebro.findings.producers.aws.codebuild_public_trigger import (
    CodeBuildPublicTriggerProducer,
)
from cerebro.findings.producers.aws.codebuild_source_credential import (
    CodeBuildSharedCredentialProducer,
)
from cerebro.findings.producers.aws.security_group_admin_port import (
    AwsSecurityGroupAdminPortProducer,
)
from cerebro.findings.producers.aws.security_group_public_ingress import (
    AwsSecurityGroupPublicIngressProducer,
)
from cerebro.findings.producers.azure.storage_secret_artifacts import (
    AzureStorageSecretArtifactProducer,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.gcp.bucket_secret_artifacts import (
    GCPBucketSecretArtifactProducer,
)
from cerebro.findings.producers.github.admin_without_2fa import (
    AdminWithout2FAProducer,
)
from cerebro.findings.producers.github.org_workflow_permissions import (
    GithubOrgWorkflowRiskProducer,
)
from cerebro.findings.producers.github.runner_exposure import (
    GithubRunnerNetworkExposureProducer,
    GithubRunnerPublicExposureProducer,
)
from cerebro.findings.producers.github.workflow_permissions import (
    GithubWorkflowDefaultWriteProducer,
)
from cerebro.findings.producers.kubernetes.ingress_public_exposure import (
    K8sIngressPublicExposureProducer,
)
from cerebro.findings.producers.kubernetes.node_public_exposure import (
    K8sNodePublicExposureProducer,
)
from cerebro.findings.producers.kubernetes.service_public_exposure import (
    K8sServicePublicExposureProducer,
)
from cerebro.findings.producers.m365.file_shared_externally import (
    M365FileSharedExternallyProducer,
)
from cerebro.findings.producers.m365.guest_admin import M365GuestAdminProducer
from cerebro.findings.producers.m365.inactive_admin import (
    M365InactivePrivilegedUserProducer,
)
from cerebro.findings.producers.m365.sharepoint_anonymous_link import (
    M365SharePointAnonymousLinkProducer,
)
from cerebro.findings.producers.okta.dormant_admin import (
    OktaDormantAdminProducer,
)
from cerebro.findings.producers.okta.mfa_disabled import (
    OktaMFADisabledProducer,
)
from cerebro.findings.producers.registry import (
    auto_discover_producers,
    get_producer_registry,
)
from cerebro.findings.producers.telemetry.repo_secret_key import (
    RepoSecretKeyProducer,
)


def _has_builder_call(source: str, function_name: str) -> bool:
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == function_name:
                return True
    return False


def _assert_builder_call(producer_cls, function_name: str) -> None:
    source = inspect.getsource(producer_cls.evaluate)
    assert _has_builder_call(
        source, function_name
    ), f"{producer_cls.__name__} should call {function_name}"


@pytest.fixture(scope="module")
def producer_instances():
    auto_discover_producers()
    registry = get_producer_registry()
    return list(registry._producers.values())  # pragma: no cover - internal access


def test_producer_context_annotation(producer_instances):
    for producer in producer_instances:
        cls = producer.__class__
        module = sys.modules[cls.__module__]
        hints = inspect.get_annotations(
            cls.evaluate,
            eval_str=True,
            globals=module.__dict__,
        )

        assert "context" in hints, f"Missing context annotation in {cls.__name__}"
        context_hint = hints["context"]

        if context_hint is ProducerContext:
            continue

        origin = get_origin(context_hint)
        args = get_args(context_hint)

        if origin is None:
            assert (
                context_hint is ProducerContext
            ), f"context annotation for {cls.__name__} should include ProducerContext"
            continue

        assert ProducerContext in args and type(None) in args, (
            "context annotation for "
            f"{cls.__name__} should include ProducerContext | None"
        )


def test_producer_resolve_rule_id_usage(producer_instances):
    for producer in producer_instances:
        source = inspect.getsource(producer.__class__.evaluate)
        assert any(
            token in source for token in ("resolve_rule_id", "_resolve_rule_id")
        ), f"Producer {producer.__class__.__name__} should resolve rule IDs via helper"


def test_producer_files_avoid_literal_slice_limits():
    root = Path(__file__).resolve().parents[2]
    producer_dir = root / "src" / "cerebro" / "findings" / "producers"
    pattern = re.compile(r"\[\s*:\s*\d+")

    offenders: list[Path] = []
    for path in producer_dir.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text()
        if pattern.search(text):
            offenders.append(path)

    assert not offenders, "Found fixed-length slices in: " + ", ".join(
        str(path) for path in offenders
    )


def test_identity_producers_use_identity_builder():
    identity_producers = [
        OktaDormantAdminProducer,
        OktaMFADisabledProducer,
        M365GuestAdminProducer,
        M365InactivePrivilegedUserProducer,
        AdminWithout2FAProducer,
    ]
    for producer_cls in identity_producers:
        source = inspect.getsource(producer_cls.evaluate)
        assert (
            "build_identity_user_evidence" in source
        ), f"{producer_cls.__name__} should use identity evidence builder"


def test_ci_producers_use_ci_builder():
    ci_producers = [
        CodeBuildPublicTriggerProducer,
        CodeBuildSharedCredentialProducer,
    ]
    for producer_cls in ci_producers:
        source = inspect.getsource(producer_cls.evaluate)
        assert (
            "build_ci_pipeline_exposure" in source
        ), f"{producer_cls.__name__} should use CI pipeline evidence builder"


def test_network_producers_use_network_builder():
    network_producers = [
        K8sServicePublicExposureProducer,
        K8sIngressPublicExposureProducer,
        K8sNodePublicExposureProducer,
    ]
    for producer_cls in network_producers:
        _assert_builder_call(producer_cls, "build_network_exposure_evidence")


def test_security_group_producers_use_security_builder():
    sg_producers = [
        AwsSecurityGroupAdminPortProducer,
        AwsSecurityGroupPublicIngressProducer,
    ]
    for producer_cls in sg_producers:
        _assert_builder_call(producer_cls, "build_security_group_exposure")


def test_workflow_permission_producers_use_builder():
    workflow_producers = [
        GithubWorkflowDefaultWriteProducer,
        GithubOrgWorkflowRiskProducer,
    ]
    for producer_cls in workflow_producers:
        _assert_builder_call(producer_cls, "build_workflow_permission_evidence")


def test_telemetry_secret_producer_uses_incident_builder():
    _assert_builder_call(RepoSecretKeyProducer, "build_telemetry_incident_evidence")


# Cross-provider behaviour tests


@pytest.mark.parametrize(
    "producer_cls, provider, resource_type, config_builder",
    [
        (
            BucketCleartextKeyProducer,
            "aws",
            "aws.s3.bucket",
            lambda count: {
                "objectsSample": [
                    {"key": f"secrets/api_key_{i}.json"} for i in range(count)
                ],
                "policyAllowsPublic": True,
            },
        ),
        (
            GCPBucketSecretArtifactProducer,
            "gcp",
            "gcp.storage.bucket",
            lambda count: {
                "is_public": True,
                "objectsSample": [
                    {
                        "key": f"service_account_{i}.json",
                        "content_type": "application/json",
                        "size": 1024,
                    }
                    for i in range(count)
                ],
            },
        ),
        (
            AzureStorageSecretArtifactProducer,
            "azure",
            "azure.storage.container",
            lambda count: {
                "public_access": "container",
                "objectsSample": [
                    {
                        "name": f"backup/credential_{i}.pem",
                        "content_type": "application/x-pem-file",
                        "size": 2048,
                    }
                    for i in range(count)
                ],
            },
        ),
    ],
)
def test_storage_secret_evidence_clamped(
    producer_cls,
    provider,
    resource_type,
    config_builder,
):
    producer = producer_cls()
    resource = ResourceEntity(
        external_id=f"{provider}-resource",
        resource_type=resource_type,
        provider=provider,
        name=f"{provider}-resource",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config=config_builder(15),
    )

    findings = producer.evaluate(resource, config, {"rule_id": uuid4()})
    assert findings, "Producer should yield a finding for synthetic secret exposure"

    evidence = findings[0].evidence
    assert len(evidence["matched_objects"]) == 10


def test_okta_dormant_admin_evidence_clamps_sequences():
    producer = OktaDormantAdminProducer()
    resource = ResourceEntity(
        external_id="okta-user-1",
        resource_type="okta.user",
        provider="okta",
        name="user1",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "status": "ACTIVE",
            "admin_roles": ["SUPER_ADMIN"],
            "last_login": "2023-01-01T00:00:00Z",
            "mfa_enrolled": False,
            "applications": [{"id": i} for i in range(15)],
            "groups": [f"group-{i}" for i in range(15)],
            "email": "admin@example.com",
            "login": "admin@example.com",
            "is_service_account": False,
        },
    )

    findings = producer.evaluate(resource, config, ProducerContext(rule_id=uuid4()))
    assert findings
    evidence = findings[0].evidence
    assert len(evidence["applications"]) == 10
    assert len(evidence["groups"]) == 10
    assert "admin_privileges" in evidence["risk_factors"]
    assert evidence["status"] == "ACTIVE"


def test_github_runner_public_exposure_clamps_repositories():
    producer = GithubRunnerPublicExposureProducer()
    resource = ResourceEntity(
        external_id="runner-1",
        resource_type="github.runner",
        provider="github",
        name="self-hosted",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "runner": {"name": "self-hosted"},
            "runner_group": {
                "id": 42,
                "name": "all-runners",
                "visibility": "all",
                "allows_public_repositories": True,
            },
            "repositories": [
                {"name": f"public-{i}", "visibility": "public"} for i in range(15)
            ],
        },
    )

    findings = producer.evaluate(resource, config, {"rule_id": uuid4()})
    assert findings
    assert len(findings[0].evidence["exposed_repositories"]) == 10


def test_github_runner_network_exposure_evidence():
    producer = GithubRunnerNetworkExposureProducer()
    resource = ResourceEntity(
        external_id="runner-2",
        resource_type="github.runner",
        provider="github",
        name="runner-2",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "runner": {
                "name": "runner-2",
                "labels": ["self-hosted"],
            }
        },
    )

    host = {
        "host_id": "host-2",
        "hostname": "runner-2",
        "ip_addresses": ["35.85.12.34"],
        "network_connections": [
            {
                "protocol": "tcp",
                "local_address": "0.0.0.0",
                "local_port": 22,
                "remote_address": None,
                "remote_port": None,
                "status": "LISTEN",
            }
        ],
    }

    context = ProducerContext(
        rule_id=uuid4(),
        extras={"host_telemetry_index": {"runner-2": host}},
    )

    findings = producer.evaluate(resource, config, context)
    assert findings
    host_evidence = findings[0].evidence["host"]
    assert host_evidence["public_ips"] == ["35.85.12.34"]
    assert host_evidence["listening_ports"] == [22]


def test_codebuild_public_trigger_evidence_builder():
    producer = CodeBuildPublicTriggerProducer()
    resource = ResourceEntity(
        external_id="project-1",
        resource_type="aws.codebuild.project",
        provider="aws",
        name="project-1",
    )
    filter_groups = [[{"type": "EVENT", "pattern": "PUSH"}]] * 12
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "source": {
                "type": "GITHUB",
                "location": "https://github.com/example/repo",
                "auth": {
                    "type": "OAUTH",
                    "resource": "arn:aws:secretsmanager:us-east-1:123:secret",
                },
                "reportBuildStatus": True,
            },
            "webhook": {
                "url": "https://codedeploy.aws/webhook",
                "filterGroups": filter_groups,
            },
        },
    )

    findings = producer.evaluate(resource, config, ProducerContext(rule_id=uuid4()))
    assert findings
    evidence = findings[0].evidence
    assert len(evidence["filter_groups"]) == 10
    assert evidence["webhook_present"] is True
    assert evidence["project"] == "project-1"


def test_service_public_exposure_severity_downgrade_with_network_posture():
    producer = K8sServicePublicExposureProducer()
    resource = ResourceEntity(
        external_id="svc1",
        resource_type="k8s.service",
        provider="kubernetes",
        name="frontend",
    )
    normalized_config = {
        "type": "LoadBalancer",
        "namespace": "prod",
        "loadBalancer": [{"ip": "35.85.12.34"}],
        "annotations": {},
    }
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config=normalized_config,
    )

    base_context = ProducerContext(rule_id=uuid4())
    findings_no_posture = producer.evaluate(resource, config, base_context)
    assert findings_no_posture
    assert findings_no_posture[0].severity == Severity.CRITICAL

    posture_context = ProducerContext(
        rule_id=uuid4(),
        extras={
            "namespace_network_posture": {
                "prod": {
                    "default_deny_ingress": True,
                    "default_deny_egress": True,
                }
            }
        },
    )

    findings_with_posture = producer.evaluate(resource, config, posture_context)
    assert findings_with_posture
    finding = findings_with_posture[0]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["namespace_network_posture"]["default_deny_ingress"]


def test_k8s_node_public_exposure_evidence_builder():
    producer = K8sNodePublicExposureProducer()
    resource = ResourceEntity(
        external_id="node-1",
        resource_type="k8s.node",
        provider="kubernetes",
        name="node-1",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "addresses": [
                {"type": "ExternalIP", "address": "35.85.12.34"},
                {"type": "Hostname", "address": "node1.example.com"},
            ],
            "namespace": "prod",
            "providerID": "aws:///us-west-2a/i-1234567890",
        },
    )

    findings = producer.evaluate(resource, config, ProducerContext(rule_id=uuid4()))
    assert findings
    evidence = findings[0].evidence
    assert evidence["exposures"][0]["ip"] == "35.85.12.34"
    assert evidence["exposures"][0]["public"] is True
    assert evidence["provider_id"] == "aws:///us-west-2a/i-1234567890"


def test_file_sharing_producers_clip_external_users():
    producer = M365FileSharedExternallyProducer()
    resource = ResourceEntity(
        external_id="sharepoint-site",
        resource_type="m365.sharepoint.site",
        provider="m365",
        name="site",
    )
    permissions = [
        {
            "grantedToV2": {
                "user": {
                    "email": f"guest{i}@example.com",
                    "displayName": f"Guest {i}",
                }
            },
            "roles": ["write"],
        }
        for i in range(25)
    ]

    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "web_url": "https://contoso.sharepoint.com/sites/site",
            "external_sharing": True,
            "permissions": permissions,
            "sharing_capability": "ExternalUserSharingOnly",
        },
    )

    context = ProducerContext(
        rule_id=uuid4(),
        organization_domains={"contoso.com"},
    )
    findings = producer.evaluate(resource, config, context)
    assert findings
    evidence = findings[0].evidence
    assert evidence["external_sharing_enabled"] is True
    assert evidence["external_users_count"] == 25
    assert len(evidence["external_users"]) == 10
    assert evidence["site_id"] == "sharepoint-site"
    assert all("roles" in entry for entry in evidence["external_users"])


def test_sharepoint_anonymous_link_evidence_clipped():
    producer = M365SharePointAnonymousLinkProducer()
    resource = ResourceEntity(
        external_id="sp-site",
        resource_type="m365.sharepoint.site",
        provider="m365",
        name="sp-site",
    )
    permissions = [
        {
            "link": {"scope": "anonymous", "type": "edit"},
            "roles": ["write"],
        }
        for _ in range(12)
    ]
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "web_url": "https://contoso.sharepoint.com/sites/sp-site",
            "permissions": permissions,
        },
    )

    findings = producer.evaluate(resource, config, {"rule_id": uuid4()})
    assert findings
    evidence = findings[0].evidence
    assert len(evidence["anonymous_links"]) == 5
    assert all("scope" in link for link in evidence["anonymous_links"])
