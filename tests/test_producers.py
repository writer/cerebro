"""Test finding producers."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

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
from cerebro.findings.producers.aws.iam_user_without_mfa import (
    IAMUserWithoutMFAProducer,
)
from cerebro.findings.producers.aws.s3_bucket_public import S3BucketPublicProducer
from cerebro.findings.producers.aws.service_account_open_assume import (
    AwsServiceAccountOpenAssumeProducer,
)
from cerebro.findings.producers.aws.storage_write_access import (
    StorageWriteAccessProducer,
)
from cerebro.findings.producers.azure.storage_public_write import (
    AzureStoragePublicWriteProducer,
)
from cerebro.findings.producers.azure.storage_secret_artifacts import (
    AzureStorageSecretArtifactProducer,
)
from cerebro.findings.producers.gcp.bucket_public_write import (
    GCPBucketPublicWriteProducer,
)
from cerebro.findings.producers.gcp.bucket_secret_artifacts import (
    GCPBucketSecretArtifactProducer,
)
from cerebro.findings.producers.github.org_workflow_permissions import (
    GithubOrgWorkflowRiskProducer,
)
from cerebro.findings.producers.github.public_repo_no_branch_protection import (
    PublicRepoNoBranchProtectionProducer,
)
from cerebro.findings.producers.github.repo_runner_group_scope import (
    GithubRepoRunnerGroupScopeProducer,
)
from cerebro.findings.producers.github.runner_exposure import (
    GithubRunnerNetworkExposureProducer,
    GithubRunnerPublicExposureProducer,
)
from cerebro.findings.producers.github.workflow_permissions import (
    GithubWorkflowDefaultWriteProducer,
)
from cerebro.findings.producers.kubernetes.cluster_admin_binding import (
    K8sClusterAdminServiceAccountProducer,
)
from cerebro.findings.producers.kubernetes.cluster_admin_wildcard import (
    K8sClusterAdminWildcardBindingProducer,
)
from cerebro.findings.producers.kubernetes.ingress_public_exposure import (
    K8sIngressPublicExposureProducer,
)
from cerebro.findings.producers.kubernetes.node_public_exposure import (
    K8sNodePublicExposureProducer,
)
from cerebro.findings.producers.kubernetes.privileged_pod import (
    K8sPrivilegedPodProducer,
)
from cerebro.findings.producers.kubernetes.service_public_exposure import (
    K8sServicePublicExposureProducer,
)
from cerebro.findings.producers.m365.guest_admin import M365GuestAdminProducer
from cerebro.findings.producers.m365.inactive_admin import (
    M365InactivePrivilegedUserProducer,
)
from cerebro.findings.producers.m365.sharepoint_anonymous_link import (
    M365SharePointAnonymousLinkProducer,
)
from cerebro.findings.producers.okta.dormant_admin import OktaDormantAdminProducer
from cerebro.findings.producers.telemetry.repo_secret_key import RepoSecretKeyProducer
from cerebro.telemetry.schemas import (
    HostTelemetry,
    NetworkConnection,
    SecretsScanResult,
)


class TestGitHubProducers:
    """Test GitHub finding producers."""

    def test_public_repo_branch_protection_producer(self):
        """Test GitHub public repo without branch protection producer."""
        producer = PublicRepoNoBranchProtectionProducer()

        # Test resource that should trigger finding
        resource = ResourceEntity(
            external_id="test-org/public-repo",
            resource_type="github.repo",
            provider="github",
            name="public-repo",
        )

        config = ConfigEntity(
            resource_external_id="test-org/public-repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "visibility": "public",
                "branchProtection": {"requirePR": False},
                "archived": False,
                "fullName": "test-org/public-repo",
                "defaultBranch": "main",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "public-repo" in finding.title
        assert finding.evidence["visibility"] == "public"
        assert not finding.evidence["branch_protection"]["enabled"]

    def test_public_repo_with_protection_no_finding(self):
        """Test that repos with branch protection don't trigger findings."""
        producer = PublicRepoNoBranchProtectionProducer()

        resource = ResourceEntity(
            external_id="test-org/protected-repo",
            resource_type="github.repo",
            provider="github",
            name="protected-repo",
        )

        config = ConfigEntity(
            resource_external_id="test-org/protected-repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "visibility": "public",
                "branchProtection": {"requirePR": True, "requiredReviewers": 2},
                "archived": False,
            },
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0

    def test_runner_public_exposure(self):
        producer = GithubRunnerPublicExposureProducer()

        resource = ResourceEntity(
            external_id="runner-123",
            resource_type="github.runner",
            provider="github",
            name="build-runner",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "runner": {
                    "id": 123,
                    "name": "build-runner",
                    "os": "linux",
                    "ephemeral": False,
                    "labels": ["self-hosted"],
                },
                "runner_group": {
                    "id": 42,
                    "name": "default",
                    "visibility": "all",
                    "allows_public_repositories": True,
                },
                "repositories": [
                    {"id": 1, "name": "public-repo", "visibility": "public"},
                    {"id": 2, "name": "private-repo", "visibility": "private"},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.evidence["runner_group"]["allows_public_repositories"] is True
        assert finding.evidence["exposed_repositories"][0]["visibility"] == "public"

    def test_runner_network_exposure(self):
        producer = GithubRunnerNetworkExposureProducer()

        resource = ResourceEntity(
            external_id="runner-234",
            resource_type="github.runner",
            provider="github",
            name="runner-host",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "runner": {
                    "id": 234,
                    "name": "runner-host",
                    "labels": ["self-hosted"],
                }
            },
        )

        host_telemetry = HostTelemetry(
            organization="test",
            site="site1",
            host_id="host-234",
            hostname="runner-host",
            agent_version="1.0.0",
            os_family="linux",
            collected_at=datetime.utcnow(),
            ip_addresses=["52.10.10.10", "10.0.0.5"],
            network_connections=[
                NetworkConnection(
                    protocol="tcp",
                    local_address="0.0.0.0",
                    local_port=22,
                    remote_address=None,
                    remote_port=None,
                    status="LISTEN",
                )
            ],
        )

        context = {
            "rule_id": uuid4(),
            "host_telemetry_index": {
                "runner-host": host_telemetry,
                "runner-host".lower(): host_telemetry,
            },
        }

        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["host"]["public_ips"] == ["52.10.10.10"]

    def test_workflow_default_write_permissions(self):
        producer = GithubWorkflowDefaultWriteProducer()

        resource = ResourceEntity(
            external_id="acme/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "actionsPermissions": {
                    "enabled": True,
                    "allowed_actions": "all",
                    "default_workflow_permissions": "write",
                    "can_approve_pull_request_reviews": True,
                }
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.evidence["default_workflow_permissions"] == "write"

    def test_workflow_read_permissions_no_finding(self):
        producer = GithubWorkflowDefaultWriteProducer()

        resource = ResourceEntity(
            external_id="acme/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "actionsPermissions": {
                    "enabled": True,
                    "allowed_actions": "selected",
                    "default_workflow_permissions": "read",
                    "can_approve_pull_request_reviews": False,
                }
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_org_workflow_risk(self):
        producer = GithubOrgWorkflowRiskProducer()

        resource = ResourceEntity(
            external_id="acme",
            resource_type="github.org",
            provider="github",
            name="Acme Org",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "actionsPermissions": {
                    "default_workflow_permissions": "write",
                    "allowed_actions": "all",
                    "can_approve_pull_request_reviews": True,
                }
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.evidence["allowed_actions"] == "all"

    def test_org_workflow_safe(self):
        producer = GithubOrgWorkflowRiskProducer()

        resource = ResourceEntity(
            external_id="acme",
            resource_type="github.org",
            provider="github",
            name="Acme Org",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "actionsPermissions": {
                    "default_workflow_permissions": "read",
                    "allowed_actions": "selected",
                    "can_approve_pull_request_reviews": False,
                }
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_repo_runner_group_scope_broad(self):
        producer = GithubRepoRunnerGroupScopeProducer()

        resource = ResourceEntity(
            external_id="acme/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "runner": {
                    "id": 101,
                    "name": "shared-runner",
                    "labels": ["linux", "x64"],
                },
                "runner_group": {
                    "id": 5,
                    "name": "default",
                    "visibility": "all",
                    "allows_public_repositories": True,
                    "restricted_to_workflows": False,
                },
                "repositories": [
                    {"full_name": "acme/repo"},
                    {"full_name": "acme/other-repo"},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.evidence["runner_group"]["visibility"] == "all"

    def test_repo_runner_group_scope_safe(self):
        producer = GithubRepoRunnerGroupScopeProducer()

        resource = ResourceEntity(
            external_id="acme/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "runner": {"id": 102, "name": "isolated-runner", "labels": ["linux"]},
                "runner_group": {
                    "id": 6,
                    "name": "repo-only",
                    "visibility": "private",
                    "allows_public_repositories": False,
                    "restricted_to_workflows": True,
                },
                "repositories": [{"full_name": "acme/repo"}],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0


class TestAWSProducers:
    """Test AWS finding producers."""

    def test_s3_bucket_public_producer(self):
        """Test S3 public bucket producer."""
        producer = S3BucketPublicProducer()

        resource = ResourceEntity(
            external_id="test-public-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="test-public-bucket",
        )

        config = ConfigEntity(
            resource_external_id="test-public-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "policyAllowsPublic": True,
                "aclAllowsPublic": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-east-1",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "test-public-bucket" in finding.title
        assert "bucket_policy" in finding.evidence["access_vectors"]

    def test_s3_bucket_cleartext_key_producer(self):
        producer = BucketCleartextKeyProducer()

        resource = ResourceEntity(
            external_id="secret-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="secret-bucket",
        )

        config = ConfigEntity(
            resource_external_id="secret-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "objectsSample": [
                    {
                        "key": "backups/api_keys.env",
                        "size": 120,
                        "modified": datetime.utcnow().isoformat(),
                    },
                    {
                        "key": "README.md",
                        "size": 80,
                        "modified": datetime.utcnow().isoformat(),
                    },
                ],
                "policyAllowsPublic": True,
                "aclAllowsPublic": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-west-2",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "api_keys" in finding.evidence["matched_objects"][0]["key"]

    def test_storage_write_access_producer(self):
        producer = StorageWriteAccessProducer()

        resource = ResourceEntity(
            external_id="writeable-bucket",
            resource_type="aws.s3.bucket",
            provider="aws",
            name="writeable-bucket",
        )

        config = ConfigEntity(
            resource_external_id="writeable-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "policyAllowsPublicWrite": True,
                "aclAllowsPublicWrite": False,
                "blockPublicAccess": {"effective": False},
                "region": "us-east-2",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["policy_allows_public_write"] is True

    def test_codebuild_public_trigger(self):
        producer = CodeBuildPublicTriggerProducer()

        resource = ResourceEntity(
            external_id="arn:aws:codebuild:us-east-1:123456789012:project/public",
            resource_type="aws.codebuild.project",
            provider="aws",
            name="public",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "source": {
                    "type": "GITHUB",
                    "location": "https://github.com/acme/public-repo",
                    "auth": {"type": "OAUTH"},
                    "reportBuildStatus": True,
                },
                "webhook": {
                    "url": "https://codebuild.us-east-1.amazonaws.com/webhooks?id=abc",
                    "filterGroups": [],
                },
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["repository"] == "https://github.com/acme/public-repo"

    def test_codebuild_public_trigger_with_filters(self):
        producer = CodeBuildPublicTriggerProducer()

        resource = ResourceEntity(
            external_id="arn:aws:codebuild:us-east-1:123456789012:project/restricted",
            resource_type="aws.codebuild.project",
            provider="aws",
            name="restricted",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "source": {
                    "type": "GITHUB",
                    "location": "https://github.com/acme/private-repo",
                    "auth": {"type": "OAUTH"},
                },
                "webhook": {
                    "url": "https://codebuild.us-east-1.amazonaws.com/webhooks?id=def",
                    "filterGroups": [
                        [
                            {"type": "EVENT", "pattern": "PUSH"},
                            {"type": "BASE_REF", "pattern": "^refs/heads/main$"},
                        ]
                    ],
                },
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 0


class TestKubernetesProducers:
    """Test Kubernetes finding producers."""

    def test_privileged_pod_producer(self):
        producer = K8sPrivilegedPodProducer()

        resource = ResourceEntity(
            external_id="prod/privileged-pod",
            resource_type="k8s.pod",
            provider="kubernetes",
            name="privileged-pod",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "serviceAccount": "builder",
                "hostNetwork": True,
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {
                            "privileged": True,
                            "capabilities": {"add": ["SYS_ADMIN", "NET_RAW"]},
                        },
                        "volumeMounts": [
                            {
                                "name": "docker-sock",
                                "mountPath": "/var/run/docker.sock",
                                "readOnly": False,
                            }
                        ],
                    }
                ],
                "volumes": [
                    {
                        "name": "docker-sock",
                        "hostPath": {"path": "/var/run/docker.sock"},
                    }
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
        assert "privileged_container" in exposure_types
        assert "host_network" in exposure_types
        assert "sensitive_host_path" in exposure_types

    def test_privileged_pod_safe(self):
        producer = K8sPrivilegedPodProducer()

        resource = ResourceEntity(
            external_id="prod/safe-pod",
            resource_type="k8s.pod",
            provider="kubernetes",
            name="safe-pod",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "serviceAccount": "default",
                "hostNetwork": False,
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "allowPrivilegeEscalation": False,
                        },
                        "volumeMounts": [],
                    }
                ],
                "volumes": [],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_privileged_pod_host_port(self):
        producer = K8sPrivilegedPodProducer()

        resource = ResourceEntity(
            external_id="prod/hostport-pod",
            resource_type="k8s.pod",
            provider="kubernetes",
            name="hostport-pod",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "containers": [
                    {
                        "name": "app",
                        "ports": [
                            {
                                "containerPort": 8443,
                                "hostPort": 30443,
                                "protocol": "TCP",
                            }
                        ],
                    }
                ],
                "volumes": [],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
        assert "host_port" in exposure_types

    def test_privileged_pod_sensitive_host_path_prefix(self):
        producer = K8sPrivilegedPodProducer()

        resource = ResourceEntity(
            external_id="prod/kube-secrets",
            resource_type="k8s.pod",
            provider="kubernetes",
            name="kube-secrets",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "containers": [
                    {
                        "name": "app",
                        "volumeMounts": [
                            {
                                "name": "kubeconfig",
                                "mountPath": "/etc/kubernetes/admin.conf",
                                "readOnly": True,
                            }
                        ],
                    }
                ],
                "volumes": [
                    {
                        "name": "kubeconfig",
                        "hostPath": {"path": "/etc/kubernetes/admin.conf"},
                    }
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
        assert "sensitive_host_path" in exposure_types

    def test_ingress_plain_http(self):
        producer = K8sIngressPublicExposureProducer()

        resource = ResourceEntity(
            external_id="prod/ingress-http",
            resource_type="k8s.ingress",
            provider="kubernetes",
            name="ingress-http",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "annotations": {
                    "kubernetes.io/ingress.allow-http": "true",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
                "rules": [
                    {
                        "host": "api.example.com",
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "api", "port": 80}},
                            }
                        ],
                    }
                ],
                "tls": [],
                "loadBalancer": [
                    {"hostname": "abc123.elb.amazonaws.com", "ip": "203.0.113.10"}
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["exposures"][0]["type"] == "plain_http"

    def test_ingress_with_tls(self):
        producer = K8sIngressPublicExposureProducer()

        resource = ResourceEntity(
            external_id="prod/ingress-tls",
            resource_type="k8s.ingress",
            provider="kubernetes",
            name="ingress-tls",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "annotations": {
                    "kubernetes.io/ingress.allow-http": "false",
                    "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
                },
                "rules": [
                    {
                        "host": "secure.example.com",
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "api", "port": 443}},
                            }
                        ],
                    }
                ],
                "tls": [{"hosts": ["secure.example.com"], "secretName": "tls-secret"}],
                "loadBalancer": [
                    {"hostname": "abc123.elb.amazonaws.com", "ip": "203.0.113.10"}
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_cluster_admin_service_account(self):
        producer = K8sClusterAdminServiceAccountProducer()

        resource = ResourceEntity(
            external_id="binding-admin",
            resource_type="k8s.cluster_role_binding",
            provider="kubernetes",
            name="binding-admin",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "builder",
                        "namespace": "default",
                    },
                    {"kind": "ServiceAccount", "name": "ci", "namespace": "prod"},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        accounts = finding.evidence["service_accounts"]
        assert any(acc.get("namespace") == "default" for acc in accounts)

    def test_cluster_admin_service_account_irrelevant(self):
        producer = K8sClusterAdminServiceAccountProducer()

        resource = ResourceEntity(
            external_id="binding-view",
            resource_type="k8s.cluster_role_binding",
            provider="kubernetes",
            name="binding-view",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "roleRef": {"kind": "ClusterRole", "name": "view"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "viewer", "namespace": "team"}
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_cluster_admin_wildcard_group(self):
        producer = K8sClusterAdminWildcardBindingProducer()

        resource = ResourceEntity(
            external_id="binding-authenticated",
            resource_type="k8s.cluster_role_binding",
            provider="kubernetes",
            name="binding-authenticated",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [
                    {"kind": "Group", "name": "system:authenticated"},
                    {"kind": "Group", "name": "system:serviceaccounts:prod"},
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        exposures = finding.evidence["exposures"]
        assert any(exp.get("name") == "system:authenticated" for exp in exposures)
        assert any(
            exp.get("name") == "system:serviceaccounts:prod" for exp in exposures
        )

    def test_cluster_admin_wildcard_safe(self):
        producer = K8sClusterAdminWildcardBindingProducer()

        resource = ResourceEntity(
            external_id="binding-team",
            resource_type="k8s.cluster_role_binding",
            provider="kubernetes",
            name="binding-team",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [
                    {"kind": "Group", "name": "dev-team"},
                    {"kind": "User", "name": "alice"},
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_service_load_balancer_public_ip(self):
        producer = K8sServicePublicExposureProducer()

        resource = ResourceEntity(
            external_id="prod/web",
            resource_type="k8s.service",
            provider="kubernetes",
            name="web",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "type": "LoadBalancer",
                "annotations": {},
                "loadBalancer": [
                    {"ip": "8.8.8.8"},
                ],
                "externalIPs": [],
                "ports": [
                    {
                        "name": "http",
                        "protocol": "TCP",
                        "port": 80,
                        "targetPort": 8080,
                        "nodePort": None,
                    }
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
        assert "load_balancer_ip" in exposure_types

    def test_service_node_port_exposure(self):
        producer = K8sServicePublicExposureProducer()

        resource = ResourceEntity(
            external_id="team/api",
            resource_type="k8s.service",
            provider="kubernetes",
            name="api",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "team",
                "type": "NodePort",
                "annotations": {},
                "ports": [
                    {
                        "name": "https",
                        "protocol": "TCP",
                        "port": 443,
                        "targetPort": 8443,
                        "nodePort": 31443,
                    }
                ],
                "loadBalancer": [],
                "externalIPs": [],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        exposure = finding.evidence["exposures"][0]
        assert exposure["type"] == "node_port"
        assert exposure["port"] == 31443

    def test_service_internal_load_balancer(self):
        producer = K8sServicePublicExposureProducer()

        resource = ResourceEntity(
            external_id="prod/internal",
            resource_type="k8s.service",
            provider="kubernetes",
            name="internal",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "namespace": "prod",
                "type": "LoadBalancer",
                "annotations": {
                    "service.beta.kubernetes.io/aws-load-balancer-internal": "true",
                },
                "loadBalancer": [
                    {"ip": "10.0.0.5"},
                ],
                "externalIPs": [],
                "ports": [
                    {
                        "name": "http",
                        "protocol": "TCP",
                        "port": 80,
                        "targetPort": 8080,
                        "nodePort": None,
                    }
                ],
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_node_public_external_ip(self):
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
                    {"type": "InternalIP", "address": "10.1.0.3"},
                    {"type": "ExternalIP", "address": "8.8.4.4"},
                ],
                "providerID": "aws:///us-west-2a/i-1234567890",
                "unschedulable": False,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        evidence = finding.evidence
        assert any(exp["type"] == "external_ip" for exp in evidence["exposures"])

    def test_node_hostname_only(self):
        producer = K8sNodePublicExposureProducer()

        resource = ResourceEntity(
            external_id="node-2",
            resource_type="k8s.node",
            provider="kubernetes",
            name="node-2",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "addresses": [
                    {"type": "Hostname", "address": "public.example.net"},
                ],
                "providerID": "gce:///projects/test/zones/us-central1-a/nodes/node-2",
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.evidence["exposures"][0]["type"] == "hostname"

    def test_node_no_public_exposure(self):
        producer = K8sNodePublicExposureProducer()

        resource = ResourceEntity(
            external_id="node-3",
            resource_type="k8s.node",
            provider="kubernetes",
            name="node-3",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "addresses": [
                    {"type": "InternalIP", "address": "10.10.0.5"},
                    {"type": "Hostname", "address": None},
                ],
                "unschedulable": True,
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_codebuild_shared_source_credentials(self):
        producer = CodeBuildSharedCredentialProducer()

        resource = ResourceEntity(
            external_id="arn:aws:codebuild:us-east-1:123456789012:project/ci",
            resource_type="aws.codebuild.project",
            provider="aws",
            name="ci",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "source": {
                    "type": "GITHUB",
                    "location": "https://github.com/acme/service",
                    "auth": {"type": "OAUTH", "resource": "token-arn"},
                    "insecureSsl": True,
                    "reportBuildStatus": True,
                },
                "logsConfig": {"cloudWatchLogs": {"status": "ENABLED"}},
                "environment": {
                    "environmentVariables": [
                        {"name": "GITHUB_TOKEN", "value": "***"},
                        {"name": "ENV", "value": "prod"},
                    ]
                },
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.evidence["insecure_ssl"] is True

    def test_codebuild_shared_source_credentials_safe(self):
        producer = CodeBuildSharedCredentialProducer()

        resource = ResourceEntity(
            external_id="arn:aws:codebuild:us-east-1:123456789012:project/secure",
            resource_type="aws.codebuild.project",
            provider="aws",
            name="secure",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "source": {
                    "type": "GITHUB",
                    "location": "https://github.enterprise/acme/secure",
                    "auth": {"type": "CODECONNECTIONS"},
                    "insecureSsl": False,
                    "reportBuildStatus": False,
                },
                "environment": {
                    "environmentVariables": [
                        {"name": "ENV", "value": "prod"},
                    ]
                },
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_service_account_open_assume_public(self):
        producer = AwsServiceAccountOpenAssumeProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:role/PublicRole",
            resource_type="aws.iam.role",
            provider="aws",
            name="PublicRole",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_id": "123456789012",
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "attached_policies": [
                    {
                        "policy_name": "ReadOnlyAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                ],
                "inline_policies": {},
                "last_used": None,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["exposures"][0]["type"] == "public"

    def test_service_account_open_assume_external_account(self):
        producer = AwsServiceAccountOpenAssumeProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:role/CrossAccount",
            resource_type="aws.iam.role",
            provider="aws",
            name="CrossAccount",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_id": "123456789012",
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::210987654321:root",
                                    "210987654322",
                                ]
                            },
                            "Action": ["sts:AssumeRole"],
                        }
                    ],
                },
                "attached_policies": [],
                "inline_policies": {},
                "last_used": None,
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        exposure = finding.evidence["exposures"][0]
        assert exposure["type"] == "external_account"
        assert "210987654321" in exposure["accounts"]
        assert "210987654322" in exposure["accounts"]

    def test_service_account_open_assume_restricted_condition(self):
        producer = AwsServiceAccountOpenAssumeProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:role/OrgBound",
            resource_type="aws.iam.role",
            provider="aws",
            name="OrgBound",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_id": "123456789012",
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::210987654321:root"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {
                                    "aws:PrincipalOrgID": "o-example",
                                }
                            },
                        }
                    ],
                },
                "attached_policies": [],
                "inline_policies": {},
                "last_used": None,
            },
        )

        findings = producer.evaluate(resource, config)

        assert len(findings) == 0

    def test_iam_user_without_mfa_producer(self):
        """Test IAM user without MFA producer."""
        producer = IAMUserWithoutMFAProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:user/testuser",
            resource_type="aws.iam.user",
            provider="aws",
            name="testuser",
        )

        config = ConfigEntity(
            resource_external_id="arn:aws:iam::123456789012:user/testuser",
            captured_at=datetime.utcnow(),
            normalized_config={
                "console_access": True,
                "mfa": {"enabled": False},
                "password_last_used": "2024-01-01T10:00:00Z",
                "attached_policies": ["ReadOnlyAccess"],
                "groups": [],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert "testuser" in finding.title
        assert finding.evidence["console_access"] is True
        assert finding.evidence["mfa_enabled"] is False

    def test_iam_admin_user_without_mfa_critical_severity(self):
        """Test that admin users without MFA get critical severity."""
        producer = IAMUserWithoutMFAProducer()

        resource = ResourceEntity(
            external_id="arn:aws:iam::123456789012:user/admin",
            resource_type="aws.iam.user",
            provider="aws",
            name="admin",
        )

        config = ConfigEntity(
            resource_external_id="arn:aws:iam::123456789012:user/admin",
            captured_at=datetime.utcnow(),
            normalized_config={
                "console_access": True,
                "mfa": {"enabled": False},
                "password_last_used": "2024-01-01T10:00:00Z",
                "attached_policies": ["AdministratorAccess"],
                "groups": [],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL  # Escalated for admin
        assert "has_admin_privileges" in finding.evidence["risk_factors"]


class TestGCPProducers:
    """Test GCP storage producers."""

    def test_gcp_bucket_public_write(self):
        producer = GCPBucketPublicWriteProducer()

        resource = ResourceEntity(
            external_id="projects/acme/buckets/public-bucket",
            resource_type="gcp.storage.bucket",
            provider="gcp",
            name="public-bucket",
        )

        config = ConfigEntity(
            resource_external_id="projects/acme/buckets/public-bucket",
            captured_at=datetime.utcnow(),
            normalized_config={
                "iam_bindings": [
                    {
                        "role": "roles/storage.objectAdmin",
                        "members": ["allUsers"],
                    }
                ],
                "uniform_bucket_level_access": {"enabled": False},
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["iam_bindings"][0]["members"] == ["allUsers"]

    def test_gcp_bucket_secret_artifacts(self):
        producer = GCPBucketSecretArtifactProducer()

        resource = ResourceEntity(
            external_id="projects/acme/buckets/exposed-secrets",
            resource_type="gcp.storage.bucket",
            provider="gcp",
            name="exposed-secrets",
        )

        config = ConfigEntity(
            resource_external_id="projects/acme/buckets/exposed-secrets",
            captured_at=datetime.utcnow(),
            normalized_config={
                "is_public": True,
                "objectsSample": [
                    {"key": "config/service_account.json", "size": 2048},
                    {"key": "readme.txt", "size": 128},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "service_account.json" in finding.evidence["matched_objects"][0]["key"]


class TestAzureProducers:
    """Test Azure storage producers."""

    def test_azure_storage_public_write(self):
        producer = AzureStoragePublicWriteProducer()

        resource = ResourceEntity(
            external_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/containers/public",
            resource_type="azure.storage.container",
            provider="azure",
            name="public",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "resource_group": "rg",
                "account_name": "acct",
                "public_access": "container",
                "allow_blob_public_access": True,
                "signed_identifiers": [],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["public_access"] == "container"

    def test_azure_storage_secret_artifacts(self):
        producer = AzureStorageSecretArtifactProducer()

        resource = ResourceEntity(
            external_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/containers/secrets",
            resource_type="azure.storage.container",
            provider="azure",
            name="secrets",
        )

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={
                "public_access": "blob",
                "allow_blob_public_access": True,
                "account_name": "acct",
                "objectsSample": [
                    {"name": "keys/service_account.json", "size": 1024},
                    {"name": "README.md", "size": 512},
                ],
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "service_account.json" in finding.evidence["matched_objects"][0]["name"]


class TestProducerRegistry:
    """Test producer registry functionality."""

    def test_producer_auto_discovery(self):
        """Test that producers are auto-discovered."""
        from cerebro.findings.producers import producer_registry

        producers = producer_registry.list_producers()

        # Should have discovered our producers
        expected_producers = [
            "PublicRepoNoBranchProtectionProducer",
            "S3BucketPublicProducer",
            "IAMUserWithoutMFAProducer",
            "S3BucketUnencryptedProducer",
            "EC2InstancePublicIPProducer",
            "OktaDormantAdminProducer",
            "M365GuestAdminProducer",
            "M365InactivePrivilegedUserProducer",
            "BucketCleartextKeyProducer",
            "StorageWriteAccessProducer",
            "CodeBuildPublicTriggerProducer",
            "CodeBuildSharedCredentialProducer",
            "AwsServiceAccountOpenAssumeProducer",
            "K8sPrivilegedPodProducer",
            "K8sIngressPublicExposureProducer",
            "K8sClusterAdminServiceAccountProducer",
            "K8sClusterAdminWildcardBindingProducer",
            "RepoSecretKeyProducer",
            "GCPBucketPublicWriteProducer",
            "GCPBucketSecretArtifactProducer",
            "AzureStoragePublicWriteProducer",
            "AzureStorageSecretArtifactProducer",
            "GithubRunnerPublicExposureProducer",
            "GithubRunnerNetworkExposureProducer",
            "GithubWorkflowDefaultWriteProducer",
            "GithubOrgWorkflowRiskProducer",
            "GithubRepoRunnerGroupScopeProducer",
            "M365SharePointAnonymousLinkProducer",
        ]

        for expected in expected_producers:
            assert expected in producers

    def test_get_producers_for_resource(self):
        """Test getting producers for specific resources."""
        from cerebro.findings.producers import producer_registry

        # Test GitHub resource
        github_producers = producer_registry.get_producers_for_resource(
            "github",
            "github.repo",
        )
        assert len(github_producers) > 0
        assert any(
            "github" in {source.lower() for source in producer.desired_sources}
            for producer in github_producers
        )

        # Test AWS S3 resource
        s3_producers = producer_registry.get_producers_for_resource(
            "aws",
            "aws.s3.bucket",
        )
        assert len(s3_producers) > 0


class TestTelemetryProducers:
    """Test telemetry-based producers."""

    def test_repo_secret_key_producer(self):
        producer = RepoSecretKeyProducer()

        resource = ResourceEntity(
            external_id="org/repo",
            resource_type="github.repo",
            provider="github",
            name="repo",
        )

        secret_payload = SecretsScanResult(
            detector_name="trufflehog",
            file_path="config/.env",
            line_number=12,
            secret_type="openai_api_key",
            verified=False,
            raw_result={"redacted": "sk-abc123xyz456", "DetectorType": "openai"},
        )

        config = ConfigEntity(
            resource_external_id="org/repo",
            captured_at=datetime.utcnow(),
            normalized_config={
                "secrets": [
                    {
                        "raw_payload": secret_payload.model_dump(),
                        "commit_sha": "deadbeef",
                    }
                ]
            },
        )

        context = {"rule_id": uuid4(), "detected_at": datetime.utcnow()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "OpenAI API key" in finding.summary
        assert finding.evidence["validation"]["status"] in {
            "format_match",
            "inferred",
            "verified",
        }


class TestIdentityProducers:
    """Test identity-focused producers."""

    def test_okta_dormant_admin(self):
        producer = OktaDormantAdminProducer()

        resource = ResourceEntity(
            external_id="00u123",
            resource_type="okta.user",
            provider="okta",
            name="admin@example.com",
        )

        old_login = (datetime.now(UTC) - timedelta(days=120)).isoformat()
        created = (datetime.now(UTC) - timedelta(days=200)).isoformat()

        config = ConfigEntity(
            resource_external_id="00u123",
            captured_at=datetime.utcnow(),
            normalized_config={
                "status": "ACTIVE",
                "admin_roles": ["SUPER_ADMIN"],
                "login": "admin@example.com",
                "email": "admin@example.com",
                "last_login": old_login,
                "created": created,
                "mfa_enrolled": True,
                "applications": [],
                "groups": [],
                "is_service_account": False,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "without sign-in activity" in finding.summary.lower()
        assert "SUPER_ADMIN" in finding.evidence["admin_roles"][0]

    def test_okta_dormant_admin_recent_login_no_finding(self):
        producer = OktaDormantAdminProducer()

        resource = ResourceEntity(
            external_id="00u456",
            resource_type="okta.user",
            provider="okta",
            name="ops@example.com",
        )

        recent_login = (datetime.now(UTC) - timedelta(days=5)).isoformat()

        config = ConfigEntity(
            resource_external_id="00u456",
            captured_at=datetime.utcnow(),
            normalized_config={
                "status": "ACTIVE",
                "admin_roles": ["ORG_ADMIN"],
                "login": "ops@example.com",
                "last_login": recent_login,
                "is_service_account": False,
            },
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0

    def test_m365_guest_admin(self):
        producer = M365GuestAdminProducer()

        resource = ResourceEntity(
            external_id="user-guest-1",
            resource_type="m365.user",
            provider="m365",
            name="guest-admin@example.com",
        )

        config = ConfigEntity(
            resource_external_id="user-guest-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "is_guest": True,
                "account_enabled": True,
                "role_names": ["Global Administrator"],
                "directory_roles": [
                    {
                        "id": "role1",
                        "display_name": "Global Administrator",
                        "role_template_id": "62e90394-69f5-4237-9190-012177145e10",
                    }
                ],
                "user_principal_name": "guest-admin@example.com",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "guest" in finding.summary.lower()

    def test_m365_inactive_privileged_user(self):
        producer = M365InactivePrivilegedUserProducer()

        resource = ResourceEntity(
            external_id="user-admin-1",
            resource_type="m365.user",
            provider="m365",
            name="admin@example.com",
        )

        stale_login = (datetime.now(UTC) - timedelta(days=120)).isoformat()

        config = ConfigEntity(
            resource_external_id="user-admin-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_enabled": True,
                "directory_roles": [
                    {
                        "id": "role1",
                        "display_name": "Global Administrator",
                    }
                ],
                "role_names": ["Global Administrator"],
                "last_login": stale_login,
                "created": (
                    datetime.now(UTC) - timedelta(days=200)
                ).isoformat(),
                "user_principal_name": "admin@example.com",
                "mfa_enrolled": False,
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert "dormant" in finding.title.lower()
        assert "inactive_account" in finding.evidence["risk_factors"]

    def test_m365_inactive_privileged_user_recent_login_no_finding(self):
        producer = M365InactivePrivilegedUserProducer()

        resource = ResourceEntity(
            external_id="user-admin-2",
            resource_type="m365.user",
            provider="m365",
            name="admin2@example.com",
        )

        config = ConfigEntity(
            resource_external_id="user-admin-2",
            captured_at=datetime.utcnow(),
            normalized_config={
                "account_enabled": True,
                "directory_roles": [
                    {
                        "id": "role2",
                        "display_name": "Exchange Administrator",
                    }
                ],
                "last_login": (
                    datetime.now(UTC) - timedelta(days=10)
                ).isoformat(),
            },
        )

        findings = producer.evaluate(resource, config)
        assert len(findings) == 0


class TestM365StorageProducers:
    """Test SharePoint storage exposure producers."""

    def test_sharepoint_anonymous_edit_link(self):
        producer = M365SharePointAnonymousLinkProducer()

        resource = ResourceEntity(
            external_id="site-1",
            resource_type="m365.sharepoint.site",
            provider="m365",
            name="Project Docs",
        )

        config = ConfigEntity(
            resource_external_id="site-1",
            captured_at=datetime.utcnow(),
            normalized_config={
                "web_url": "https://contoso.sharepoint.com/sites/project",
                "permissions": [
                    {
                        "link": {"scope": "anonymous", "type": "edit"},
                        "roles": ["write"],
                    }
                ],
                "sharing_capability": "anonymousAccess",
            },
        )

        context = {"rule_id": uuid4()}
        findings = producer.evaluate(resource, config, context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["anonymous_links"][0]["scope"] == "anonymous"
