"""Kubernetes provider implementation."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

from ..base import (
    BaseProvider,
    ConfigurationSnapshot,
    IamPermission,
    PrincipalInfo,
    ProviderError,
    ResourceInfo,
)
from ..utils.connector import call_sync_with_retries

logger = logging.getLogger(__name__)


try:  # pragma: no cover - optional dependency
    from kubernetes import client, config  # type: ignore
    from kubernetes.client import ApiException  # type: ignore
    from kubernetes.config.config_exception import ConfigException  # type: ignore

    _K8S_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    client = None  # type: ignore
    config = None  # type: ignore
    ApiException = Exception  # type: ignore
    ConfigException = Exception  # type: ignore
    _K8S_AVAILABLE = False


class KubernetesProvider(BaseProvider):
    """Collect Kubernetes resources for cluster posture analysis."""

    def __init__(
        self,
        account_id,
        cluster_name: str,
        kubeconfig_path: str | None = None,
        kube_context: str | None = None,
        verify_ssl: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(account_id, **kwargs)
        self.cluster_name = cluster_name
        self.kubeconfig_path = kubeconfig_path
        self.kube_context = kube_context
        self.verify_ssl = verify_ssl

        self._api_client: client.ApiClient | None = None
        self._core: client.CoreV1Api | None = None
        self._apps: client.AppsV1Api | None = None
        self._networking: client.NetworkingV1Api | None = None
        self._rbac: client.RbacAuthorizationV1Api | None = None
        self._cluster_version: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "kubernetes"

    async def authenticate(self) -> bool:
        if not _K8S_AVAILABLE:
            raise ProviderError(
                "kubernetes Python client is not installed; install the 'kubernetes' "
                "package"
            )

        try:
            def _load_config() -> tuple[client.ApiClient, dict[str, Any]]:
                if not self.verify_ssl:
                    config.load_kube_config(
                        config_file=self.kubeconfig_path,
                        context=self.kube_context,
                        persist_config=False,
                    )
                    cfg = client.Configuration.get_default_copy()
                    cfg.verify_ssl = False
                    api_client = client.ApiClient(configuration=cfg)
                else:
                    try:
                        if self.kubeconfig_path:
                            config.load_kube_config(
                                config_file=self.kubeconfig_path,
                                context=self.kube_context,
                            )
                        else:
                            config.load_incluster_config()
                    except ConfigException:
                        config.load_kube_config(context=self.kube_context)

                    api_client = client.ApiClient()

                version_api = client.VersionApi(api_client)
                version_info = version_api.get_code()

                cluster_version = {
                    "major": getattr(version_info, "major", None),
                    "minor": getattr(version_info, "minor", None),
                    "git_version": getattr(version_info, "git_version", None),
                    "platform": getattr(version_info, "platform", None),
                }

                return api_client, cluster_version

            api_client, cluster_version = await call_sync_with_retries(
                _load_config,
                exceptions=(ConfigException, ApiException, OSError),
                logger=logger,
            )

            self._api_client = api_client
            self._cluster_version = cluster_version
            self._core = client.CoreV1Api(api_client)
            self._apps = client.AppsV1Api(api_client)
            self._networking = client.NetworkingV1Api(api_client)
            self._rbac = client.RbacAuthorizationV1Api(api_client)
            return True
        except (ConfigException, ApiException, OSError) as exc:
            logger.error("Failed to authenticate with Kubernetes cluster: %s", exc)
            raise ProviderError(f"Kubernetes authentication failed: {exc}") from exc

    async def discover_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> AsyncGenerator[ResourceInfo, None]:
        if not self._api_client:
            await self.authenticate()

        if not resource_types or "k8s.cluster" in resource_types:
            server = None
            if self._api_client:
                server = getattr(self._api_client.configuration, "host", None)

            yield ResourceInfo(
                external_id=self.cluster_name,
                name=self.cluster_name,
                resource_type="k8s.cluster",
                metadata={
                    "version": self._cluster_version,
                    "server": server,
                },
            )

        if not resource_types or "k8s.namespace" in resource_types:
            namespaces = await call_sync_with_retries(
                lambda: self._core.list_namespace(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for namespace in namespaces.items:
                metadata = namespace.metadata
                yield ResourceInfo(
                    external_id=metadata.name,
                    name=metadata.name,
                    resource_type="k8s.namespace",
                    metadata={
                        "labels": metadata.labels or {},
                        "annotations": metadata.annotations or {},
                        "creation_timestamp": metadata.creation_timestamp.isoformat()
                        if metadata.creation_timestamp
                        else None,
                    },
                )

        if not resource_types or "k8s.node" in resource_types:
            nodes = await call_sync_with_retries(
                lambda: self._core.list_node(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for node in nodes.items:
                metadata = node.metadata
                status = node.status or client.V1NodeStatus()

                addresses = [
                    {
                        "type": address.type,
                        "address": address.address,
                    }
                    for address in status.addresses or []
                ]

                taints = []
                for taint in getattr(node.spec, "taints", []) or []:
                    taints.append(
                        {
                            "key": taint.key,
                            "value": taint.value,
                            "effect": taint.effect,
                        }
                    )

                yield ResourceInfo(
                    external_id=metadata.name,
                    name=metadata.name,
                    resource_type="k8s.node",
                    metadata={
                        "labels": metadata.labels or {},
                        "annotations": metadata.annotations or {},
                        "provider_id": getattr(node.spec, "provider_id", None),
                        "unschedulable": bool(
                            getattr(node.spec, "unschedulable", False)
                        ),
                        "addresses": addresses,
                        "taints": taints,
                    },
                )

        if not resource_types or "k8s.pod" in resource_types:
            pods = await call_sync_with_retries(
                lambda: self._core.list_pod_for_all_namespaces(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for pod in pods.items:
                metadata = pod.metadata
                external_id = f"{metadata.namespace}/{metadata.name}"
                pod_node = getattr(pod.spec, "node_name", None)
                service_account = getattr(pod.spec, "service_account_name", None)
                yield ResourceInfo(
                    external_id=external_id,
                    name=metadata.name,
                    resource_type="k8s.pod",
                    parent_external_id=metadata.namespace,
                    metadata={
                        "namespace": metadata.namespace,
                        "node": pod_node,
                        "service_account": service_account,
                    },
                )

        if not resource_types or "k8s.service" in resource_types:
            services = await call_sync_with_retries(
                lambda: self._core.list_service_for_all_namespaces(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for service in services.items:
                metadata = service.metadata
                spec = service.spec or client.V1ServiceSpec()
                status = service.status or client.V1ServiceStatus()

                external_id = f"{metadata.namespace}/{metadata.name}"
                load_balancer = []
                if status.load_balancer and status.load_balancer.ingress:
                    for ingress in status.load_balancer.ingress:
                        load_balancer.append(
                            {
                                "hostname": getattr(ingress, "hostname", None),
                                "ip": getattr(ingress, "ip", None),
                            }
                        )

                ports = [
                    {
                        "name": port.name,
                        "protocol": port.protocol,
                        "port": port.port,
                        "targetPort": getattr(port, "target_port", None),
                        "nodePort": getattr(port, "node_port", None),
                    }
                    for port in spec.ports or []
                ]

                yield ResourceInfo(
                    external_id=external_id,
                    name=metadata.name,
                    resource_type="k8s.service",
                    parent_external_id=metadata.namespace,
                    metadata={
                        "namespace": metadata.namespace,
                        "type": spec.type,
                        "cluster_ip": getattr(spec, "cluster_ip", None),
                        "cluster_ips": getattr(spec, "cluster_i_ps", None) or [],
                        "external_ips": getattr(spec, "external_i_ps", None) or [],
                        "load_balancer": load_balancer,
                        "ports": ports,
                        "selector": spec.selector or {},
                        "annotations": metadata.annotations or {},
                    },
                )

        if not resource_types or "k8s.ingress" in resource_types:
            ingresses = await call_sync_with_retries(
                lambda: self._networking.list_ingress_for_all_namespaces(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for ingress in ingresses.items:
                metadata = ingress.metadata
                external_id = f"{metadata.namespace}/{metadata.name}"
                annotations = metadata.annotations or {}
                ingress_class = (
                    ingress.spec.ingress_class_name
                    or annotations.get("kubernetes.io/ingress.class")
                )
                yield ResourceInfo(
                    external_id=external_id,
                    name=metadata.name,
                    resource_type="k8s.ingress",
                    parent_external_id=metadata.namespace,
                    metadata={
                        "namespace": metadata.namespace,
                        "ingress_class": ingress_class,
                    },
                )

        if (
            (not resource_types or "k8s.network_policy" in resource_types)
            and self._networking
        ):
            policies = await call_sync_with_retries(
                lambda: self._networking.list_network_policy_for_all_namespaces(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for policy in policies.items:
                metadata = policy.metadata
                external_id = f"{metadata.namespace}/{metadata.name}"
                yield ResourceInfo(
                    external_id=external_id,
                    name=metadata.name,
                    resource_type="k8s.network_policy",
                    parent_external_id=metadata.namespace,
                    metadata={
                        "namespace": metadata.namespace,
                    },
                )

        if not resource_types or "k8s.cluster_role_binding" in resource_types:
            cluster_role_bindings = await call_sync_with_retries(
                lambda: self._rbac.list_cluster_role_binding(),
                exceptions=(ApiException,),
                logger=logger,
            )

            for binding in cluster_role_bindings.items:
                metadata = binding.metadata
                yield ResourceInfo(
                    external_id=metadata.name,
                    name=metadata.name,
                    resource_type="k8s.cluster_role_binding",
                    metadata={
                        "labels": metadata.labels or {},
                        "annotations": metadata.annotations or {},
                    },
                )

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        if not self._api_client:
            await self.authenticate()

        service_accounts = await call_sync_with_retries(
            lambda: self._core.list_service_account_for_all_namespaces(),
            exceptions=(ApiException,),
            logger=logger,
        )

        for service_account in service_accounts.items:
            metadata = service_account.metadata
            external_id = f"{metadata.namespace}:{metadata.name}"
            secret_names = [
                secret.name for secret in service_account.secrets or []
            ]
            yield PrincipalInfo(
                external_id=external_id,
                principal_type="service_account",
                display_name=metadata.name,
                is_human=False,
                metadata={
                    "namespace": metadata.namespace,
                    "secrets": secret_names,
                    "labels": metadata.labels or {},
                },
            )

    async def get_resource_configuration(
        self,
        resource: ResourceInfo,
    ) -> ConfigurationSnapshot:
        if not self._api_client:
            await self.authenticate()

        if resource.resource_type == "k8s.cluster":
            normalized_config = {
                "cluster": self.cluster_name,
                "server": getattr(self._api_client.configuration, "host", None)
                if self._api_client
                else None,
                "version": self._cluster_version,
            }
        elif resource.resource_type == "k8s.namespace":
            namespace = await call_sync_with_retries(
                lambda: self._core.read_namespace(name=resource.external_id),
                exceptions=(ApiException,),
                logger=logger,
            )
            network_policies: list[Any] = []
            if self._networking:
                try:
                    policy_list = await call_sync_with_retries(
                        lambda: self._networking.list_namespaced_network_policy(
                            namespace=resource.external_id
                        ),
                        exceptions=(ApiException,),
                        logger=logger,
                    )
                    network_policies = policy_list.items or []
                except ApiException as exc:  # pragma: no cover - logged for visibility
                    logger.warning(
                        "Failed to list network policies for namespace %s: %s",
                        resource.external_id,
                        exc,
                    )

            normalized_config = self._build_namespace_config(
                namespace,
                network_policies=network_policies,
            )
        elif resource.resource_type == "k8s.pod":
            namespace, name = self._split_namespaced_name(resource.external_id)
            pod = await call_sync_with_retries(
                lambda: self._core.read_namespaced_pod(name=name, namespace=namespace),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_pod_config(pod)
        elif resource.resource_type == "k8s.ingress":
            namespace, name = self._split_namespaced_name(resource.external_id)
            ingress = await call_sync_with_retries(
                lambda: self._networking.read_namespaced_ingress(
                    name=name, namespace=namespace
                ),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_ingress_config(ingress)
        elif resource.resource_type == "k8s.service":
            namespace, name = self._split_namespaced_name(resource.external_id)
            service = await call_sync_with_retries(
                lambda: self._core.read_namespaced_service(
                    name=name, namespace=namespace
                ),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_service_config(service)
        elif resource.resource_type == "k8s.node":
            node = await call_sync_with_retries(
                lambda: self._core.read_node(name=resource.external_id),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_node_config(node)
        elif resource.resource_type == "k8s.cluster_role_binding":
            binding = await call_sync_with_retries(
                lambda: self._rbac.read_cluster_role_binding(name=resource.external_id),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_cluster_role_binding_config(binding)
        elif resource.resource_type == "k8s.network_policy" and self._networking:
            namespace, name = self._split_namespaced_name(resource.external_id)
            policy = await call_sync_with_retries(
                lambda: self._networking.read_namespaced_network_policy(
                    name=name, namespace=namespace
                ),
                exceptions=(ApiException,),
                logger=logger,
            )
            normalized_config = self._build_network_policy_config(policy)
        else:
            normalized_config = {}

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=normalized_config,
            raw_config=None,
        )

    async def discover_iam_edges(
        self,
        resource: ResourceInfo | None = None,
    ) -> AsyncGenerator[IamPermission, None]:
        # Kubernetes RBAC ingestion is not yet implemented.
        if False:  # pragma: no cover - placeholder to satisfy async generator typing
            yield

    def _split_namespaced_name(self, value: str) -> tuple[str, str]:
        if "/" in value:
            namespace, name = value.split("/", 1)
            return namespace, name
        return "default", value

    def _build_namespace_config(
        self,
        namespace: client.V1Namespace,
        *,
        network_policies: list[Any] | None = None,
    ) -> dict[str, Any]:
        metadata = namespace.metadata
        return {
            "name": metadata.name,
            "labels": metadata.labels or {},
            "annotations": metadata.annotations or {},
            "status": getattr(namespace.status, "phase", None),
            "creation_timestamp": metadata.creation_timestamp.isoformat()
            if metadata.creation_timestamp
            else None,
            "networkPolicies": [
                self._summarize_network_policy(policy)
                for policy in network_policies or []
            ],
        }

    def _build_pod_config(self, pod: client.V1Pod) -> dict[str, Any]:
        metadata = pod.metadata
        spec = pod.spec
        status = pod.status

        return {
            "name": metadata.name,
            "namespace": metadata.namespace,
            "node": getattr(spec, "node_name", None),
            "serviceAccount": getattr(spec, "service_account_name", None),
            "automountServiceAccountToken": getattr(
                spec, "automount_service_account_token", None
            ),
            "labels": metadata.labels or {},
            "annotations": metadata.annotations or {},
            "hostNetwork": bool(getattr(spec, "host_network", False)),
            "hostPID": bool(getattr(spec, "host_pid", False)),
            "hostIPC": bool(getattr(spec, "host_ipc", False)),
            "containers": [
                self._build_container_config(container)
                for container in spec.containers or []
            ],
            "initContainers": [
                self._build_container_config(container)
                for container in spec.init_containers or []
            ],
            "volumes": [
                self._build_volume_config(volume) for volume in spec.volumes or []
            ],
            "conditions": [
                {
                    "type": condition.type,
                    "status": condition.status,
                }
                for condition in status.conditions or []
            ]
            if status
            else [],
        }

    def _build_ingress_config(self, ingress: client.V1Ingress) -> dict[str, Any]:
        metadata = ingress.metadata
        spec = ingress.spec or client.V1IngressSpec()
        status = ingress.status or client.V1IngressStatus()

        load_balancer = []
        if status.load_balancer and status.load_balancer.ingress:
            for lb in status.load_balancer.ingress:
                load_balancer.append(
                    {
                        "hostname": getattr(lb, "hostname", None),
                        "ip": getattr(lb, "ip", None),
                    }
                )

        rules = []
        for rule in spec.rules or []:
            http_paths = []
            if rule.http and rule.http.paths:
                for path in rule.http.paths:
                    http_paths.append(
                        {
                            "path": getattr(path, "path", None),
                            "pathType": getattr(path, "path_type", None),
                            "backend": self._get_backend_target(path.backend),
                        }
                    )
            rules.append({"host": getattr(rule, "host", None), "paths": http_paths})

        tls_entries = []
        for tls in spec.tls or []:
            tls_entries.append(
                {
                    "hosts": tls.hosts or [],
                    "secretName": tls.secret_name,
                }
            )

        annotations = metadata.annotations or {}
        ingress_class = (
            spec.ingress_class_name or annotations.get("kubernetes.io/ingress.class")
        )

        return {
            "name": metadata.name,
            "namespace": metadata.namespace,
            "ingressClass": ingress_class,
            "annotations": annotations,
            "labels": metadata.labels or {},
            "rules": rules,
            "tls": tls_entries,
            "loadBalancer": load_balancer,
        }

    def _build_service_config(self, service: client.V1Service) -> dict[str, Any]:
        metadata = service.metadata
        spec = service.spec or client.V1ServiceSpec()
        status = service.status or client.V1ServiceStatus()

        ports = [
            {
                "name": port.name,
                "protocol": port.protocol,
                "port": port.port,
                "targetPort": getattr(port, "target_port", None),
                "nodePort": getattr(port, "node_port", None),
            }
            for port in spec.ports or []
        ]

        load_balancer = []
        if status.load_balancer and status.load_balancer.ingress:
            for ingress in status.load_balancer.ingress:
                load_balancer.append(
                    {
                        "hostname": getattr(ingress, "hostname", None),
                        "ip": getattr(ingress, "ip", None),
                    }
                )

        return {
            "name": metadata.name,
            "namespace": metadata.namespace,
            "type": spec.type,
            "clusterIP": getattr(spec, "cluster_ip", None),
            "clusterIPs": getattr(spec, "cluster_i_ps", None) or [],
            "externalIPs": getattr(spec, "external_i_ps", None) or [],
            "externalName": getattr(spec, "external_name", None),
            "externalTrafficPolicy": getattr(spec, "external_traffic_policy", None),
            "loadBalancerIP": getattr(spec, "load_balancer_ip", None),
            "loadBalancerSourceRanges": getattr(
                spec, "load_balancer_source_ranges", []
            ),
            "selector": spec.selector or {},
            "ports": ports,
            "sessionAffinity": getattr(spec, "session_affinity", None),
            "loadBalancer": load_balancer,
            "annotations": metadata.annotations or {},
        }

    def _build_node_config(self, node: client.V1Node) -> dict[str, Any]:
        metadata = node.metadata
        status = node.status or client.V1NodeStatus()
        spec = node.spec or client.V1NodeSpec()

        addresses = [
            {
                "type": address.type,
                "address": address.address,
            }
            for address in status.addresses or []
        ]

        taints = []
        for taint in spec.taints or []:
            taints.append(
                {
                    "key": taint.key,
                    "value": taint.value,
                    "effect": taint.effect,
                }
            )

        conditions = []
        for condition in status.conditions or []:
            conditions.append(
                {
                    "type": condition.type,
                    "status": condition.status,
                    "reason": getattr(condition, "reason", None),
                }
            )

        return {
            "name": metadata.name,
            "labels": metadata.labels or {},
            "annotations": metadata.annotations or {},
            "providerID": getattr(spec, "provider_id", None),
            "unschedulable": bool(getattr(spec, "unschedulable", False)),
            "addresses": addresses,
            "taints": taints,
            "conditions": conditions,
            "creation_timestamp": metadata.creation_timestamp.isoformat()
            if metadata.creation_timestamp
            else None,
        }

    def _build_cluster_role_binding_config(
        self, binding: client.V1ClusterRoleBinding
    ) -> dict[str, Any]:
        metadata = binding.metadata
        subjects = binding.subjects or []
        normalized_subjects = []
        for subject in subjects:
            normalized_subjects.append(
                {
                    "kind": getattr(subject, "kind", None),
                    "name": getattr(subject, "name", None),
                    "namespace": getattr(subject, "namespace", None),
                    "apiGroup": getattr(subject, "api_group", None),
                }
            )

        role_ref = binding.role_ref

        return {
            "name": metadata.name,
            "annotations": metadata.annotations or {},
            "labels": metadata.labels or {},
            "subjects": normalized_subjects,
            "roleRef": {
                "apiGroup": getattr(role_ref, "api_group", None),
                "kind": getattr(role_ref, "kind", None),
                "name": getattr(role_ref, "name", None),
            },
        }

    def _build_network_policy_config(
        self, policy: client.V1NetworkPolicy
    ) -> dict[str, Any]:
        metadata = policy.metadata
        spec = policy.spec or client.V1NetworkPolicySpec()
        selector = spec.pod_selector or client.V1LabelSelector()

        def _summarize_peers(peers: list[Any] | None) -> list[dict[str, Any]]:
            summarized: list[dict[str, Any]] = []
            for peer in peers or []:
                summarized.append(
                    {
                        "podSelector": self._describe_label_selector(
                            getattr(peer, "pod_selector", None)
                        ),
                        "namespaceSelector": self._describe_label_selector(
                            getattr(peer, "namespace_selector", None)
                        ),
                        "ipBlock": {
                            "cidr": getattr(peer.ip_block, "cidr", None),
                            "except": getattr(peer.ip_block, "_except", None) or [],
                        }
                        if getattr(peer, "ip_block", None)
                        else None,
                    }
                )
            return summarized

        def _summarize_ports(ports: list[Any] | None) -> list[dict[str, Any]]:
            summarized: list[dict[str, Any]] = []
            for port in ports or []:
                summarized.append(
                    {
                        "port": getattr(port, "port", None),
                        "protocol": getattr(port, "protocol", None),
                    }
                )
            return summarized

        ingress_rules = []
        for rule in spec.ingress or []:
            ingress_rules.append(
                {
                    "from": _summarize_peers(getattr(rule, "_from", None)),
                    "ports": _summarize_ports(getattr(rule, "ports", None)),
                }
            )

        egress_rules = []
        for rule in spec.egress or []:
            egress_rules.append(
                {
                    "to": _summarize_peers(getattr(rule, "to", None)),
                    "ports": _summarize_ports(getattr(rule, "ports", None)),
                }
            )

        return {
            "name": metadata.name,
            "namespace": metadata.namespace,
            "policyTypes": spec.policy_types or ["Ingress"],
            "podSelector": self._describe_label_selector(selector),
            "ingress": ingress_rules,
            "egress": egress_rules,
        }

    def _build_container_config(self, container: client.V1Container) -> dict[str, Any]:
        security_context = container.security_context
        capabilities = getattr(security_context, "capabilities", None)
        add_caps = capabilities.add if capabilities and capabilities.add else []
        drop_caps = capabilities.drop if capabilities and capabilities.drop else []

        return {
            "name": container.name,
            "image": container.image,
            "securityContext": {
                "privileged": getattr(security_context, "privileged", None),
                "allowPrivilegeEscalation": getattr(
                    security_context, "allow_privilege_escalation", None
                ),
                "readOnlyRootFilesystem": getattr(
                    security_context, "read_only_root_filesystem", None
                ),
                "runAsNonRoot": getattr(security_context, "run_as_non_root", None),
                "runAsUser": getattr(security_context, "run_as_user", None),
                "runAsGroup": getattr(security_context, "run_as_group", None),
                "capabilities": {
                    "add": add_caps,
                    "drop": drop_caps,
                },
            },
            "volumeMounts": [
                {
                    "name": mount.name,
                    "mountPath": mount.mount_path,
                    "readOnly": mount.read_only,
                }
                for mount in container.volume_mounts or []
            ],
            "env": [
                {
                    "name": env_var.name,
                    "value": env_var.value,
                    "valueFrom": self._describe_env_source(env_var.value_from),
                }
                for env_var in container.env or []
            ],
        }

    def _build_volume_config(self, volume: client.V1Volume) -> dict[str, Any]:
        host_path = getattr(volume, "host_path", None)
        projected = getattr(volume, "projected", None)

        projected_sources: list[dict[str, Any]] | None = None
        if projected and projected.sources:
            projected_sources = []
            for source in projected.sources:
                token = getattr(source, "service_account_token", None)
                if token:
                    projected_sources.append(
                        {
                            "type": "serviceAccountToken",
                            "audience": getattr(token, "audience", None),
                            "expirationSeconds": getattr(
                                token, "expiration_seconds", None
                            ),
                            "path": getattr(token, "path", None),
                        }
                    )
                    continue

                config_map = getattr(source, "config_map", None)
                if config_map:
                    projected_sources.append(
                        {
                            "type": "configMap",
                            "name": getattr(config_map, "name", None),
                            "items": [
                                {
                                    "key": item.key,
                                    "path": item.path,
                                }
                                for item in getattr(config_map, "items", []) or []
                            ],
                        }
                    )
                    continue

                secret = getattr(source, "secret", None)
                if secret:
                    projected_sources.append(
                        {
                            "type": "secret",
                            "name": getattr(secret, "name", None),
                            "items": [
                                {
                                    "key": item.key,
                                    "path": item.path,
                                }
                                for item in getattr(secret, "items", []) or []
                            ],
                        }
                    )
                    continue

                downward_api = getattr(source, "downward_api", None)
                if downward_api:
                    projected_sources.append(
                        {
                            "type": "downwardAPI",
                            "items": [
                                {
                                    "path": item.path,
                                    "fieldRef": (
                                        {
                                            "fieldPath": getattr(
                                                item.field_ref, "field_path", None
                                            )
                                        }
                                        if item.field_ref
                                        else None
                                    ),
                                    "resourceFieldRef": (
                                        {
                                            "containerName": getattr(
                                                item.resource_field_ref,
                                                "container_name",
                                                None,
                                            ),
                                            "resource": getattr(
                                                item.resource_field_ref,
                                                "resource",
                                                None,
                                            ),
                                        }
                                        if item.resource_field_ref
                                        else None
                                    ),
                                }
                                for item in getattr(downward_api, "items", []) or []
                            ],
                        }
                    )
                    continue

                projected_sources.append({"type": "unknown"})

        return {
            "name": volume.name,
            "hostPath": {
                "path": host_path.path,
                "type": host_path.type,
            }
            if host_path
            else None,
            "projectedSources": projected_sources,
        }

    def _summarize_network_policy(
        self,
        policy: client.V1NetworkPolicy,
    ) -> dict[str, Any]:
        spec = policy.spec or client.V1NetworkPolicySpec()
        selector = spec.pod_selector or client.V1LabelSelector()
        selects_all = not (
            getattr(selector, "match_labels", None) or selector.match_expressions
        )

        return {
            "name": policy.metadata.name,
            "policyTypes": spec.policy_types or ["Ingress"],
            "selectsAllPods": selects_all,
            "ingressRuleCount": len(spec.ingress or []),
            "egressRuleCount": len(spec.egress or []),
        }

    def _describe_env_source(self, value_from: Any) -> dict[str, Any] | None:
        if not value_from:
            return None

        if value_from.secret_key_ref:
            return {
                "type": "secret",
                "name": value_from.secret_key_ref.name,
                "key": value_from.secret_key_ref.key,
            }

        if value_from.config_map_key_ref:
            return {
                "type": "configMap",
                "name": value_from.config_map_key_ref.name,
                "key": value_from.config_map_key_ref.key,
            }

        if value_from.field_ref:
            return {
                "type": "fieldRef",
                "fieldPath": value_from.field_ref.field_path,
            }

        return None

    def _get_backend_target(self, backend: Any) -> dict[str, Any] | None:
        if not backend:
            return None

        target = {}
        service = getattr(backend, "service", None)
        if service:
            target["service"] = {
                "name": service.name,
                "port": getattr(service.port, "number", None)
                or getattr(service.port, "name", None),
            }

        resource = getattr(backend, "resource", None)
        if resource:
            target["resource"] = {
                "apiGroup": resource.api_group,
                "kind": resource.kind,
                "name": resource.name,
            }

        return target or None

    def _describe_label_selector(self, selector: Any) -> dict[str, Any] | None:
        if not selector:
            return None

        match_labels = getattr(selector, "match_labels", None) or {}
        match_expressions = []
        for expression in getattr(selector, "match_expressions", []) or []:
            match_expressions.append(
                {
                    "key": getattr(expression, "key", None),
                    "operator": getattr(expression, "operator", None),
                    "values": getattr(expression, "values", None) or [],
                }
            )

        if not match_labels and not match_expressions:
            return None

        return {
            "matchLabels": match_labels,
            "matchExpressions": match_expressions,
        }
