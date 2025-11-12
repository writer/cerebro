"""Detect Kubernetes pods with dangerous privilege settings."""

from __future__ import annotations

from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer
from cerebro.findings.producers.registry import register_producer

SENSITIVE_CAPABILITIES: set[str] = {
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "NET_ADMIN",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "SYS_TIME",
}

SENSITIVE_HOST_PATH_PREFIXES: set[str] = {
    "/var/run/docker.sock",
    "/var/run/containerd",
    "/var/run/crio",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/etc/kubernetes",
    "/var/lib/etcd",
    "/etc/ssh",
    "/root",
}


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "on"}
    return bool(value)


def _collect_capabilities(capabilities: dict[str, Any] | None) -> list[str]:
    if not capabilities:
        return []
    caps: list[str] = []
    for entry in capabilities.get("add", []) or []:
        if entry:
            caps.append(str(entry).upper())
    return caps


@register_producer
class K8sPrivilegedPodProducer(BaseFindingProducer):
    """Detect pods with privileged containers or host-level access."""

    @property
    def desired_sources(self) -> set[str]:  # pragma: no cover - simple property
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:  # pragma: no cover - simple property
        return {"k8s.pod"}

    @property
    def finding_name(self) -> str:  # pragma: no cover - simple property
        return "Kubernetes pod running with privileged or host access"

    @property
    def severity(self) -> Severity:  # pragma: no cover - simple property
        return Severity.HIGH

    @property
    def rule_name(self) -> str:  # pragma: no cover - simple property
        return "k8s_privileged_pod"

    @property
    def description(self) -> str:  # pragma: no cover - simple property
        return "Pod is configured with privileged containers or host-level access"

    @property
    def remediation(self) -> str:  # pragma: no cover - simple property
        return (
            "Remove privileged flags, host networking, and sensitive hostPath mounts. "
            "Use dedicated service accounts with minimal permissions."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: dict[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}

        exposures: list[dict[str, Any]] = []
        host_network = _normalize_bool(normalized.get("hostNetwork"))
        host_pid = _normalize_bool(normalized.get("hostPID"))
        host_ipc = _normalize_bool(normalized.get("hostIPC"))

        if host_network:
            exposures.append({"type": "host_network"})
        if host_pid:
            exposures.append({"type": "host_pid"})
        if host_ipc:
            exposures.append({"type": "host_ipc"})

        volumes = normalized.get("volumes") or []
        host_path_volumes: dict[str, dict[str, Any]] = {}
        for volume in volumes:
            host_path = volume.get("hostPath")
            if host_path and volume.get("name"):
                host_path_volumes[volume["name"]] = host_path

        for container in normalized.get("containers") or []:
            security_context = container.get("securityContext") or {}
            container_name = container.get("name")

            if _normalize_bool(security_context.get("privileged")):
                exposures.append(
                    {
                        "type": "privileged_container",
                        "container": container_name,
                    }
                )

            if _normalize_bool(security_context.get("allowPrivilegeEscalation")):
                exposures.append(
                    {
                        "type": "allow_privilege_escalation",
                        "container": container_name,
                    }
                )

            capabilities = _collect_capabilities(security_context.get("capabilities"))
            sensitive_caps = [
                cap for cap in capabilities if cap in SENSITIVE_CAPABILITIES
            ]
            if sensitive_caps:
                exposures.append(
                    {
                        "type": "sensitive_capability",
                        "container": container_name,
                        "capabilities": sensitive_caps,
                    }
                )

            for mount in container.get("volumeMounts") or []:
                name = mount.get("name")
                host_path = host_path_volumes.get(name)
                if not host_path:
                    continue

                path = str(host_path.get("path", ""))
                exposures.append(
                    {
                        "type": "host_path_mount",
                        "container": container_name,
                        "path": path,
                        "readOnly": mount.get("readOnly"),
                    }
                )

                if path == "/" or any(
                    path.startswith(prefix) for prefix in SENSITIVE_HOST_PATH_PREFIXES
                ):
                    exposures.append(
                        {
                            "type": "sensitive_host_path",
                            "container": container_name,
                            "path": path,
                        }
                    )

            for port in container.get("ports") or []:
                host_port = port.get("hostPort")
                if not host_port:
                    continue
                exposures.append(
                    {
                        "type": "host_port",
                        "container": container_name,
                        "hostPort": host_port,
                        "containerPort": port.get("containerPort"),
                        "protocol": port.get("protocol"),
                    }
                )

        if not exposures:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        severity = self.severity
        critical_conditions = {
            "host_network",
            "privileged_container",
            "sensitive_host_path",
        }
        if any(exp.get("type") in critical_conditions for exp in exposures):
            severity = Severity.CRITICAL

        summary_parts = []
        for exposure in exposures:
            exposure_type = exposure["type"]
            if exposure_type == "host_network":
                summary_parts.append("pod uses host networking")
            elif exposure_type == "host_pid":
                summary_parts.append("pod shares host PID namespace")
            elif exposure_type == "host_ipc":
                summary_parts.append("pod shares host IPC namespace")
            elif exposure_type == "privileged_container":
                summary_parts.append(
                    f"container {exposure.get('container')} runs in privileged mode"
                )
            elif exposure_type == "allow_privilege_escalation":
                summary_parts.append(
                    f"container {exposure.get('container')} allows privilege escalation"
                )
            elif exposure_type == "sensitive_capability":
                caps = ", ".join(exposure.get("capabilities", []))
                summary_parts.append(
                    f"container {exposure.get('container')} grants capabilities {caps}"
                )
            elif exposure_type == "host_path_mount":
                path = exposure.get("path")
                summary_parts.append(
                    "container " f"{exposure.get('container')} mounts host path {path}"
                )
            elif exposure_type == "sensitive_host_path":
                path = exposure.get("path")
                summary_parts.append(
                    "container "
                    f"{exposure.get('container')} mounts sensitive host path {path}"
                )
            elif exposure_type == "host_port":
                summary_parts.append(
                    f"container {exposure.get('container')} exposes host port "
                    f"{exposure.get('hostPort')}"
                )

        evidence = {
            "namespace": normalized.get("namespace"),
            "service_account": normalized.get("serviceAccount"),
            "exposures": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Kubernetes pod "
                f"{resource.name or resource.external_id} has privileged access"
            ),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]
