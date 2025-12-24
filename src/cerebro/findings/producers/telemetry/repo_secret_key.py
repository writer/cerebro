"""Repository secret key producer used by telemetry ingestion."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from cerebro.analysis.secrets import identify_secret_family, validate_secret_payload
from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.telemetry.schemas import SecretsScanResult

from ..base import BaseFindingProducer, ProducerContext
from ..utils import (
    ProducerRunContext,
    build_telemetry_incident_evidence,
    resolve_rule_id,
)


class RepoSecretKeyProducer(BaseFindingProducer):
    """Evaluates repository telemetry for leaked secrets."""

    @property
    def desired_sources(self) -> set[str]:
        return {"github"}

    @property
    def resource_types(self) -> set[str]:
        return {"github.repo"}

    @property
    def finding_name(self) -> str:
        return "Repository contains leaked credentials"

    @property
    def rule_name(self) -> str:
        return "github_repo_secret_exposure"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Source repository contains embedded credentials or API keys"

    @property
    def remediation(self) -> str:
        return (
            "Purge the credential from version control history, rotate the associated "
            "secret, and implement automated scanning in CI to block future leaks."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        run_context = ProducerRunContext.ensure(context)

        findings: list[FindingEntity] = []

        secrets = config.normalized_config.get("secrets", [])
        if not secrets:
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        timestamp = run_context.get("detected_at") if run_context else None
        for item in secrets:
            scan_result = SecretsScanResult(**item["raw_payload"])
            descriptor = identify_secret_family(
                scan_result.secret_type,
                scan_result.raw_result,
            )
            validation = validate_secret_payload(scan_result)
            metadata: dict[str, Any] = {}
            if timestamp:
                metadata["detected_at"] = timestamp.isoformat()

            evidence = build_telemetry_incident_evidence(
                repository=resource.external_id,
                file_path=scan_result.file_path,
                line_number=scan_result.line_number,
                secret_type=scan_result.secret_type,
                secret_family=descriptor.family.value,
                detector=scan_result.detector_name,
                validation={
                    "status": validation.status,
                    "confidence": validation.confidence,
                    "reason": validation.reason,
                    "metadata": validation.metadata,
                },
                commit_sha=item.get("commit_sha"),
                graph_controls=descriptor.graph_controls,
                metadata=metadata,
            )

            repository_name = resource.name or resource.external_id
            summary = (
                f"{descriptor.display_name} detected in repository {repository_name} "
                f"at {scan_result.file_path}."
            )

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Credential leak: {descriptor.display_name}",
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )

            fingerprint_seed = "|".join(
                [
                    str(rule_id),
                    resource.external_id,
                    scan_result.file_path,
                    descriptor.family.value,
                ]
            )
            finding.fingerprint = sha256(fingerprint_seed.encode()).hexdigest()
            if timestamp:
                finding.first_seen = timestamp
                finding.last_seen = timestamp

            findings.append(finding)

        return findings

    def build_from_telemetry(
        self,
        resource: ResourceEntity,
        secret: SecretsScanResult,
        telemetry: dict[str, Any],
        rule_id: Any,
    ) -> FindingEntity:
        """Helper used by telemetry ingestion to construct a finding entity."""

        config = ConfigEntity(
            resource_external_id=resource.external_id,
            captured_at=telemetry["timestamp"],
            normalized_config={
                "secrets": [
                    {
                        "raw_payload": secret.model_dump(),
                        "commit_sha": telemetry.get("sha"),
                    }
                ]
            },
        )

        findings = self.evaluate(
            resource=resource,
            config=config,
            context=ProducerRunContext.ensure({"rule_id": rule_id, "detected_at": telemetry["timestamp"]}),
        )
        return findings[0]
