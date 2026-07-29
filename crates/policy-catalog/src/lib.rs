#![forbid(unsafe_code)]

//! Closed, content-addressed policy definitions used by Rust authority paths.

mod generated;

use std::{error::Error, fmt};

use cerebro_platform_sdk::{FindingValidationReceipt, SdkError};
use serde::Serialize;
use sha2::{Digest, Sha256};

const POLICY_DEFINITION_DIGEST_SCHEMA: &str = "cerebro.policy-definition.v2";
const DETECTION_DEFINITION_DIGEST_SCHEMA: &str = "cerebro.detection-definition.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationMode {
    Event,
    Graph,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    DurableState,
    AuditEvidence,
    TtlEvidence,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAnchor {
    GraphAnchored,
    SourceState,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Lifecycle {
    pub kind: LifecycleKind,
    pub anchor: LifecycleAnchor,
    pub ttl_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RequiredAttributesByKind<'a> {
    pub event_kind: &'a str,
    pub attributes: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyDefinition<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub domain: &'a str,
    pub severity: &'a str,
    pub effect: &'a str,
    pub resource: &'a str,
    pub enabled: bool,
    pub evaluation_mode: EvaluationMode,
    pub event_kinds: &'a [&'a str],
    pub output_kind: &'a str,
    pub required_attributes: &'a [&'a str],
    pub required_attributes_by_kind: &'a [RequiredAttributesByKind<'a>],
    pub fingerprint_fields: &'a [&'a str],
    pub lifecycle: Lifecycle,
    pub source_path: &'a str,
    pub source_digest: &'a str,
    pub definition_digest: &'a str,
}

impl PolicyDefinition<'_> {
    pub fn computed_digest(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            id: &'a str,
            name: &'a str,
            domain: &'a str,
            severity: &'a str,
            effect: &'a str,
            resource: &'a str,
            enabled: bool,
            evaluation_mode: EvaluationMode,
            event_kinds: &'a [&'a str],
            output_kind: &'a str,
            required_attributes: &'a [&'a str],
            required_attributes_by_kind: &'a [RequiredAttributesByKind<'a>],
            fingerprint_fields: &'a [&'a str],
            lifecycle: Lifecycle,
            source_path: &'a str,
            source_digest: &'a str,
        }

        let material = DigestMaterial {
            schema: POLICY_DEFINITION_DIGEST_SCHEMA,
            id: self.id,
            name: self.name,
            domain: self.domain,
            severity: self.severity,
            effect: self.effect,
            resource: self.resource,
            enabled: self.enabled,
            evaluation_mode: self.evaluation_mode,
            event_kinds: self.event_kinds,
            output_kind: self.output_kind,
            required_attributes: self.required_attributes,
            required_attributes_by_kind: self.required_attributes_by_kind,
            fingerprint_fields: self.fingerprint_fields,
            lifecycle: self.lifecycle,
            source_path: self.source_path,
            source_digest: self.source_digest,
        };
        Ok(hex_digest(&serde_json::to_vec(&material)?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DetectionDefinition<'a> {
    pub id: &'a str,
    pub source_id: &'a str,
    pub evaluation_mode: EvaluationMode,
    pub event_kinds: &'a [&'a str],
    pub output_kind: &'a str,
    pub required_attributes: &'a [&'a str],
    pub required_attributes_by_kind: &'a [RequiredAttributesByKind<'a>],
    pub fingerprint_fields: &'a [&'a str],
    pub lifecycle: Lifecycle,
    pub definition_digest: &'a str,
}

impl DetectionDefinition<'_> {
    pub fn computed_digest(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            id: &'a str,
            source_id: &'a str,
            evaluation_mode: EvaluationMode,
            event_kinds: &'a [&'a str],
            output_kind: &'a str,
            required_attributes: &'a [&'a str],
            required_attributes_by_kind: &'a [RequiredAttributesByKind<'a>],
            fingerprint_fields: &'a [&'a str],
            lifecycle: Lifecycle,
        }

        let material = DigestMaterial {
            schema: DETECTION_DEFINITION_DIGEST_SCHEMA,
            id: self.id,
            source_id: self.source_id,
            evaluation_mode: self.evaluation_mode,
            event_kinds: self.event_kinds,
            output_kind: self.output_kind,
            required_attributes: self.required_attributes,
            required_attributes_by_kind: self.required_attributes_by_kind,
            fingerprint_fields: self.fingerprint_fields,
            lifecycle: self.lifecycle,
        };
        Ok(hex_digest(&serde_json::to_vec(&material)?))
    }
}

#[derive(Debug)]
pub enum PolicyCatalogError {
    InvalidReceipt(SdkError),
    UnknownPolicy(String),
    UnknownDetection(String),
    DefinitionDigestMismatch { policy_id: String },
}

impl fmt::Display for PolicyCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReceipt(error) => write!(formatter, "{error}"),
            Self::UnknownPolicy(policy_id) => write!(formatter, "unknown policy {policy_id:?}"),
            Self::UnknownDetection(detection_id) => {
                write!(formatter, "unknown detection {detection_id:?}")
            }
            Self::DefinitionDigestMismatch { policy_id } => {
                write!(
                    formatter,
                    "policy definition digest does not match {policy_id:?}"
                )
            }
        }
    }
}

impl Error for PolicyCatalogError {}

impl From<SdkError> for PolicyCatalogError {
    fn from(value: SdkError) -> Self {
        Self::InvalidReceipt(value)
    }
}

pub fn definitions() -> &'static [PolicyDefinition<'static>] {
    generated::POLICY_DEFINITIONS
}

pub fn detection_definitions() -> &'static [DetectionDefinition<'static>] {
    generated::DETECTION_DEFINITIONS
}

pub fn lookup(policy_id: &str) -> Result<&'static PolicyDefinition<'static>, PolicyCatalogError> {
    definitions()
        .binary_search_by_key(&policy_id, |definition| definition.id)
        .map(|index| &definitions()[index])
        .map_err(|_| PolicyCatalogError::UnknownPolicy(policy_id.to_owned()))
}

pub fn lookup_detection(
    detection_id: &str,
) -> Result<&'static DetectionDefinition<'static>, PolicyCatalogError> {
    detection_definitions()
        .binary_search_by_key(&detection_id, |definition| definition.id)
        .map(|index| &detection_definitions()[index])
        .map_err(|_| PolicyCatalogError::UnknownDetection(detection_id.to_owned()))
}

pub fn validate_finding_receipt(
    receipt: &FindingValidationReceipt,
) -> Result<&'static PolicyDefinition<'static>, PolicyCatalogError> {
    receipt.validate()?;
    let definition = lookup(receipt.policy_id.as_str())?;
    if receipt.policy_definition_digest.as_str() != definition.definition_digest {
        return Err(PolicyCatalogError::DefinitionDigestMismatch {
            policy_id: receipt.policy_id.clone(),
        });
    }
    Ok(definition)
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cerebro_platform_sdk::{
        ActorId, ContentDigest, FindingValidationDecision, FindingValidationReceipt, GraphRevision,
        OpaqueId, TenantId,
    };

    use super::*;

    fn receipt(definition: &PolicyDefinition<'_>) -> FindingValidationReceipt {
        let mut receipt = FindingValidationReceipt {
            tenant_id: TenantId::parse("tenant:one").unwrap(),
            finding_id: OpaqueId::parse("finding:one").unwrap(),
            finding_revision_digest: ContentDigest::of_bytes("finding"),
            graph_revision: GraphRevision::new(1).unwrap(),
            policy_id: definition.id.to_owned(),
            policy_definition_digest: ContentDigest::parse(definition.definition_digest).unwrap(),
            decision: FindingValidationDecision::Confirmed,
            evidence_digests: vec![ContentDigest::of_bytes("evidence")],
            validated_by: ActorId::parse("validator:one").unwrap(),
            validated_at_unix_ms: 10,
            expires_at_unix_ms: 20,
            receipt_digest: ContentDigest::of_bytes("placeholder"),
        };
        receipt.bind_computed_digest().unwrap();
        receipt
    }

    #[test]
    fn generated_definitions_are_unique_sorted_and_content_addressed() {
        assert!(definitions().len() > 1_000);
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut previous = None;
        for definition in definitions() {
            if let Some(previous) = previous {
                assert!(previous < definition.id);
            }
            previous = Some(definition.id);
            assert!(ids.insert(definition.id));
            assert!(digests.insert(definition.definition_digest));
            assert_eq!(
                definition.computed_digest().expect("digest"),
                definition.definition_digest
            );
            assert_eq!(definition.source_digest.len(), 64);
        }
    }

    #[test]
    fn generated_detection_definitions_preserve_go_rule_semantics() {
        assert_eq!(definitions().len() + detection_definitions().len(), 1_617);
        assert_eq!(detection_definitions().len(), 86);

        let mut ids = BTreeSet::new();
        let mut previous = None;
        for definition in detection_definitions() {
            if let Some(previous) = previous {
                assert!(previous < definition.id);
            }
            previous = Some(definition.id);
            assert!(ids.insert(definition.id));
            assert!(
                !definition.fingerprint_fields.is_empty()
                    || definition.lifecycle.kind == LifecycleKind::Retired
            );
            assert_eq!(
                definition.computed_digest().expect("digest"),
                definition.definition_digest
            );
        }

        let runtime = lookup_detection("runtime-active-threat-evidence").unwrap();
        assert_eq!(runtime.evaluation_mode, EvaluationMode::Event);
        assert_eq!(runtime.event_kinds, &["runtime.evidence"]);
        assert_eq!(
            runtime.required_attributes,
            &["evidence_id", "evidence_type"]
        );
        assert_eq!(runtime.fingerprint_fields, &["tenant_id", "evidence_id"]);
        assert_eq!(
            runtime.lifecycle,
            Lifecycle {
                kind: LifecycleKind::TtlEvidence,
                anchor: LifecycleAnchor::None,
                ttl_seconds: 86_400,
            }
        );

        let source_state = lookup_detection("tailscale-tailnet-device-approval-disabled").unwrap();
        assert_eq!(
            source_state.lifecycle,
            Lifecycle {
                kind: LifecycleKind::DurableState,
                anchor: LifecycleAnchor::SourceState,
                ttl_seconds: 0,
            }
        );

        let policy = lookup("aws-s3-bucket-no-public-access").unwrap();
        assert_eq!(
            policy.fingerprint_fields,
            &["tenant_id", "policy_id", "resource_urn", "resource_id"]
        );
        assert_eq!(
            policy.lifecycle,
            Lifecycle {
                kind: LifecycleKind::AuditEvidence,
                anchor: LifecycleAnchor::None,
                ttl_seconds: 0,
            }
        );
    }

    #[test]
    fn receipt_must_bind_a_known_exact_policy_definition() {
        let definition = definitions().first().expect("generated policy");
        validate_finding_receipt(&receipt(definition)).expect("known definition");

        let mut unknown = receipt(definition);
        unknown.policy_id = "unknown-policy".to_owned();
        unknown.bind_computed_digest().unwrap();
        assert!(matches!(
            validate_finding_receipt(&unknown),
            Err(PolicyCatalogError::UnknownPolicy(_))
        ));

        let mut digest = receipt(definition);
        digest.policy_definition_digest = ContentDigest::of_bytes("attacker policy");
        digest.bind_computed_digest().unwrap();
        assert!(matches!(
            validate_finding_receipt(&digest),
            Err(PolicyCatalogError::DefinitionDigestMismatch { .. })
        ));
    }
}
