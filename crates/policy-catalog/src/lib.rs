#![forbid(unsafe_code)]

//! Closed, content-addressed policy definitions used by Rust authority paths.

mod generated;

use std::{error::Error, fmt};

use cerebro_platform_sdk::{FindingValidationReceipt, SdkError};
use serde::Serialize;
use sha2::{Digest, Sha256};

const POLICY_DEFINITION_DIGEST_SCHEMA: &str = "cerebro.policy-definition.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyDefinition<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub domain: &'a str,
    pub severity: &'a str,
    pub effect: &'a str,
    pub resource: &'a str,
    pub enabled: bool,
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
            source_path: self.source_path,
            source_digest: self.source_digest,
        };
        Ok(hex_digest(&serde_json::to_vec(&material)?))
    }
}

#[derive(Debug)]
pub enum PolicyCatalogError {
    InvalidReceipt(SdkError),
    UnknownPolicy(String),
    DefinitionDigestMismatch { policy_id: String },
}

impl fmt::Display for PolicyCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReceipt(error) => write!(formatter, "{error}"),
            Self::UnknownPolicy(policy_id) => write!(formatter, "unknown policy {policy_id:?}"),
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

pub fn lookup(policy_id: &str) -> Result<&'static PolicyDefinition<'static>, PolicyCatalogError> {
    definitions()
        .binary_search_by_key(&policy_id, |definition| definition.id)
        .map(|index| &definitions()[index])
        .map_err(|_| PolicyCatalogError::UnknownPolicy(policy_id.to_owned()))
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
