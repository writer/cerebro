#![forbid(unsafe_code)]

//! Closed, content-addressed Action definitions.
//!
//! The canonical catalog source lives with this crate. The retiring Go registry
//! is generated as a compatibility consumer. New Action proposals must bind one
//! exact generated definition; stored historical operations retain their
//! original digest.

mod generated;

use std::{error::Error, fmt};

use cerebro_platform_sdk::{ActionProposal, SdkError};
use serde::Serialize;
use sha2::{Digest, Sha256};

const ACTION_DEFINITION_DIGEST_SCHEMA: &str = "cerebro.action-definition.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ActionDefinition<'a> {
    pub id: &'a str,
    pub provider: &'a str,
    pub provider_action: &'a str,
    pub target_kind: &'a str,
    pub effect: &'a str,
    pub destructive: bool,
    pub reversible_by: &'a str,
    pub definition_digest: &'a str,
}

impl ActionDefinition<'_> {
    pub fn computed_digest(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            id: &'a str,
            provider: &'a str,
            provider_action: &'a str,
            target_kind: &'a str,
            effect: &'a str,
            destructive: bool,
            reversible_by: &'a str,
        }

        let material = DigestMaterial {
            schema: ACTION_DEFINITION_DIGEST_SCHEMA,
            id: self.id,
            provider: self.provider,
            provider_action: self.provider_action,
            target_kind: self.target_kind,
            effect: self.effect,
            destructive: self.destructive,
            reversible_by: self.reversible_by,
        };
        let digest = Sha256::digest(serde_json::to_vec(&material)?);
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(encoded)
    }
}

#[derive(Debug)]
pub enum ActionCatalogError {
    InvalidProposal(SdkError),
    UnknownActionKind(String),
    DefinitionDigestMismatch { action_kind: String },
    EffectMismatch { action_kind: String },
    EffectTargetMismatch { action_kind: String },
}

impl fmt::Display for ActionCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProposal(error) => write!(formatter, "{error}"),
            Self::UnknownActionKind(action_kind) => {
                write!(formatter, "unknown Action kind {action_kind:?}")
            }
            Self::DefinitionDigestMismatch { action_kind } => {
                write!(
                    formatter,
                    "Action definition digest does not match {action_kind:?}"
                )
            }
            Self::EffectMismatch { action_kind } => {
                write!(
                    formatter,
                    "Action expected effect does not match {action_kind:?}"
                )
            }
            Self::EffectTargetMismatch { action_kind } => {
                write!(
                    formatter,
                    "Action expected effect target does not match {action_kind:?}"
                )
            }
        }
    }
}

impl Error for ActionCatalogError {}

impl From<SdkError> for ActionCatalogError {
    fn from(value: SdkError) -> Self {
        Self::InvalidProposal(value)
    }
}

pub fn definitions() -> &'static [ActionDefinition<'static>] {
    generated::ACTION_DEFINITIONS
}

pub fn lookup(action_kind: &str) -> Result<&'static ActionDefinition<'static>, ActionCatalogError> {
    definitions()
        .iter()
        .find(|definition| definition.id == action_kind)
        .ok_or_else(|| ActionCatalogError::UnknownActionKind(action_kind.to_owned()))
}

pub fn validate_proposal(
    proposal: &ActionProposal,
) -> Result<&'static ActionDefinition<'static>, ActionCatalogError> {
    proposal.validate()?;
    let definition = lookup(&proposal.action_kind)?;
    if proposal.action_definition_digest.as_str() != definition.definition_digest {
        return Err(ActionCatalogError::DefinitionDigestMismatch {
            action_kind: proposal.action_kind.clone(),
        });
    }
    for effect in &proposal.expected_effects {
        if effect.effect_kind != definition.effect {
            return Err(ActionCatalogError::EffectMismatch {
                action_kind: proposal.action_kind.clone(),
            });
        }
        if effect.target_id != proposal.target_id {
            return Err(ActionCatalogError::EffectTargetMismatch {
                action_kind: proposal.action_kind.clone(),
            });
        }
    }
    Ok(definition)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cerebro_platform_sdk::{
        ActionEffect, ActionOperationId, ActionProposal, ActorId, ContentDigest, GraphRevision,
        OpaqueId, TenantId,
    };

    use super::*;

    fn proposal(definition: &ActionDefinition<'_>) -> ActionProposal {
        let target = OpaqueId::parse("target:one").expect("target");
        let mut proposal = ActionProposal {
            operation_id: ActionOperationId::parse("operation:one").expect("operation"),
            tenant_id: TenantId::parse("tenant-one").expect("tenant"),
            finding_id: OpaqueId::parse("finding:one").expect("finding"),
            finding_revision_digest: ContentDigest::of_bytes("finding"),
            finding_validation_receipt_digest: ContentDigest::of_bytes("validation"),
            graph_revision: GraphRevision::new(1).expect("revision"),
            action_kind: definition.id.to_owned(),
            action_definition_digest: ContentDigest::parse(definition.definition_digest)
                .expect("generated digest"),
            target_id: target.clone(),
            expected_effects: vec![ActionEffect {
                target_id: target,
                effect_kind: definition.effect.to_owned(),
                expected_state_digest: ContentDigest::of_bytes("expected state"),
            }],
            rollback_ref: OpaqueId::parse("rollback:one").expect("rollback"),
            idempotency_key: OpaqueId::parse("idempotency:one").expect("idempotency"),
            simulation_digest: ContentDigest::of_bytes("simulation"),
            verification_plan_digest: ContentDigest::of_bytes("verification"),
            proposed_by: ActorId::parse("actor:one").expect("actor"),
            proposed_at_unix_ms: 10,
            proposal_expires_at_unix_ms: 20,
            proposal_digest: ContentDigest::of_bytes("placeholder"),
        };
        proposal.bind_computed_digest().expect("proposal digest");
        proposal
    }

    #[test]
    fn generated_definitions_are_unique_and_content_addressed() {
        assert!(!definitions().is_empty());
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for definition in definitions() {
            assert!(ids.insert(definition.id));
            assert!(digests.insert(definition.definition_digest));
            assert_eq!(
                definition.computed_digest().expect("digest"),
                definition.definition_digest
            );
            if !definition.reversible_by.is_empty() {
                lookup(definition.reversible_by).expect("reversible Action must exist");
            }
        }
    }

    #[test]
    fn proposal_must_bind_the_generated_definition_and_effect() {
        let definition = definitions().first().expect("generated definition");
        validate_proposal(&proposal(definition)).expect("valid proposal");

        let mut unknown = proposal(definition);
        unknown.action_kind = "identity.unknown.mutate".to_owned();
        unknown.bind_computed_digest().expect("proposal digest");
        assert!(matches!(
            validate_proposal(&unknown),
            Err(ActionCatalogError::UnknownActionKind(_))
        ));

        let mut digest = proposal(definition);
        digest.action_definition_digest = ContentDigest::of_bytes("attacker definition");
        digest.bind_computed_digest().expect("proposal digest");
        assert!(matches!(
            validate_proposal(&digest),
            Err(ActionCatalogError::DefinitionDigestMismatch { .. })
        ));

        let mut effect = proposal(definition);
        effect.expected_effects[0].effect_kind = "attacker_effect".to_owned();
        effect.bind_computed_digest().expect("proposal digest");
        assert!(matches!(
            validate_proposal(&effect),
            Err(ActionCatalogError::EffectMismatch { .. })
        ));

        let mut target = proposal(definition);
        target.expected_effects[0].target_id =
            OpaqueId::parse("target:other").expect("other target");
        target.bind_computed_digest().expect("proposal digest");
        assert!(matches!(
            validate_proposal(&target),
            Err(ActionCatalogError::EffectTargetMismatch { .. })
        ));
    }
}
