use std::collections::{BTreeMap, BTreeSet};

use cerebro_organizational_model::{CollectionReceipt, ObservationId};

use crate::{CollectedBatch, CollectedScope, SourceRecord};

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionSelectionRequestV1, SourceWorkerDecodeOutputV2,
    canonical_result_digest, validate_and_deduplicate_records,
};

use super::{
    AsanaError, AsanaFamily, AsanaKernel, AsanaRecord, AsanaRuntimeDefinition,
    normalize::normalize, request::validate_cursor,
};

/// One deterministic tenant-scoped Asana projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AsanaEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// One deterministic Asana projection relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AsanaRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AsanaProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AsanaEntityFact>,
    /// Deduplicated relations in canonical order.
    pub relations: Vec<AsanaRelationFact>,
}

/// Convert one validated Asana users worker result into non-authoritative graph-mapper input.
///
/// This provider-local bridge preserves the authenticated tenant, exact event
/// contract, stable identities, and validated continuation. It deliberately
/// cannot construct a complete collection, persist projection authority, or
/// advance a durable checkpoint.
pub fn asana_users_graph_batch(
    receipt: CollectionReceipt,
    output: &SourceWorkerDecodeOutputV2,
) -> Result<CollectedBatch, AsanaError> {
    let definition = AsanaRuntimeDefinition::compile(AsanaFamily::Users)?;
    let plan = SourceExecutionDispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: definition.source_id.to_owned(),
            family_id: definition.family.as_str().to_owned(),
        })
        .map_err(|_| AsanaError::EventContractRejection)?;
    let safe_receipt = output
        .receipt
        .as_ref()
        .ok_or(AsanaError::EventContractRejection)?;
    let result = output
        .result
        .as_ref()
        .ok_or(AsanaError::EventContractRejection)?;
    let tenant_id = receipt.tenant_id().as_str();
    let runtime_id = receipt.source_runtime_id().as_str();
    if receipt.scope() != "asana.users"
        || receipt.observed_at_unix_ms() != result.observed_at_unix_millis
        || safe_receipt.plan_digest_sha256 != plan.plan_digest_sha256
        || safe_receipt.credential_operation != "source.bearer"
        || safe_receipt.status_code != 200
        || safe_receipt.tenant_id != tenant_id
        || safe_receipt.runtime_id != runtime_id
        || result.plan_id != plan.plan_id
        || result.plan_digest_sha256 != plan.plan_digest_sha256
        || result.logical_page_id != safe_receipt.logical_page_id
        || result.request_intent_digest != safe_receipt.request_intent_digest
        || result.tenant_id != tenant_id
        || result.runtime_id != runtime_id
        || result.runtime_generation != safe_receipt.runtime_generation
        || result.lease_generation != safe_receipt.lease_generation
        || result.observed_at_unix_millis != safe_receipt.observed_at_unix_millis
        || canonical_result_digest(safe_receipt, &result.next_cursor, &result.records)
            .map_err(|_| AsanaError::EventContractRejection)?
            != result.result_digest_sha256
    {
        return Err(AsanaError::EventContractRejection);
    }
    let next_cursor = (!result.next_cursor.is_empty())
        .then(|| validate_cursor(&result.next_cursor))
        .transpose()?;
    let worker_records = validate_and_deduplicate_records(result.records.clone())
        .map_err(|_| AsanaError::EventContractRejection)?;
    let validation_kernel = AsanaKernel::new(
        plan.origin.as_str(),
        tenant_id,
        "projection-validation",
        AsanaFamily::Users,
        Some(100),
    )?;
    let mut accepted = BTreeMap::<String, AsanaRecord>::new();

    for record in worker_records {
        let payload: serde_json::Value = serde_json::from_slice(&record.payload_json)
            .map_err(|_| AsanaError::EventContractRejection)?;
        let occurred_at = time::OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(record.occurred_at_unix_millis) * 1_000_000,
        )
        .map_err(|_| AsanaError::EventContractRejection)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| AsanaError::EventContractRejection)?;
        let normalized = normalize(&validation_kernel, payload.clone(), &occurred_at)?;
        let worker_attributes = record.attributes.into_iter().collect::<BTreeMap<_, _>>();
        if normalized.event_id != record.event_id
            || normalized.provider_id != record.provider_id
            || normalized.kind != definition.event_contract.kind
            || normalized.schema_ref != definition.event_contract.schema_ref
            || normalized.occurred_at != occurred_at
            || normalized.attributes != worker_attributes
            || normalized.payload != payload
        {
            return Err(AsanaError::EventContractRejection);
        }
        match accepted.get(&normalized.event_id) {
            Some(existing) if existing == &normalized => continue,
            Some(_) => return Err(AsanaError::ConflictingDuplicate),
            None => {
                accepted.insert(normalized.event_id.clone(), normalized);
            }
        }
    }

    let records = accepted
        .into_values()
        .map(|record| {
            Ok(SourceRecord {
                observation_id: ObservationId::parse(&record.event_id)
                    .map_err(|_| AsanaError::EventContractRejection)?,
                family: AsanaFamily::Users.as_str().to_owned(),
                provider_kind: AsanaFamily::Users.event_kind().to_owned(),
                provider_id: record.provider_id,
                fields: record.attributes,
                payload: record.payload,
            })
        })
        .collect::<Result<Vec<_>, AsanaError>>()?;

    Ok(CollectedBatch {
        scope: CollectedScope::NonAuthoritative(receipt),
        records,
        next_cursor,
    })
}

/// Project normalized Asana records into identity, project, and audit context.
pub fn project_asana_records(records: &[AsanaRecord]) -> AsanaProjectionFacts {
    let mut entities = BTreeMap::<String, AsanaEntityFact>::new();
    let mut relations = BTreeSet::new();
    for record in records {
        match record.family {
            AsanaFamily::Users | AsanaFamily::Projects => {
                if let Some(urn) = record.attributes.get("resource_urn") {
                    entities.insert(
                        urn.clone(),
                        AsanaEntityFact {
                            urn: urn.clone(),
                            entity_type: record.attributes["resource_type"].clone(),
                            label: record
                                .attributes
                                .get("resource_name")
                                .cloned()
                                .unwrap_or_else(|| record.provider_id.clone()),
                        },
                    );
                }
            }
            AsanaFamily::AuditEvents => {
                let actor_id = &record.attributes["actor_id"];
                let actor_urn =
                    format!("urn:cerebro:{}:runtime_users:{actor_id}", record.tenant_id);
                entities.insert(
                    actor_urn.clone(),
                    AsanaEntityFact {
                        urn: actor_urn.clone(),
                        entity_type: "identity_user".to_owned(),
                        label: record
                            .attributes
                            .get("actor_name")
                            .cloned()
                            .unwrap_or_else(|| actor_id.clone()),
                    },
                );
                if let Some(resource_urn) = record.attributes.get("resource_urn") {
                    entities.insert(
                        resource_urn.clone(),
                        AsanaEntityFact {
                            urn: resource_urn.clone(),
                            entity_type: record
                                .attributes
                                .get("resource_type")
                                .cloned()
                                .unwrap_or_else(|| "resource".to_owned()),
                            label: record
                                .attributes
                                .get("resource_name")
                                .cloned()
                                .unwrap_or_else(|| resource_urn.clone()),
                        },
                    );
                    relations.insert(AsanaRelationFact {
                        from_urn: actor_urn,
                        relation: "performed_action_on".to_owned(),
                        to_urn: resource_urn.clone(),
                    });
                }
            }
        }
    }
    AsanaProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
    }
}
