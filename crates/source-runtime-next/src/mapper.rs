use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_organizational_model::{
    AssertionProvenance, Entity, EntityKind, GraphAssertion, GraphDelta, GraphDeltaBuilder,
    ModelError, ObservationRef, ProviderIdentity, ProviderKind, RelationKind,
    RelationshipAssertion,
};
use cerebro_source_catalog::{CompiledFamily, CompiledSource};
use serde_json::Value;

use crate::{CollectedBatch, CollectedScope, GraphMapper, SourceRecord};

#[derive(Debug)]
pub enum CatalogMapperError {
    UnknownFamily(String),
    MissingField { family: String, field: String },
    UnsupportedTemplate(String),
    Domain(ModelError),
}

impl fmt::Display for CatalogMapperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFamily(family) => {
                write!(formatter, "source batch contains unknown family {family}")
            }
            Self::MissingField { family, field } => {
                write!(
                    formatter,
                    "family {family} record is missing projected field {field}"
                )
            }
            Self::UnsupportedTemplate(template) => {
                write!(
                    formatter,
                    "projection template {template} requires a bespoke Rust mapper"
                )
            }
            Self::Domain(error) => write!(formatter, "catalog projection is invalid: {error}"),
        }
    }
}

impl Error for CatalogMapperError {}

impl From<ModelError> for CatalogMapperError {
    fn from(value: ModelError) -> Self {
        Self::Domain(value)
    }
}

/// Maps the catalog's closed projection grammar into the sealed domain model.
/// It never creates canonical identities or confirmed identity bindings.
pub struct CatalogGraphMapper {
    source: CompiledSource,
    producer_version: String,
}

impl CatalogGraphMapper {
    pub fn new(
        source: CompiledSource,
        producer_version: impl Into<String>,
    ) -> Result<Self, CatalogMapperError> {
        let producer_version = producer_version.into();
        if producer_version.trim().is_empty() || producer_version.trim() != producer_version {
            return Err(ModelError::Invalid("catalog mapper version").into());
        }
        Ok(Self {
            source,
            producer_version,
        })
    }
}

impl GraphMapper for CatalogGraphMapper {
    type Error = CatalogMapperError;

    fn map(&self, batch: &CollectedBatch) -> Result<GraphDelta, Self::Error> {
        match &batch.scope {
            CollectedScope::Complete(collection) => {
                self.map_with_builder(batch, collection.clone().begin_delta())
            }
            CollectedScope::NonAuthoritative(collection) => {
                self.map_with_builder(batch, collection.clone().begin_delta())
            }
        }
    }
}

impl CatalogGraphMapper {
    fn map_with_builder<Mode>(
        &self,
        batch: &CollectedBatch,
        mut builder: GraphDeltaBuilder<Mode>,
    ) -> Result<GraphDelta, CatalogMapperError> {
        for record in &batch.records {
            let family = self
                .source
                .families()
                .iter()
                .find(|family| family.id() == record.family)
                .ok_or_else(|| CatalogMapperError::UnknownFamily(record.family.clone()))?;
            let projected = projected_fields(family, record);
            let provenance = AssertionProvenance::direct(
                vec![ObservationRef::new(
                    batch.scope.receipt(),
                    record.observation_id.clone(),
                    format!("{}:{}", record.provider_kind, record.provider_id),
                )?],
                format!("catalog-{}-mapper", self.source.id()),
                self.producer_version.clone(),
            )?;
            match family.projection().template() {
                "group_membership" => {
                    self.map_group_membership(batch, family, &projected, provenance, &mut builder)?
                }
                template if entity_kind(template).is_some() => {
                    let entity = self.map_entity(batch, record, family, &projected)?;
                    builder.add_entity(entity)?;
                }
                template => {
                    return Err(CatalogMapperError::UnsupportedTemplate(template.to_owned()));
                }
            }
        }
        Ok(builder.build())
    }

    fn map_entity(
        &self,
        batch: &CollectedBatch,
        record: &SourceRecord,
        family: &CompiledFamily,
        projected: &BTreeMap<String, String>,
    ) -> Result<Entity, CatalogMapperError> {
        let template = family.projection().template();
        let kind = entity_kind(template)
            .ok_or_else(|| CatalogMapperError::UnsupportedTemplate(template.to_owned()))?;
        let label = label_for(template, projected, family, record);
        let provider_kind = ProviderKind::parse(format!("{}.{}", self.source.id(), template))?;
        if template == "identity_user" {
            let provider = ProviderIdentity::new(
                batch.scope.receipt().tenant_id().clone(),
                batch.scope.receipt().source_runtime_id().clone(),
                provider_kind,
                identity_id(projected, record),
                label,
            )?;
            return add_properties(provider.into_entity(), projected);
        }
        let entity = Entity::provider(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            provider_kind,
            projected_id(template, projected, record),
            kind,
            label,
        )?;
        add_properties(entity, projected)
    }

    fn map_group_membership<Mode>(
        &self,
        batch: &CollectedBatch,
        family: &CompiledFamily,
        projected: &BTreeMap<String, String>,
        provenance: AssertionProvenance,
        builder: &mut GraphDeltaBuilder<Mode>,
    ) -> Result<(), CatalogMapperError> {
        let group_id =
            first(projected, &["group_id"]).ok_or_else(|| CatalogMapperError::MissingField {
                family: family.id().to_owned(),
                field: "group_id".to_owned(),
            })?;
        let member_id = first(
            projected,
            &["member_id", "member_user_id", "user_id", "member_email"],
        )
        .ok_or_else(|| CatalogMapperError::MissingField {
            family: family.id().to_owned(),
            field: "member_id".to_owned(),
        })?;
        let identity = ProviderIdentity::new(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            ProviderKind::parse(format!("{}.identity_user", self.source.id()))?,
            member_id,
            first(projected, &["member_name", "member_email"]).unwrap_or(member_id),
        )?;
        let group = Entity::provider(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            ProviderKind::parse(format!("{}.identity_group", self.source.id()))?,
            group_id,
            EntityKind::Group,
            first(projected, &["group_name", "group_email"]).unwrap_or(group_id),
        )?;
        let identity = add_properties(identity.into_entity(), projected)?;
        let group = add_properties(group, projected)?;
        let assertion = RelationshipAssertion::new(
            &identity,
            RelationKind::MemberOf,
            &group,
            provenance,
            batch.scope.receipt().observed_at_unix_ms(),
        )?;
        builder.add_entity(identity)?;
        builder.add_entity(group)?;
        builder.add_assertion(GraphAssertion::Relationship(assertion))?;
        Ok(())
    }
}

fn projected_fields(family: &CompiledFamily, record: &SourceRecord) -> BTreeMap<String, String> {
    let mut values = family.projection().static_fields().clone();
    for (target, expression) in family.projection().fields() {
        if let Some(value) = expression
            .split('|')
            .find_map(|path| scalar_at_path(&record.payload, path.trim()))
        {
            values.insert(target.clone(), value);
        }
    }
    values
}

fn scalar_at_path(value: &Value, path: &str) -> Option<String> {
    let mut value = value;
    for part in path.trim_start_matches("$.").split('.') {
        value = value.get(part)?;
    }
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn entity_kind(template: &str) -> Option<EntityKind> {
    Some(match template {
        "identity_user" => EntityKind::Identity,
        "identity_group" => EntityKind::Group,
        "repository" => EntityKind::Repository,
        "deployment" => EntityKind::Environment,
        "policy" => EntityKind::Policy,
        "finding" | "vulnerability" | "alert" => EntityKind::Finding,
        "identity_application" => EntityKind::Application,
        "cloud_resource"
        | "asset"
        | "secret"
        | "endpoint_device"
        | "identity_credential"
        | "audit_event"
        | "evidence_cas_reference" => EntityKind::Resource,
        _ => return None,
    })
}

fn identity_id<'a>(projected: &'a BTreeMap<String, String>, record: &'a SourceRecord) -> &'a str {
    first(projected, &["user_id", "identity_id", "email"]).unwrap_or(&record.provider_id)
}

fn projected_id<'a>(
    template: &str,
    projected: &'a BTreeMap<String, String>,
    record: &'a SourceRecord,
) -> &'a str {
    let keys: &[&str] = match template {
        "identity_group" => &["group_id", "group_email"],
        "repository" => &["repository_id", "repo_id", "resource_id", "id"],
        "deployment" => &["deployment_id", "resource_id", "id"],
        "policy" => &["policy_id", "resource_id", "id"],
        "finding" | "vulnerability" => &["finding_id", "vulnerability_id", "id"],
        "alert" => &["alert_id", "finding_id", "id"],
        "secret" => &["secret_id", "resource_id", "id"],
        "identity_application" => &["app_id", "application_id", "id"],
        _ => &["resource_id", "id"],
    };
    first(projected, keys).unwrap_or(&record.provider_id)
}

fn label_for(
    template: &str,
    projected: &BTreeMap<String, String>,
    family: &CompiledFamily,
    record: &SourceRecord,
) -> String {
    let keys: &[&str] = match template {
        "identity_user" => &["display_name", "email", "user_id"],
        "identity_group" => &["group_name", "group_email", "group_id"],
        "repository" => &["repository_name", "resource_name", "name"],
        "deployment" => &["deployment_name", "resource_name", "name"],
        "policy" => &["policy_name", "resource_name", "name"],
        "finding" | "vulnerability" => &["title", "finding_id", "id"],
        "alert" => &["alert_name", "title", "alert_id"],
        "secret" => &["secret_name", "resource_name", "name"],
        _ => &["resource_name", "name", "display_name"],
    };
    first(projected, keys)
        .map(str::to_owned)
        .or_else(|| {
            family
                .name_field()
                .and_then(|path| scalar_at_path(&record.payload, path))
        })
        .unwrap_or_else(|| record.provider_id.clone())
}

fn first<'a>(values: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| values.get(*key).map(String::as_str))
}

fn add_properties(
    mut entity: Entity,
    projected: &BTreeMap<String, String>,
) -> Result<Entity, CatalogMapperError> {
    for (key, value) in projected {
        entity = entity.with_property(key.clone(), value.clone())?;
    }
    Ok(entity)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use cerebro_organizational_model::{
        CollectionId, CompleteCollection, ObservationId, SourceRuntimeId, TenantId,
    };
    use cerebro_source_catalog::SourceCatalog;

    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn catalog_membership_becomes_two_provider_entities_and_one_typed_edge() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("box").unwrap().clone();
        let collection = CompleteCollection::new(
            TenantId::parse("tenant-a").unwrap(),
            SourceRuntimeId::parse("box-prod").unwrap(),
            CollectionId::parse("collection-1").unwrap(),
            "box.group_memberships",
            10,
        )
        .unwrap();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(collection),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-1").unwrap(),
                family: "group_memberships".to_owned(),
                provider_kind: "box.group_memberships".to_owned(),
                provider_id: "membership-1".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({
                    "id": "membership-1",
                    "group_id": "group-1",
                    "user": {
                        "id": "user-1",
                        "login": "user@example.test",
                        "name": "User One"
                    },
                    "role": "member"
                }),
            }],
            next_cursor: None,
        };
        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .map(&batch)
            .unwrap();
        assert_eq!(delta.entities().len(), 2);
        assert_eq!(delta.assertions().len(), 1);
        let GraphAssertion::Relationship(assertion) = &delta.assertions()[0] else {
            panic!("expected relationship")
        };
        assert_eq!(assertion.relation(), RelationKind::MemberOf);
    }
}
