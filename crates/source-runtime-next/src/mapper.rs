//! Catalog-driven projection from connector records into the sealed graph model.
//!
//! Mapping is tenant scoped and deterministic. Catalog templates select the
//! permitted graph shape, while identity bindings can resolve only against a
//! caller-supplied snapshot of already accepted canonical claims.

use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_organizational_model::{
    AssertionProvenance, CanonicalIdentity, CanonicalIdentityId, Entity, EntityKind,
    GraphAssertion, GraphDelta, GraphDeltaBuilder, IdentityBindingAssertion, IdentityBindingState,
    IdentityClaim, IdentityResolutionMethod, ModelError, ObservationRef, ProviderIdentity,
    ProviderKind, RelationKind, RelationshipAssertion, TenantId,
};
use cerebro_source_catalog::{CompiledFamily, CompiledSource};
use serde_json::Value;

use crate::{CollectedBatch, CollectedScope, GraphMapper, SourceRecord};

#[derive(Debug)]
/// A catalog record could not be projected into a valid graph delta.
pub enum CatalogMapperError {
    /// The batch names a family absent from the compiled source catalog.
    UnknownFamily(String),
    /// A projection requires a field that the source record did not provide.
    MissingField {
        /// Catalog family being projected.
        family: String,
        /// Required projected field that was absent.
        field: String,
    },
    /// The catalog selected a template without a generic Rust mapper.
    UnsupportedTemplate(String),
    /// The projected value violates an organizational-model invariant.
    Domain(ModelError),
    /// One verified claim points at two different canonical identities.
    IdentityConflict(String),
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
            Self::IdentityConflict(claim) => {
                write!(
                    formatter,
                    "identity claim {claim} resolves to conflicting people"
                )
            }
        }
    }
}

impl Error for CatalogMapperError {}

impl From<ModelError> for CatalogMapperError {
    fn from(value: ModelError) -> Self {
        Self::Domain(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedCanonicalIdentity {
    id: CanonicalIdentityId,
    label: String,
}

/// A tenant-scoped snapshot of claims already accepted by the durable identity
/// registry. Provider records can match this snapshot but cannot add to it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityResolutionSnapshot {
    tenant_id: Option<TenantId>,
    verified_emails: BTreeMap<String, ResolvedCanonicalIdentity>,
}

impl IdentityResolutionSnapshot {
    /// Create an empty snapshot restricted to `tenant_id`.
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id: Some(tenant_id),
            verified_emails: BTreeMap::new(),
        }
    }

    /// Add a verified email claim and its previously accepted canonical identity.
    ///
    /// Repeating the same binding is idempotent. A conflicting binding fails
    /// rather than letting connector order choose the canonical person.
    pub fn add_verified_email(
        &mut self,
        email: impl Into<String>,
        canonical_id: CanonicalIdentityId,
        canonical_label: impl Into<String>,
    ) -> Result<(), CatalogMapperError> {
        let claim = IdentityClaim::verified_email(email)?;
        let canonical_label = canonical_label.into();
        if canonical_label.trim().is_empty() || canonical_label.trim() != canonical_label {
            return Err(ModelError::Invalid("canonical identity label").into());
        }
        let resolved = ResolvedCanonicalIdentity {
            id: canonical_id,
            label: canonical_label,
        };
        if let Some(existing) = self.verified_emails.get(claim.value())
            && existing != &resolved
        {
            return Err(CatalogMapperError::IdentityConflict(
                claim.value().to_owned(),
            ));
        }
        self.verified_emails
            .insert(claim.value().to_owned(), resolved);
        Ok(())
    }

    fn resolve_verified_email(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<&ResolvedCanonicalIdentity>, CatalogMapperError> {
        if self
            .tenant_id
            .as_ref()
            .is_some_and(|tenant| tenant != tenant_id)
        {
            return Err(ModelError::TenantMismatch.into());
        }
        let claim = IdentityClaim::verified_email(email)?;
        Ok(self.verified_emails.get(claim.value()))
    }
}

/// Maps the catalog's closed projection grammar into the sealed domain model.
pub struct CatalogGraphMapper {
    source: CompiledSource,
    producer_version: String,
    mapper_id: String,
    families: BTreeMap<String, FamilyPlan>,
    provider_kinds: BTreeMap<String, ProviderKind>,
    identity_resolution: IdentityResolutionSnapshot,
}

struct FamilyPlan {
    index: usize,
    projected_paths: Vec<(String, Vec<String>)>,
}

impl CatalogGraphMapper {
    /// Compile the catalog families and provider kinds used for projection.
    ///
    /// `producer_version` becomes assertion provenance and must be a stable,
    /// non-empty version owned by the mapper deployment.
    pub fn new(
        source: CompiledSource,
        producer_version: impl Into<String>,
    ) -> Result<Self, CatalogMapperError> {
        let producer_version = producer_version.into();
        if producer_version.trim().is_empty() || producer_version.trim() != producer_version {
            return Err(ModelError::Invalid("catalog mapper version").into());
        }
        let mut families = BTreeMap::new();
        let mut provider_kinds = BTreeMap::new();
        for (index, family) in source.families().iter().enumerate() {
            let template = family.projection().template();
            if entity_kind(template).is_some() {
                provider_kinds
                    .entry(template.to_owned())
                    .or_insert(ProviderKind::parse(format!(
                        "{}.{}",
                        source.id(),
                        template
                    ))?);
            }
            families.insert(
                family.id().to_owned(),
                FamilyPlan {
                    index,
                    projected_paths: family
                        .projection()
                        .fields()
                        .iter()
                        .map(|(target, expression)| {
                            (
                                target.clone(),
                                expression
                                    .split('|')
                                    .map(str::trim)
                                    .map(str::to_owned)
                                    .collect(),
                            )
                        })
                        .collect(),
                },
            );
        }
        for template in [
            "identity_user",
            "identity_group",
            "identity_application",
            "access_target",
        ] {
            provider_kinds
                .entry(template.to_owned())
                .or_insert(ProviderKind::parse(format!(
                    "{}.{}",
                    source.id(),
                    template
                ))?);
        }
        let mapper_id = format!("catalog-{}-mapper", source.id());
        Ok(Self {
            source,
            producer_version,
            mapper_id,
            families,
            provider_kinds,
            identity_resolution: IdentityResolutionSnapshot::default(),
        })
    }

    /// Attach the durable identity snapshot used to resolve verified claims.
    pub fn with_identity_resolution(
        mut self,
        identity_resolution: IdentityResolutionSnapshot,
    ) -> Self {
        self.identity_resolution = identity_resolution;
        self
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
            let plan = self
                .families
                .get(&record.family)
                .ok_or_else(|| CatalogMapperError::UnknownFamily(record.family.clone()))?;
            let family = &self.source.families()[plan.index];
            let projected = projected_fields(family, &plan.projected_paths, record);
            match family.projection().template() {
                "group_membership" | "identity_group_membership" => {
                    let provenance = self.assertion_provenance(batch, record)?;
                    self.map_group_membership(batch, family, projected, provenance, &mut builder)?
                }
                "identity_app_assignment" => {
                    let provenance = self.assertion_provenance(batch, record)?;
                    self.map_app_assignment(batch, family, projected, provenance, &mut builder)?
                }
                "identity_user" => {
                    self.map_identity_user(batch, record, family, projected, &mut builder)?
                }
                template if entity_kind(template).is_some() => {
                    let entity = self.map_entity(batch, record, family, projected)?;
                    builder.add_entity(entity)?;
                }
                template => {
                    return Err(CatalogMapperError::UnsupportedTemplate(template.to_owned()));
                }
            }
        }
        Ok(builder.build())
    }

    fn assertion_provenance(
        &self,
        batch: &CollectedBatch,
        record: &SourceRecord,
    ) -> Result<AssertionProvenance, CatalogMapperError> {
        Ok(AssertionProvenance::direct(
            vec![ObservationRef::new(
                batch.scope.receipt(),
                record.observation_id.clone(),
                format!("{}:{}", record.provider_kind, record.provider_id),
            )?],
            self.mapper_id.clone(),
            self.producer_version.clone(),
        )?)
    }

    fn map_entity(
        &self,
        batch: &CollectedBatch,
        record: &SourceRecord,
        family: &CompiledFamily,
        projected: BTreeMap<String, String>,
    ) -> Result<Entity, CatalogMapperError> {
        let template = family.projection().template();
        let kind = entity_kind(template)
            .ok_or_else(|| CatalogMapperError::UnsupportedTemplate(template.to_owned()))?;
        let label = label_for(template, &projected, family, record);
        let provider_kind = self.provider_kind(template)?;
        let entity = Entity::provider(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            provider_kind,
            projected_id(template, &projected, record),
            kind,
            label,
        )?;
        add_properties(entity, projected)
    }

    #[allow(clippy::too_many_arguments)]
    fn map_identity_user<Mode>(
        &self,
        batch: &CollectedBatch,
        record: &SourceRecord,
        family: &CompiledFamily,
        projected: BTreeMap<String, String>,
        builder: &mut GraphDeltaBuilder<Mode>,
    ) -> Result<(), CatalogMapperError> {
        let tenant_id = batch.scope.receipt().tenant_id().clone();
        let label = label_for("identity_user", &projected, family, record);
        let provider = ProviderIdentity::new(
            tenant_id.clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            self.provider_kind("identity_user")?,
            identity_id(&projected, record),
            label.clone(),
        )?;
        let provider_entity = add_properties(provider.clone().into_entity(), projected.clone())?;
        builder.add_entity(provider_entity)?;

        if self.source.id() == "okta" {
            let Some(employee_id) = first(&projected, &["employee_id", "employee_number"]) else {
                return Ok(());
            };
            let employee_claim = IdentityClaim::employee_id(employee_id)?;
            let canonical =
                CanonicalIdentity::for_claim(tenant_id, &employee_claim, label.clone())?;
            let provenance = self.assertion_provenance(batch, record)?;
            let employee_binding = IdentityBindingAssertion::new(
                &provider,
                &canonical,
                IdentityResolutionMethod::AuthoritativeEmployeeId,
                Some(employee_claim),
                IdentityBindingState::Confirmed,
                provenance.clone(),
                batch.scope.receipt().observed_at_unix_ms(),
            )?;
            builder.add_entity(canonical.clone().into_entity())?;
            builder.add_assertion(GraphAssertion::IdentityBinding(employee_binding))?;
            if let Some(email) = first(&projected, &["email"]) {
                let email_binding = IdentityBindingAssertion::new(
                    &provider,
                    &canonical,
                    IdentityResolutionMethod::VerifiedEmail,
                    Some(IdentityClaim::verified_email(email)?),
                    IdentityBindingState::Confirmed,
                    provenance,
                    batch.scope.receipt().observed_at_unix_ms(),
                )?;
                builder.add_assertion(GraphAssertion::IdentityBinding(email_binding))?;
            }
            return Ok(());
        }

        let source_can_match = match self.source.id() {
            "github" => first(&projected, &["email_verified"]) == Some("true"),
            "slack" => true,
            _ => false,
        };
        if !source_can_match {
            return Ok(());
        }
        let Some(email) = first(&projected, &["email"]) else {
            return Ok(());
        };
        let Some(resolved) = self
            .identity_resolution
            .resolve_verified_email(&tenant_id, email)?
        else {
            return Ok(());
        };
        let canonical =
            CanonicalIdentity::new(tenant_id, resolved.id.clone(), resolved.label.clone())?;
        let provenance = self.assertion_provenance(batch, record)?;
        let binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::ExistingClaimMatch,
            Some(IdentityClaim::verified_email(email)?),
            IdentityBindingState::Confirmed,
            provenance,
            batch.scope.receipt().observed_at_unix_ms(),
        )?;
        builder.add_entity(canonical.into_entity())?;
        builder.add_assertion(GraphAssertion::IdentityBinding(binding))?;
        Ok(())
    }

    fn map_group_membership<Mode>(
        &self,
        batch: &CollectedBatch,
        family: &CompiledFamily,
        projected: BTreeMap<String, String>,
        provenance: AssertionProvenance,
        builder: &mut GraphDeltaBuilder<Mode>,
    ) -> Result<(), CatalogMapperError> {
        let group_id =
            first(&projected, &["group_id"]).ok_or_else(|| CatalogMapperError::MissingField {
                family: family.id().to_owned(),
                field: "group_id".to_owned(),
            })?;
        let member_id = first(
            &projected,
            &["member_id", "member_user_id", "user_id", "member_email"],
        )
        .ok_or_else(|| CatalogMapperError::MissingField {
            family: family.id().to_owned(),
            field: "member_id".to_owned(),
        })?;
        let identity = ProviderIdentity::new(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            self.provider_kind("identity_user")?,
            member_id,
            first(&projected, &["member_name", "member_email"]).unwrap_or(member_id),
        )?;
        let group = Entity::provider(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            self.provider_kind("identity_group")?,
            group_id,
            EntityKind::Group,
            first(&projected, &["group_name", "group_email"]).unwrap_or(group_id),
        )?;
        let identity = add_properties(
            identity.into_entity(),
            projected
                .iter()
                .filter(|(key, _)| {
                    !key.starts_with("group_") && key.as_str() != "role" && key.as_str() != "id"
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )?;
        let group = add_properties(
            group,
            projected
                .into_iter()
                .filter(|(key, _)| !key.starts_with("member_") && key != "role" && key != "id")
                .collect(),
        )?;
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

    fn map_app_assignment<Mode>(
        &self,
        batch: &CollectedBatch,
        family: &CompiledFamily,
        projected: BTreeMap<String, String>,
        provenance: AssertionProvenance,
        builder: &mut GraphDeltaBuilder<Mode>,
    ) -> Result<(), CatalogMapperError> {
        let app_id =
            first(&projected, &["app_id"]).ok_or_else(|| CatalogMapperError::MissingField {
                family: family.id().to_owned(),
                field: "app_id".to_owned(),
            })?;
        let application = Entity::provider(
            batch.scope.receipt().tenant_id().clone(),
            batch.scope.receipt().source_runtime_id().clone(),
            self.provider_kind("identity_application")?,
            app_id,
            EntityKind::Application,
            first(&projected, &["app_name"]).unwrap_or(app_id),
        )?;
        let application = add_properties(application, projected.clone())?;
        let subject_id = first(
            &projected,
            &["subject_id", "member_user_id", "user_id", "member_email"],
        );
        let (principal, target) = if let Some(subject_id) = subject_id {
            let principal = add_properties(
                ProviderIdentity::new(
                    batch.scope.receipt().tenant_id().clone(),
                    batch.scope.receipt().source_runtime_id().clone(),
                    self.provider_kind("identity_user")?,
                    subject_id,
                    first(&projected, &["member_name", "member_email"]).unwrap_or(subject_id),
                )?
                .into_entity(),
                projected,
            )?;
            (principal, application)
        } else {
            let audience = first(&projected, &["audience"]).ok_or_else(|| {
                CatalogMapperError::MissingField {
                    family: family.id().to_owned(),
                    field: "subject_id or audience".to_owned(),
                }
            })?;
            let target = Entity::provider(
                batch.scope.receipt().tenant_id().clone(),
                batch.scope.receipt().source_runtime_id().clone(),
                self.provider_kind("access_target")?,
                audience,
                EntityKind::Resource,
                audience,
            )?;
            (application, target)
        };
        let assertion = RelationshipAssertion::new(
            &principal,
            RelationKind::CanAccess,
            &target,
            provenance,
            batch.scope.receipt().observed_at_unix_ms(),
        )?;
        builder.add_entity(principal)?;
        builder.add_entity(target)?;
        builder.add_assertion(GraphAssertion::Relationship(assertion))?;
        Ok(())
    }

    fn provider_kind(&self, template: &str) -> Result<ProviderKind, CatalogMapperError> {
        self.provider_kinds
            .get(template)
            .cloned()
            .ok_or_else(|| CatalogMapperError::UnsupportedTemplate(template.to_owned()))
    }
}

fn projected_fields(
    family: &CompiledFamily,
    projected_paths: &[(String, Vec<String>)],
    record: &SourceRecord,
) -> BTreeMap<String, String> {
    let mut values = record.fields.clone();
    values.extend(family.projection().static_fields().clone());
    for (target, paths) in projected_paths {
        if let Some(value) = paths
            .iter()
            .find_map(|path| scalar_at_path(&record.payload, path))
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
        // Application events commonly expose both a provider-internal name and
        // a human-facing label. Prefer the normalized application name so graph
        // readers see the same label that the source runtime selected.
        "identity_application" => &["app_name", "app_label", "name", "app_id"],
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
    projected: BTreeMap<String, String>,
) -> Result<Entity, CatalogMapperError> {
    for (key, value) in projected {
        entity = entity.with_property(key, value)?;
    }
    Ok(entity)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use cerebro_organizational_model::{
        CanonicalIdentity, CanonicalIdentityId, CollectionId, CompleteCollection, IdentityClaim,
        ObservationId, SourceRuntimeId, TenantId,
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

    #[test]
    fn okta_runtime_membership_becomes_a_native_typed_edge() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("okta").unwrap().clone();
        let collection = CompleteCollection::new(
            TenantId::parse("tenant-a").unwrap(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            CollectionId::parse("collection-okta-membership-1").unwrap(),
            "okta.group_membership",
            10,
        )
        .unwrap();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(collection),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-okta-membership-1").unwrap(),
                family: "group_membership".to_owned(),
                provider_kind: "okta.group_membership".to_owned(),
                provider_id: "membership-1".to_owned(),
                fields: BTreeMap::from([
                    ("group_id".to_owned(), "group-1".to_owned()),
                    ("member_email".to_owned(), "user@example.test".to_owned()),
                    ("member_id".to_owned(), "user-1".to_owned()),
                    ("member_name".to_owned(), "User One".to_owned()),
                    ("member_status".to_owned(), "ACTIVE".to_owned()),
                    ("member_type".to_owned(), "user".to_owned()),
                    ("member_user_id".to_owned(), "user-1".to_owned()),
                    ("user_id".to_owned(), "user-1".to_owned()),
                ]),
                payload: serde_json::json!({"id": "user-1"}),
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

    #[test]
    fn okta_runtime_application_becomes_a_native_application_entity() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("okta").unwrap().clone();
        let collection = CompleteCollection::new(
            TenantId::parse("tenant-a").unwrap(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            CollectionId::parse("collection-okta-application-1").unwrap(),
            "okta.application",
            10,
        )
        .unwrap();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(collection),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-okta-application-1").unwrap(),
                family: "application".to_owned(),
                provider_kind: "okta.application".to_owned(),
                provider_id: "app-1".to_owned(),
                fields: BTreeMap::from([
                    ("app_id".to_owned(), "app-1".to_owned()),
                    ("app_name".to_owned(), "Payroll".to_owned()),
                    ("oauth_public_client".to_owned(), "false".to_owned()),
                    ("status".to_owned(), "ACTIVE".to_owned()),
                ]),
                payload: serde_json::json!({
                    "id": "app-1",
                    "label": "Payroll",
                    "name": "payroll_oidc",
                    "status": "ACTIVE"
                }),
            }],
            next_cursor: None,
        };

        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .map(&batch)
            .unwrap();

        assert_eq!(delta.entities().len(), 1);
        assert!(delta.assertions().is_empty());
        let application = &delta.entities()[0];
        assert_eq!(application.kind(), &EntityKind::Application);
        assert_eq!(application.label(), "Payroll");
        assert_eq!(
            application.properties().get("status").map(String::as_str),
            Some("ACTIVE")
        );
        assert_eq!(
            application
                .properties()
                .get("oauth_public_client")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn application_grant_becomes_an_application_to_resource_access_edge() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("auth0").unwrap().clone();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(
                CompleteCollection::new(
                    TenantId::parse("tenant-a").unwrap(),
                    SourceRuntimeId::parse("auth0-prod").unwrap(),
                    CollectionId::parse("collection-auth0-1").unwrap(),
                    "auth0.client_grants",
                    10,
                )
                .unwrap(),
            ),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-auth0-1").unwrap(),
                family: "client_grants".to_owned(),
                provider_kind: "auth0.client_grants".to_owned(),
                provider_id: "grant-1".to_owned(),
                fields: BTreeMap::from([
                    ("app_id".to_owned(), "client-1".to_owned()),
                    ("audience".to_owned(), "https://api.example.test".to_owned()),
                ]),
                payload: serde_json::json!({"id": "grant-1"}),
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
        assert_eq!(assertion.relation(), RelationKind::CanAccess);
    }

    #[test]
    fn okta_employee_record_anchors_one_person_and_its_email() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("okta").unwrap().clone();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(
                CompleteCollection::new(
                    TenantId::parse("tenant-a").unwrap(),
                    SourceRuntimeId::parse("okta-prod").unwrap(),
                    CollectionId::parse("collection-okta-1").unwrap(),
                    "okta.user",
                    10,
                )
                .unwrap(),
            ),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-okta-1").unwrap(),
                family: "user".to_owned(),
                provider_kind: "okta.user".to_owned(),
                provider_id: "00u1".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({
                    "id": "00u1",
                    "name": "Person One",
                    "email": "person@example.com",
                    "profile": {"employeeNumber": "employee-1"}
                }),
            }],
            next_cursor: None,
        };
        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .map(&batch)
            .unwrap();
        assert_eq!(delta.entities().len(), 2);
        assert_eq!(delta.assertions().len(), 2);
        assert_eq!(
            delta
                .entities()
                .iter()
                .filter(|entity| entity.kind() == &EntityKind::Person)
                .count(),
            1
        );
    }

    #[test]
    fn slack_matches_an_existing_workforce_email_but_cannot_seed_one() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("slack").unwrap().clone();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let employee_claim = IdentityClaim::employee_id("employee-1").unwrap();
        let canonical =
            CanonicalIdentity::for_claim(tenant.clone(), &employee_claim, "Person One").unwrap();
        let canonical_id = CanonicalIdentityId::parse(
            canonical
                .entity()
                .id()
                .as_str()
                .strip_prefix("person:canonical:")
                .unwrap(),
        )
        .unwrap();
        let mut resolution = IdentityResolutionSnapshot::new(tenant.clone());
        resolution
            .add_verified_email("person@example.com", canonical_id, "Person One")
            .unwrap();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(
                CompleteCollection::new(
                    tenant,
                    SourceRuntimeId::parse("slack-prod").unwrap(),
                    CollectionId::parse("collection-slack-1").unwrap(),
                    "slack.user",
                    20,
                )
                .unwrap(),
            ),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-slack-1").unwrap(),
                family: "user".to_owned(),
                provider_kind: "slack.user".to_owned(),
                provider_id: "U1".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({
                    "id": "U1",
                    "name": "person",
                    "profile": {"email": "person@example.com"}
                }),
            }],
            next_cursor: None,
        };
        let unbound = CatalogGraphMapper::new(source.clone(), "v1")
            .unwrap()
            .map(&batch)
            .unwrap();
        assert!(unbound.assertions().is_empty());
        let bound = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .with_identity_resolution(resolution)
            .map(&batch)
            .unwrap();
        assert_eq!(bound.assertions().len(), 1);
        let GraphAssertion::IdentityBinding(binding) = &bound.assertions()[0] else {
            panic!("expected identity binding")
        };
        assert_eq!(
            binding.method(),
            IdentityResolutionMethod::ExistingClaimMatch
        );
    }

    #[test]
    fn github_unverified_email_cannot_match_a_person() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("github").unwrap().clone();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let mut resolution = IdentityResolutionSnapshot::new(tenant.clone());
        resolution
            .add_verified_email(
                "person@example.com",
                CanonicalIdentityId::parse("person-1").unwrap(),
                "Person One",
            )
            .unwrap();
        let batch = CollectedBatch {
            scope: CollectedScope::Complete(
                CompleteCollection::new(
                    tenant,
                    SourceRuntimeId::parse("github-prod").unwrap(),
                    CollectionId::parse("collection-github-1").unwrap(),
                    "github.email",
                    20,
                )
                .unwrap(),
            ),
            records: vec![SourceRecord {
                observation_id: ObservationId::parse("observation-github-1").unwrap(),
                family: "email".to_owned(),
                provider_kind: "github.email".to_owned(),
                provider_id: "person@example.com".to_owned(),
                fields: BTreeMap::new(),
                payload: serde_json::json!({
                    "email": "person@example.com",
                    "verified": false
                }),
            }],
            next_cursor: None,
        };
        let delta = CatalogGraphMapper::new(source, "v1")
            .unwrap()
            .with_identity_resolution(resolution)
            .map(&batch)
            .unwrap();
        assert!(delta.assertions().is_empty());
    }
}
