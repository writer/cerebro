#![forbid(unsafe_code)]

//! Compiler for the checked-in connector catalog.
//!
//! Catalog YAML is a wire format. Callers receive a closed, validated model
//! and cannot mark an unverified provider definition authoritative.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod authority_evidence;
mod authority_qualification;
mod authority_readiness;
pub use authority_evidence::{
    AuthorityDecisionKind, AuthorityEvidenceError, AuthorityEvidenceRecord,
    AuthorityEvidenceStream, validate_authority_evidence_record,
};
pub use authority_qualification::{
    AuthorityQualificationEvidence, PagePublicationReceiptReference, PersistedReceiptReference,
    SourceCollectionReceiptReference, authority_qualification_digest,
    missing_authority_qualification_evidence, validate_authority_qualification_evidence,
};

const MAX_PAGE_SIZE: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    Io { path: PathBuf, message: String },
    Decode { path: PathBuf, message: String },
    Invalid { path: PathBuf, message: String },
    DuplicateSource(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "read {}: {message}", path.display()),
            Self::Decode { path, message } => {
                write!(formatter, "decode {}: {message}", path.display())
            }
            Self::Invalid { path, message } => {
                write!(formatter, "invalid {}: {message}", path.display())
            }
            Self::DuplicateSource(source) => write!(formatter, "duplicate source {source}"),
        }
    }
}

impl Error for CatalogError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionAuthority {
    /// Provider contract and every family mapping are checked in and verified.
    Authoritative,
    /// Definition remains usable for fixtures and shadow comparison only.
    ShadowOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthModel {
    None,
    ApiKey,
    BearerToken,
    Basic,
    OauthAuthorizationCode,
    OauthClientCredentials,
    TwoStep,
    Jwt,
    Signature,
    AwsSigV4,
    DuoHmac,
    DuoHmacV5,
}

impl AuthModel {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "api_key" => Self::ApiKey,
            "bearer_token" => Self::BearerToken,
            "basic" => Self::Basic,
            "oauth_authorization_code" => Self::OauthAuthorizationCode,
            "oauth_client_credentials" => Self::OauthClientCredentials,
            "two_step" => Self::TwoStep,
            "jwt" => Self::Jwt,
            "signature" => Self::Signature,
            "aws_sigv4" => Self::AwsSigV4,
            "duo_hmac" => Self::DuoHmac,
            "duo_hmac_v5" => Self::DuoHmacV5,
            _ => return None,
        })
    }

    pub fn supports_generic_runtime(&self) -> bool {
        matches!(
            self,
            Self::None
                | Self::ApiKey
                | Self::BearerToken
                | Self::Basic
                | Self::OauthAuthorizationCode
                | Self::OauthClientCredentials
                | Self::TwoStep
                | Self::Jwt
                | Self::Signature
                | Self::AwsSigV4
                | Self::DuoHmacV5
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathParameterBinding {
    ScalarConfig { field: String },
    OptionalScalarConfig { field: String },
    CsvFanout { field: String },
}

impl PathParameterBinding {
    pub fn field(&self) -> &str {
        match self {
            Self::ScalarConfig { field }
            | Self::OptionalScalarConfig { field }
            | Self::CsvFanout { field } => field,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pagination {
    None,
    Cursor {
        parameter: String,
        response_path: String,
        page_size_parameter: Option<String>,
        page_size: usize,
    },
    Page {
        parameter: String,
        start: usize,
        page_size_parameter: Option<String>,
        page_size: usize,
    },
    Offset {
        parameter: String,
        limit_parameter: String,
        page_size: usize,
    },
    Link {
        header: String,
    },
    NextUrl {
        response_path: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    class: ProjectionClass,
    template: String,
    fields: BTreeMap<String, String>,
    static_fields: BTreeMap<String, String>,
}

impl Projection {
    pub fn class(&self) -> ProjectionClass {
        self.class
    }

    pub fn template(&self) -> &str {
        &self.template
    }

    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }

    pub fn static_fields(&self) -> &BTreeMap<String, String> {
        &self.static_fields
    }
}

/// The closed semantic lanes a source family may project into.
///
/// Connector YAML cannot add a new lane. A new projection shape must first be
/// represented here and implemented by the Rust mapper.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionClass {
    Identity,
    Access,
    Resource,
    Finding,
    Activity,
    Bespoke,
}

impl ProjectionClass {
    fn for_template(template: &str) -> Option<Self> {
        Some(match template {
            "identity_user"
            | "identity_group"
            | "group_membership"
            | "identity_group_membership"
            | "identity_credential"
            | "identity_application" => Self::Identity,
            "identity_app_assignment" | "policy" => Self::Access,
            "asset"
            | "cloud_resource"
            | "deployment"
            | "endpoint_device"
            | "repository"
            | "secret"
            | "evidence_cas_reference" => Self::Resource,
            "alert" | "finding" | "vulnerability" => Self::Finding,
            "audit_event" => Self::Activity,
            "" => Self::Bespoke,
            _ => return None,
        })
    }

    pub fn can_be_authoritative(self) -> bool {
        self != Self::Bespoke
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledFamily {
    id: String,
    base_url: Option<String>,
    method: HttpMethod,
    path: String,
    record_selector: String,
    scalar_record_field: Option<String>,
    id_template: Option<String>,
    id_field: String,
    name_field: Option<String>,
    static_query: BTreeMap<String, String>,
    config_query: BTreeMap<String, PathParameterBinding>,
    config_headers: BTreeMap<String, PathParameterBinding>,
    config_attributes: BTreeMap<String, PathParameterBinding>,
    static_json_body: BTreeMap<String, serde_json::Value>,
    config_json_body: BTreeMap<String, PathParameterBinding>,
    map_records: BTreeMap<String, String>,
    event_attributes: BTreeMap<String, String>,
    event_static_attributes: BTreeMap<String, String>,
    exact_event_attributes: bool,
    pagination: Pagination,
    cursor_in_json_body: bool,
    path_parameters: BTreeMap<String, PathParameterBinding>,
    projection: Projection,
    authoritative: bool,
    projection_authoritative: bool,
    unsupported_reasons: Vec<UnsupportedReasonCode>,
}

impl CompiledFamily {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Public family-specific provider base URL, when it differs from the
    /// source transport origin.
    pub fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn record_selector(&self) -> &str {
        &self.record_selector
    }

    pub fn scalar_record_field(&self) -> Option<&str> {
        self.scalar_record_field.as_deref()
    }

    pub fn id_template(&self) -> Option<&str> {
        self.id_template.as_deref()
    }

    pub fn id_field(&self) -> &str {
        &self.id_field
    }

    pub fn name_field(&self) -> Option<&str> {
        self.name_field.as_deref()
    }

    pub fn static_query(&self) -> &BTreeMap<String, String> {
        &self.static_query
    }

    pub fn config_query(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.config_query
    }

    pub fn config_headers(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.config_headers
    }

    pub fn config_attributes(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.config_attributes
    }

    pub fn static_json_body(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.static_json_body
    }

    pub fn config_json_body(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.config_json_body
    }

    pub fn map_records(&self) -> &BTreeMap<String, String> {
        &self.map_records
    }

    pub fn event_attributes(&self) -> &BTreeMap<String, String> {
        &self.event_attributes
    }

    pub fn event_static_attributes(&self) -> &BTreeMap<String, String> {
        &self.event_static_attributes
    }

    pub fn exact_event_attributes(&self) -> bool {
        self.exact_event_attributes
    }

    pub fn pagination(&self) -> &Pagination {
        &self.pagination
    }

    pub fn cursor_in_json_body(&self) -> bool {
        self.cursor_in_json_body
    }

    pub fn path_parameters(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.path_parameters
    }

    pub fn projection(&self) -> &Projection {
        &self.projection
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    /// Whether a committed event from this family may be promoted to the
    /// native Rust projector.
    ///
    /// This is separate from collection authority. A source may still require
    /// a bespoke collector while its verified, append-log-committed events use
    /// a closed Rust projection lane.
    pub fn is_projection_authoritative(&self) -> bool {
        self.projection_authoritative
    }

    pub fn unsupported_reasons(&self) -> &[UnsupportedReasonCode] {
        &self.unsupported_reasons
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledSource {
    id: String,
    display_name: String,
    auth: AuthModel,
    configurable_auth_models: Vec<AuthModel>,
    token_header: String,
    token_scheme: String,
    auth_header_parameters: BTreeMap<String, String>,
    auth_query_parameters: BTreeMap<String, String>,
    auth_json_body_parameters: BTreeMap<String, String>,
    oauth_authorization_code: Option<CompiledOauthAuthorizationCode>,
    oauth_client_credentials: Option<CompiledOauthClientCredentials>,
    authority: CollectionAuthority,
    families: Vec<CompiledFamily>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledOauthAuthorizationCode {
    token_url: String,
    scopes: Vec<String>,
    scope_separator: String,
    token_request_auth_method: String,
    token_params: BTreeMap<String, String>,
}

impl CompiledOauthAuthorizationCode {
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn scope_separator(&self) -> &str {
        &self.scope_separator
    }

    pub fn token_request_auth_method(&self) -> &str {
        &self.token_request_auth_method
    }

    pub fn token_params(&self) -> &BTreeMap<String, String> {
        &self.token_params
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledOauthClientCredentials {
    token_url: String,
    scopes: Vec<String>,
    scope_separator: String,
    token_request_auth_method: String,
    token_params: BTreeMap<String, String>,
}

impl CompiledOauthClientCredentials {
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn scope_separator(&self) -> &str {
        &self.scope_separator
    }

    pub fn token_request_auth_method(&self) -> &str {
        &self.token_request_auth_method
    }

    pub fn token_params(&self) -> &BTreeMap<String, String> {
        &self.token_params
    }
}

impl CompiledSource {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn auth(&self) -> &AuthModel {
        &self.auth
    }

    pub fn configurable_auth_models(&self) -> &[AuthModel] {
        &self.configurable_auth_models
    }

    pub fn token_header(&self) -> &str {
        &self.token_header
    }

    pub fn token_scheme(&self) -> &str {
        &self.token_scheme
    }

    pub fn auth_header_parameters(&self) -> &BTreeMap<String, String> {
        &self.auth_header_parameters
    }

    pub fn auth_query_parameters(&self) -> &BTreeMap<String, String> {
        &self.auth_query_parameters
    }

    pub fn auth_json_body_parameters(&self) -> &BTreeMap<String, String> {
        &self.auth_json_body_parameters
    }

    pub fn oauth_client_credentials(&self) -> Option<&CompiledOauthClientCredentials> {
        self.oauth_client_credentials.as_ref()
    }

    pub fn oauth_authorization_code(&self) -> Option<&CompiledOauthAuthorizationCode> {
        self.oauth_authorization_code.as_ref()
    }

    pub fn authority(&self) -> CollectionAuthority {
        self.authority
    }

    pub fn families(&self) -> &[CompiledFamily] {
        &self.families
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogSummary {
    pub sources: usize,
    pub families: usize,
    pub push_sources: usize,
    pub push_families: usize,
    pub authoritative_sources: usize,
    pub authoritative_families: usize,
    pub shadow_only_sources: usize,
    pub projection_classes: BTreeMap<ProjectionClass, usize>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogFamilyClassification {
    RustAuthoritative,
    ShadowOnly,
    ProjectionOnly,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReasonCode {
    UnsupportedAuthModel,
    MissingProviderProof,
    UnboundPathConfigParameter,
    UnboundConfigQueryParameter,
    UnboundConfigHeader,
    UnboundConfigJsonBody,
    UnboundConfigAttribute,
    UnsupportedProjectionTemplate,
    UnsupportedPaginationGrammar,
    BespokeRuntime,
    IncompleteRuntimeFamilyProof,
    MissingProviderAuthorityEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnsupportedFeatureFamilyReport {
    pub source_id: String,
    pub family_id: String,
    pub classification: CatalogFamilyClassification,
    pub reason_codes: Vec<UnsupportedReasonCode>,
    pub safe_detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnsupportedFeatureReport {
    pub total_sources: usize,
    pub total_families: usize,
    pub rust_authoritative_families: usize,
    pub shadow_only_families: usize,
    pub projection_only_families: usize,
    pub unsupported_families: usize,
    pub reason_code_counts: BTreeMap<UnsupportedReasonCode, usize>,
    pub missing_family_reports: Vec<String>,
    pub families: Vec<UnsupportedFeatureFamilyReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityReadinessFamilyReport {
    pub source_id: String,
    pub family_id: String,
    pub engine: String,
    pub authority_epoch: u64,
    pub plan_digest: String,
    pub proof_revision: String,
    pub fixture_revision: String,
    pub parity_status: String,
    pub rollback_status: String,
    pub projection_status: String,
    pub promotion_decision_id: String,
    pub blocking_reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityReadinessReport {
    pub total_families: usize,
    pub rust_authoritative_families: usize,
    pub shadow_or_go_families: usize,
    pub families: Vec<AuthorityReadinessFamilyReport>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCatalog {
    sources: BTreeMap<String, CompiledSource>,
    push_sources: BTreeMap<String, CompiledPushSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPushSource {
    id: String,
    display_name: String,
    families: BTreeMap<String, CompiledPushFamily>,
}

impl CompiledPushSource {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn families(&self) -> impl Iterator<Item = &CompiledPushFamily> {
        self.families.values()
    }

    pub fn family(&self, family_id: &str) -> Option<&CompiledPushFamily> {
        self.families.get(family_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPushFamily {
    id: String,
    event_kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

impl CompiledPushFamily {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn event_kind(&self) -> &str {
        &self.event_kind
    }

    pub fn schema_ref(&self) -> &str {
        &self.schema_ref
    }

    pub fn required_attributes(&self) -> &[String] {
        &self.required_attributes
    }

    pub fn required_payload_fields(&self) -> &[String] {
        &self.required_payload_fields
    }
}

impl SourceCatalog {
    /// Loads the complete definition catalog and joins it to provider proof
    /// manifests. Missing or unverified proof can only produce shadow data.
    pub fn load(
        definition_root: impl AsRef<Path>,
        source_root: impl AsRef<Path>,
    ) -> Result<Self, CatalogError> {
        let manifests = load_source_manifests(source_root.as_ref())?;
        let mut definition_paths = yaml_files(definition_root.as_ref())?;
        definition_paths.sort();
        let mut sources = BTreeMap::new();
        for path in definition_paths {
            let bytes = read_file(&path)?;
            let file: EntryFileWire =
                serde_saphyr::from_slice(&bytes).map_err(|error| CatalogError::Decode {
                    path: path.clone(),
                    message: error.to_string(),
                })?;
            for entry in file.entries {
                let source = compile_source(&path, entry, &manifests.proofs)?;
                if sources.insert(source.id.clone(), source.clone()).is_some() {
                    return Err(CatalogError::DuplicateSource(source.id));
                }
            }
        }
        reject_dual_mode_source_ids(sources.keys(), &manifests.push_sources)?;
        Ok(Self {
            sources,
            push_sources: manifests.push_sources,
        })
    }

    pub fn get(&self, source_id: &str) -> Option<&CompiledSource> {
        self.sources.get(source_id)
    }

    pub fn sources(&self) -> impl Iterator<Item = &CompiledSource> {
        self.sources.values()
    }

    /// Returns a checked-in push-only source contract. Push contracts are
    /// intentionally separate from HTTP connector definitions so they cannot
    /// be selected as empty pollers.
    pub fn push_source(&self, source_id: &str) -> Option<&CompiledPushSource> {
        self.push_sources.get(source_id)
    }

    pub fn push_sources(&self) -> impl Iterator<Item = &CompiledPushSource> {
        self.push_sources.values()
    }

    /// Returns whether an append-log source/family pair is admitted by either
    /// the pull connector catalog or an exact push-only event contract.
    pub fn admits_event_family(&self, source_id: &str, family_id: &str) -> bool {
        self.sources.contains_key(source_id)
            || self
                .push_sources
                .get(source_id)
                .is_some_and(|source| source.family(family_id).is_some())
    }

    pub fn summary(&self) -> CatalogSummary {
        let families = self
            .sources
            .values()
            .map(|source| source.families.len())
            .sum();
        let authoritative_sources = self
            .sources
            .values()
            .filter(|source| source.authority == CollectionAuthority::Authoritative)
            .count();
        let authoritative_families = self
            .sources
            .values()
            .flat_map(|source| &source.families)
            .filter(|family| family.authoritative)
            .count();
        let mut projection_classes = BTreeMap::new();
        for family in self.sources.values().flat_map(|source| &source.families) {
            *projection_classes
                .entry(family.projection.class())
                .or_insert(0) += 1;
        }
        CatalogSummary {
            sources: self.sources.len(),
            families,
            push_sources: self.push_sources.len(),
            push_families: self
                .push_sources
                .values()
                .map(|source| source.families.len())
                .sum(),
            authoritative_sources,
            authoritative_families,
            shadow_only_sources: self.sources.len() - authoritative_sources,
            projection_classes,
        }
    }

    pub fn unsupported_feature_report(&self) -> UnsupportedFeatureReport {
        let mut families = Vec::new();
        let mut reason_code_counts = BTreeMap::new();
        let mut rust_authoritative_families = 0usize;
        let mut shadow_only_families = 0usize;
        let mut projection_only_families = 0usize;
        let mut unsupported_families = 0usize;
        for source in self.sources() {
            for family in source.families() {
                let mut reason_codes = family.unsupported_reasons().to_vec();
                if family.is_authoritative() {
                    reason_codes.push(UnsupportedReasonCode::MissingProviderAuthorityEvidence);
                }
                reason_codes.sort();
                reason_codes.dedup();
                let classification = if family.is_authoritative()
                    && !reason_codes
                        .contains(&UnsupportedReasonCode::MissingProviderAuthorityEvidence)
                {
                    rust_authoritative_families += 1;
                    CatalogFamilyClassification::RustAuthoritative
                } else if family.is_projection_authoritative() {
                    projection_only_families += 1;
                    CatalogFamilyClassification::ProjectionOnly
                } else if source.authority() == CollectionAuthority::ShadowOnly {
                    shadow_only_families += 1;
                    CatalogFamilyClassification::ShadowOnly
                } else {
                    unsupported_families += 1;
                    CatalogFamilyClassification::Unsupported
                };
                if classification != CatalogFamilyClassification::RustAuthoritative {
                    if reason_codes.is_empty() {
                        reason_codes.push(UnsupportedReasonCode::IncompleteRuntimeFamilyProof);
                    }
                    for reason in &reason_codes {
                        *reason_code_counts.entry(*reason).or_insert(0) += 1;
                    }
                }
                families.push(UnsupportedFeatureFamilyReport {
                    source_id: source.id().to_owned(),
                    family_id: family.id().to_owned(),
                    classification,
                    reason_codes,
                    safe_detail: format!(
                        "source={} family={} classification={classification:?}",
                        source.id(),
                        family.id()
                    ),
                });
            }
        }
        let total_families = families.len();
        UnsupportedFeatureReport {
            total_sources: self.sources.len(),
            total_families,
            rust_authoritative_families,
            shadow_only_families,
            projection_only_families,
            unsupported_families,
            reason_code_counts,
            missing_family_reports: Vec::new(),
            families,
        }
    }

    pub fn authority_readiness_report(&self) -> AuthorityReadinessReport {
        self.authority_readiness_report_with_evidence("", &AuthorityEvidenceStream::default())
    }

    /// Return the exact compiled catalog plan digest for one source family.
    pub fn compiled_family_plan_digest(&self, source_id: &str, family_id: &str) -> Option<String> {
        authority_readiness::compiled_family_plan_digest(self, source_id, family_id)
    }

    /// Render one tenant's audit evidence against the compiled catalog. This
    /// report never substitutes for the persisted projection-authority ledger.
    pub fn authority_readiness_report_with_evidence(
        &self,
        tenant_id: &str,
        evidence: &AuthorityEvidenceStream,
    ) -> AuthorityReadinessReport {
        authority_readiness::report_with_evidence(self, tenant_id, evidence)
    }
}

fn reject_dual_mode_source_ids<'a>(
    pull_source_ids: impl Iterator<Item = &'a String>,
    push_sources: &BTreeMap<String, CompiledPushSource>,
) -> Result<(), CatalogError> {
    if let Some(source_id) = pull_source_ids
        .filter(|source_id| push_sources.contains_key(source_id.as_str()))
        .min()
    {
        return Err(CatalogError::DuplicateSource(source_id.clone()));
    }
    Ok(())
}

#[derive(Deserialize)]
struct EntryFileWire {
    #[serde(default)]
    entries: Vec<EntryWire>,
}

#[derive(Deserialize)]
struct EntryWire {
    classifier_output: String,
    definition: DefinitionWire,
}

#[derive(Deserialize)]
struct DefinitionWire {
    id: String,
    #[serde(default)]
    source_id: String,
    display_name: String,
    auth: AuthWire,
    #[serde(default)]
    config_fields: Vec<ConfigFieldWire>,
    #[serde(default)]
    resource_families: Vec<FamilyWire>,
}

#[derive(Deserialize)]
struct ConfigFieldWire {
    key: String,
    #[serde(default)]
    required: bool,
}

#[derive(Deserialize)]
struct AuthWire {
    model: String,
    #[serde(default)]
    configurable_models: Vec<String>,
    #[serde(default)]
    model_config_key: String,
    #[serde(default)]
    credential_fields: Vec<CredentialFieldWire>,
    #[serde(default)]
    token_header: String,
    #[serde(default)]
    token_scheme: String,
    #[serde(default)]
    header_parameters: BTreeMap<String, String>,
    #[serde(default)]
    query_parameters: BTreeMap<String, String>,
    #[serde(default)]
    json_body_parameters: BTreeMap<String, String>,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    refresh_url: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    scope_separator: String,
    #[serde(default)]
    token_request_auth_method: String,
    #[serde(default)]
    token_params: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct CredentialFieldWire {
    key: String,
}

#[derive(Deserialize)]
struct FamilyWire {
    id: String,
    #[serde(default)]
    singleton: bool,
    #[serde(default)]
    method: String,
    path: String,
    #[serde(default)]
    record_selector: String,
    #[serde(default)]
    list_key: String,
    id_field: String,
    #[serde(default)]
    name_field: String,
    #[serde(default)]
    static_query: BTreeMap<String, String>,
    #[serde(default)]
    config_query: BTreeMap<String, String>,
    #[serde(default)]
    config: Option<FamilyConfigWire>,
    #[serde(default)]
    read: Option<FamilyReadWire>,
    #[serde(default)]
    event: EventWire,
    pagination: Option<PaginationWire>,
    projection: Option<ProjectionWire>,
}

#[derive(Default, Deserialize)]
struct EventWire {
    #[serde(default)]
    attributes: BTreeMap<String, String>,
    #[serde(default)]
    static_attributes: BTreeMap<String, String>,
    #[serde(default)]
    exact_attributes: bool,
}

#[derive(Default, Deserialize)]
struct FamilyConfigWire {
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    config_query: BTreeMap<String, String>,
    #[serde(default)]
    config_headers: BTreeMap<String, String>,
    #[serde(default)]
    config_attributes: BTreeMap<String, String>,
    #[serde(default)]
    id_template: String,
}

#[derive(Default, Deserialize)]
struct FamilyReadWire {
    #[serde(default)]
    path_param_fanout: BTreeMap<String, String>,
    #[serde(default)]
    scalar_record_field: String,
    #[serde(default)]
    static_json_body: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    config_json_body: BTreeMap<String, String>,
    #[serde(default)]
    map_records: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
struct PaginationWire {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    cursor_param: String,
    #[serde(default)]
    cursor_json_path: String,
    #[serde(default)]
    next_cursor_keys: Vec<String>,
    #[serde(default)]
    page_param: String,
    #[serde(default)]
    page_size_param: String,
    #[serde(default)]
    offset_param: String,
    #[serde(default)]
    limit_param: String,
    #[serde(default)]
    link_header: String,
    #[serde(default)]
    next_url_json_path: String,
    #[serde(default)]
    start_page: Option<usize>,
    #[serde(default)]
    page_size: usize,
    #[serde(default)]
    cursor_in_json_body: bool,
}

#[derive(Deserialize)]
struct ProjectionWire {
    #[serde(default)]
    template: String,
    #[serde(default)]
    fields: BTreeMap<String, String>,
    #[serde(default)]
    static_fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProofManifestWire {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    collection_mode: String,
    #[serde(default)]
    emitted_kinds: Vec<String>,
    #[serde(default)]
    event_contracts: Vec<PushEventContractWire>,
    provider_api: Option<ProviderApiWire>,
    #[serde(default)]
    runtime_families: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PushEventContractWire {
    kind: String,
    schema_ref: String,
    #[serde(default)]
    required_attributes: Vec<String>,
    #[serde(default)]
    required_payload_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProviderApiWire {
    #[serde(default)]
    status: String,
    #[serde(default)]
    basis: String,
    #[serde(default)]
    spec_url: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    families: Vec<ProofFamilyWire>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProofFamilyWire {
    id: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
}

fn compile_source(
    path: &Path,
    entry: EntryWire,
    proofs: &BTreeMap<String, ProofManifestWire>,
) -> Result<CompiledSource, CatalogError> {
    let classifier_supported = entry.classifier_output.trim() == "supported";
    let id = source_id(&entry.definition.id, Some(&entry.definition.source_id));
    let auth = AuthModel::parse(entry.definition.auth.model.trim()).ok_or_else(|| {
        CatalogError::Invalid {
            path: path.to_path_buf(),
            message: format!("unsupported auth model {}", entry.definition.auth.model),
        }
    })?;
    let configurable_auth_models = if entry.definition.auth.configurable_models.is_empty() {
        vec![auth.clone()]
    } else {
        let mut models = Vec::new();
        for model in &entry.definition.auth.configurable_models {
            let model = AuthModel::parse(model.trim()).ok_or_else(|| CatalogError::Invalid {
                path: path.to_path_buf(),
                message: format!("unsupported configurable auth model {model}"),
            })?;
            if !models.contains(&model) {
                models.push(model);
            }
        }
        if !models.contains(&auth) {
            return invalid(
                path,
                "configurable auth models must include the default auth model",
            );
        }
        models
    };
    let token_header = entry.definition.auth.token_header.trim().to_owned();
    if token_header.len() > 128
        || token_header
            .chars()
            .any(|character| character.is_control() || matches!(character, ' ' | ':'))
    {
        return invalid(path, "auth token_header is invalid");
    }
    let token_scheme = entry.definition.auth.token_scheme.trim().to_owned();
    if token_scheme.len() > 64 || token_scheme.chars().any(char::is_control) {
        return invalid(path, "auth token_scheme is invalid");
    }
    let credential_fields = entry
        .definition
        .auth
        .credential_fields
        .iter()
        .map(|field| field.key.trim())
        .collect::<BTreeSet<_>>();
    let oauth_authorization_code = compile_oauth_authorization_code(path, &entry.definition.auth)?;
    let oauth_client_credentials =
        compile_oauth_client_credentials(path, &entry.definition.auth, &credential_fields)?;
    let mut auth_header_parameters = BTreeMap::new();
    let mut normalized_header_names = BTreeSet::new();
    for (header, credential_field) in entry.definition.auth.header_parameters {
        let header = header.trim();
        let credential_field = credential_field.trim();
        if header.is_empty()
            || header.len() > 128
            || !header.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return invalid(path, "auth header parameter name is invalid");
        }
        if !normalized_header_names.insert(header.to_ascii_lowercase()) {
            return invalid(path, "auth header parameter names must be unique");
        }
        if credential_field.is_empty() || !credential_fields.contains(credential_field) {
            return invalid(
                path,
                &format!(
                    "auth header {header} references undeclared credential field {credential_field}"
                ),
            );
        }
        auth_header_parameters.insert(header.to_owned(), credential_field.to_owned());
    }
    if auth_header_parameters.len() > 16 {
        return invalid(path, "auth header parameters exceed the 16-header limit");
    }
    let mut auth_query_parameters = BTreeMap::new();
    for (parameter, credential_field) in entry.definition.auth.query_parameters {
        let parameter = parameter.trim();
        let credential_field = credential_field.trim();
        if parameter.is_empty()
            || parameter.len() > 128
            || !parameter.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
        {
            return invalid(path, "auth query parameter name is invalid");
        }
        if credential_field.is_empty() || !credential_fields.contains(credential_field) {
            return invalid(
                path,
                &format!(
                    "auth query parameter {parameter} references undeclared credential field {credential_field}"
                ),
            );
        }
        auth_query_parameters.insert(parameter.to_owned(), credential_field.to_owned());
    }
    if auth_query_parameters.len() > 16 {
        return invalid(path, "auth query parameters exceed the 16-parameter limit");
    }
    let mut auth_json_body_parameters = BTreeMap::new();
    for (parameter, credential_field) in entry.definition.auth.json_body_parameters {
        let parameter = parameter.trim();
        let credential_field = credential_field.trim();
        if parameter.is_empty()
            || parameter.len() > 128
            || !parameter.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
        {
            return invalid(path, "auth JSON body parameter name is invalid");
        }
        if credential_field.is_empty() || !credential_fields.contains(credential_field) {
            return invalid(
                path,
                &format!(
                    "auth JSON body parameter {parameter} references undeclared credential field {credential_field}"
                ),
            );
        }
        auth_json_body_parameters.insert(parameter.to_owned(), credential_field.to_owned());
    }
    if auth_json_body_parameters.len() > 16 {
        return invalid(
            path,
            "auth JSON body parameters exceed the 16-parameter limit",
        );
    }
    if (!auth_header_parameters.is_empty()
        || !auth_query_parameters.is_empty()
        || !auth_json_body_parameters.is_empty())
        && auth != AuthModel::ApiKey
    {
        return invalid(
            path,
            "auth request parameters are supported only for api_key authentication",
        );
    }
    let api_key_placements = usize::from(!token_header.is_empty())
        + usize::from(!auth_header_parameters.is_empty())
        + usize::from(!auth_query_parameters.is_empty())
        + usize::from(!auth_json_body_parameters.is_empty());
    if api_key_placements > 1 {
        return invalid(
            path,
            "api_key authentication must use exactly one credential placement",
        );
    }
    let config_fields = entry
        .definition
        .config_fields
        .iter()
        .map(|field| (field.key.as_str(), field.required))
        .collect::<BTreeMap<_, _>>();
    let model_config_key = entry.definition.auth.model_config_key.trim();
    if configurable_auth_models.len() > 1 {
        if model_config_key.is_empty() || !config_fields.contains_key(model_config_key) {
            return invalid(
                path,
                "selectable authentication requires a declared model_config_key config field",
            );
        }
    } else if !model_config_key.is_empty() {
        return invalid(
            path,
            "model_config_key requires more than one configurable auth model",
        );
    }
    let auth_runtime_supported = configurable_auth_models
        .iter()
        .all(AuthModel::supports_generic_runtime)
        && (auth != AuthModel::ApiKey
            || !token_header.is_empty()
            || !auth_header_parameters.is_empty()
            || !auth_query_parameters.is_empty()
            || !auth_json_body_parameters.is_empty());
    let generic_runtime_supported = classifier_supported && auth_runtime_supported;
    let verified_families = verified_families(proofs.get(&id));
    let mut family_ids = BTreeSet::new();
    let mut families = Vec::with_capacity(entry.definition.resource_families.len());
    for family in entry.definition.resource_families {
        if !family_ids.insert(family.id.clone()) {
            return invalid(path, &format!("duplicate family {}", family.id));
        }
        families.push(compile_family(
            path,
            family,
            &verified_families,
            generic_runtime_supported,
            classifier_supported,
            auth_runtime_supported,
            &config_fields,
        )?);
    }
    if !auth_json_body_parameters.is_empty()
        && families
            .iter()
            .any(|family| family.method() != HttpMethod::Post)
    {
        return invalid(
            path,
            "JSON body authentication requires POST for every source family",
        );
    }
    if auth_json_body_parameters.is_empty()
        && families
            .iter()
            .any(|family| family.cursor_in_json_body() && family.static_json_body().is_empty())
    {
        return invalid(
            path,
            "JSON body cursor placement requires a static JSON body or JSON body authentication",
        );
    }
    if families.is_empty() {
        return invalid(path, "at least one resource family is required");
    }
    let authority = if classifier_supported && families.iter().all(CompiledFamily::is_authoritative)
    {
        CollectionAuthority::Authoritative
    } else {
        CollectionAuthority::ShadowOnly
    };
    Ok(CompiledSource {
        id,
        display_name: nonempty(path, "display_name", entry.definition.display_name)?,
        auth,
        configurable_auth_models,
        token_header,
        token_scheme,
        auth_header_parameters,
        auth_query_parameters,
        auth_json_body_parameters,
        oauth_authorization_code,
        oauth_client_credentials,
        authority,
        families,
    })
}

fn compile_oauth_authorization_code(
    path: &Path,
    auth: &AuthWire,
) -> Result<Option<CompiledOauthAuthorizationCode>, CatalogError> {
    if auth.model.trim() != "oauth_authorization_code" {
        return Ok(None);
    }
    let token_url = if auth.refresh_url.trim().is_empty() {
        auth.token_url.trim()
    } else {
        auth.refresh_url.trim()
    };
    if token_url.is_empty() || token_url.len() > 2_048 || token_url.chars().any(char::is_control) {
        return invalid(path, "oauth_authorization_code token_url is invalid");
    }
    let token_request_auth_method = match auth.token_request_auth_method.trim() {
        "" | "client_secret_post" => "client_secret_post",
        "client_secret_basic" | "basic" => "client_secret_basic",
        _ => {
            return invalid(
                path,
                "oauth_authorization_code token request auth method is invalid",
            );
        }
    };
    let scope_separator = if auth.scope_separator.is_empty() {
        " "
    } else {
        auth.scope_separator.as_str()
    };
    if scope_separator.len() > 16 || scope_separator.chars().any(char::is_control) {
        return invalid(path, "oauth_authorization_code scope separator is invalid");
    }
    let scopes = auth
        .scopes
        .iter()
        .map(|scope| scope.trim())
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.len() > 128
        || scopes
            .iter()
            .any(|scope| scope.len() > 512 || scope.chars().any(char::is_control))
    {
        return invalid(path, "oauth_authorization_code scopes are invalid");
    }
    if auth.token_params.len() > 32
        || auth.token_params.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || value.len() > 2_048
                || value.chars().any(char::is_control)
        })
    {
        return invalid(
            path,
            "oauth_authorization_code token parameters are invalid",
        );
    }
    Ok(Some(CompiledOauthAuthorizationCode {
        token_url: token_url.to_owned(),
        scopes,
        scope_separator: scope_separator.to_owned(),
        token_request_auth_method: token_request_auth_method.to_owned(),
        token_params: auth.token_params.clone(),
    }))
}

fn compile_oauth_client_credentials(
    path: &Path,
    auth: &AuthWire,
    credential_fields: &BTreeSet<&str>,
) -> Result<Option<CompiledOauthClientCredentials>, CatalogError> {
    if auth.model.trim() != "oauth_client_credentials" {
        return Ok(None);
    }
    if !credential_fields.contains("client_id") || !credential_fields.contains("client_secret") {
        return invalid(
            path,
            "oauth_client_credentials requires client_id and client_secret credential fields",
        );
    }
    let token_url = auth.token_url.trim();
    if token_url.is_empty() || token_url.len() > 2_048 || token_url.chars().any(char::is_control) {
        return invalid(path, "oauth_client_credentials token_url is invalid");
    }
    let token_request_auth_method = match auth.token_request_auth_method.trim() {
        "" | "client_secret_post" => "client_secret_post",
        "client_secret_basic" | "basic" => "client_secret_basic",
        _ => {
            return invalid(
                path,
                "oauth_client_credentials token request auth method is invalid",
            );
        }
    };
    let scope_separator = if auth.scope_separator.is_empty() {
        " "
    } else {
        auth.scope_separator.as_str()
    };
    if scope_separator.len() > 16 || scope_separator.chars().any(char::is_control) {
        return invalid(path, "oauth_client_credentials scope separator is invalid");
    }
    let scopes = auth
        .scopes
        .iter()
        .map(|scope| scope.trim())
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.len() > 128
        || scopes
            .iter()
            .any(|scope| scope.len() > 512 || scope.chars().any(char::is_control))
    {
        return invalid(path, "oauth_client_credentials scopes are invalid");
    }
    if auth.token_params.len() > 32
        || auth.token_params.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || value.len() > 2_048
                || value.chars().any(char::is_control)
        })
    {
        return invalid(
            path,
            "oauth_client_credentials token parameters are invalid",
        );
    }
    Ok(Some(CompiledOauthClientCredentials {
        token_url: token_url.to_owned(),
        scopes,
        scope_separator: scope_separator.to_owned(),
        token_request_auth_method: token_request_auth_method.to_owned(),
        token_params: auth.token_params.clone(),
    }))
}

fn compile_family(
    path: &Path,
    family: FamilyWire,
    verified: &BTreeSet<(String, String, String)>,
    generic_runtime_supported: bool,
    classifier_supported: bool,
    auth_runtime_supported: bool,
    config_fields: &BTreeMap<&str, bool>,
) -> Result<CompiledFamily, CatalogError> {
    let method = match family.method.trim() {
        "" | "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        other => {
            return invalid(
                path,
                &format!("family {} has unsupported method {other}", family.id),
            );
        }
    };
    let cursor_in_json_body = family
        .pagination
        .as_ref()
        .is_some_and(|pagination| pagination.cursor_in_json_body);
    if cursor_in_json_body
        && (method != HttpMethod::Post
            || family.pagination.as_ref().is_none_or(|pagination| {
                pagination.r#type != "cursor" || !pagination.page_size_param.is_empty()
            }))
    {
        return invalid(
            path,
            &format!(
                "family {} JSON-body cursor requires POST cursor pagination without a page-size parameter",
                family.id
            ),
        );
    }
    if !family.path.starts_with('/') {
        return invalid(
            path,
            &format!("family {} path must start with /", family.id),
        );
    }
    let path_parameter_names = family
        .path
        .split_once('?')
        .map_or(family.path.as_str(), |(path, _)| path)
        .split('/')
        .filter_map(path_parameter)
        .collect::<BTreeSet<_>>();
    let explicit_path_fanout = family
        .read
        .as_ref()
        .map(|read| &read.path_param_fanout)
        .cloned()
        .unwrap_or_default();
    if let Some(parameter) = explicit_path_fanout
        .keys()
        .find(|parameter| !path_parameter_names.contains(parameter.as_str()))
    {
        return invalid(
            path,
            &format!(
                "family {} fanout binding references unknown path parameter {parameter}",
                family.id
            ),
        );
    }
    let path_parameters = path_parameter_names
        .iter()
        .filter_map(|parameter| {
            let binding = if let Some(field) = explicit_path_fanout.get(*parameter) {
                config_fields.contains_key(field.as_str()).then(|| {
                    PathParameterBinding::CsvFanout {
                        field: field.clone(),
                    }
                })
            } else {
                config_binding(parameter, config_fields)
            };
            binding.map(|binding| ((*parameter).to_owned(), binding))
        })
        .collect::<BTreeMap<_, _>>();
    let path_parameters_configured = path_parameters.len() == path_parameter_names.len();
    let mut config_query_wire = family
        .config
        .as_ref()
        .map(|config| config.config_query.clone())
        .unwrap_or_default();
    for (parameter, field) in &family.config_query {
        if config_query_wire
            .insert(parameter.clone(), field.clone())
            .is_some_and(|existing| existing != *field)
        {
            return invalid(
                path,
                &format!(
                    "family {} defines conflicting config query parameter {parameter}",
                    family.id
                ),
            );
        }
    }
    let config_query = config_query_wire
        .iter()
        .filter_map(|(query_parameter, config_field)| {
            config_query_binding(config_field, config_fields)
                .map(|binding| (query_parameter.clone(), binding))
        })
        .collect::<BTreeMap<_, _>>();
    let config_query_configured = config_query.len() == config_query_wire.len();
    let config_headers_wire = family
        .config
        .as_ref()
        .map(|config| &config.config_headers)
        .cloned()
        .unwrap_or_default();
    if config_headers_wire.keys().any(|header| {
        header.is_empty()
            || header.len() > 128
            || !header.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    }) {
        return invalid(
            path,
            &format!("family {} config header name is invalid", family.id),
        );
    }
    let config_headers = config_headers_wire
        .iter()
        .filter_map(|(header, config_field)| {
            config_query_binding(config_field, config_fields)
                .map(|binding| (header.clone(), binding))
        })
        .collect::<BTreeMap<_, _>>();
    let config_headers_configured = config_headers.len() == config_headers_wire.len();
    let config_attributes_wire = family
        .config
        .as_ref()
        .map(|config| &config.config_attributes)
        .cloned()
        .unwrap_or_default();
    let mut config_attributes = config_attributes_wire
        .iter()
        .filter_map(|(attribute, config_field)| {
            config_binding(config_field, config_fields)
                .or_else(|| path_parameters.get(config_field).cloned())
                .map(|binding| (attribute.clone(), binding))
        })
        .collect::<BTreeMap<_, _>>();
    let config_attributes_configured = config_attributes.len() == config_attributes_wire.len();
    for (query_parameter, config_field) in &config_query_wire {
        if let Some(binding) = config_query.get(query_parameter) {
            config_attributes
                .entry(config_field.clone())
                .or_insert_with(|| binding.clone());
        }
    }
    let id_template = family
        .config
        .as_ref()
        .and_then(|config| optional(config.id_template.clone()));
    let base_url = family
        .config
        .as_ref()
        .and_then(|config| optional(config.base_url.trim().to_owned()));
    if id_template.as_deref().is_some_and(|template| {
        !(valid_id_template(template) || family.singleton && valid_singleton_id_literal(template))
    }) {
        return invalid(
            path,
            &format!("family {} id_template is invalid", family.id),
        );
    }
    let projection = family.projection.ok_or_else(|| CatalogError::Invalid {
        path: path.to_path_buf(),
        message: format!("family {} requires a projection", family.id),
    })?;
    if generic_runtime_supported && projection.template.trim().is_empty() {
        return invalid(
            path,
            &format!("family {} projection template is required", family.id),
        );
    }
    let template = projection.template.trim().to_owned();
    let projection_class =
        ProjectionClass::for_template(&template).ok_or_else(|| CatalogError::Invalid {
            path: path.to_path_buf(),
            message: format!(
                "family {} has unsupported projection template {}",
                family.id, template
            ),
        })?;
    let record_selector = if !family.record_selector.trim().is_empty() {
        family.record_selector
    } else if !family.list_key.trim().is_empty() {
        format!("$.{}[*]", family.list_key.trim())
    } else {
        "$[*]".to_owned()
    };
    let scalar_record_field = family
        .read
        .as_ref()
        .and_then(|read| optional(read.scalar_record_field.clone()));
    if scalar_record_field.as_ref().is_some_and(|field| {
        field.len() > 128
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) {
        return invalid(path, "family scalar_record_field is invalid");
    }
    let static_json_body = family
        .read
        .as_ref()
        .map(|read| read.static_json_body.clone())
        .unwrap_or_default();
    if !static_json_body.is_empty() {
        if method != HttpMethod::Post {
            return invalid(
                path,
                &format!("family {} static JSON body requires POST", family.id),
            );
        }
        if static_json_body.keys().any(|key| {
            key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }) {
            return invalid(
                path,
                &format!("family {} static JSON body key is invalid", family.id),
            );
        }
        let body_size = serde_json::to_vec(&static_json_body)
            .map_err(|error| CatalogError::Invalid {
                path: path.to_path_buf(),
                message: format!("family {} static JSON body is invalid: {error}", family.id),
            })?
            .len();
        if body_size > 16 * 1024 {
            return invalid(
                path,
                &format!("family {} static JSON body exceeds 16384 bytes", family.id),
            );
        }
    }
    let config_json_body_wire = family
        .read
        .as_ref()
        .map(|read| read.config_json_body.clone())
        .unwrap_or_default();
    if !config_json_body_wire.is_empty() && method != HttpMethod::Post {
        return invalid(
            path,
            &format!("family {} configured JSON body requires POST", family.id),
        );
    }
    if config_json_body_wire.keys().any(|key| {
        key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }) {
        return invalid(
            path,
            &format!("family {} configured JSON body key is invalid", family.id),
        );
    }
    let config_json_body = config_json_body_wire
        .iter()
        .filter_map(|(parameter, config_field)| {
            config_query_binding(config_field, config_fields)
                .map(|binding| (parameter.clone(), binding))
        })
        .collect::<BTreeMap<_, _>>();
    let config_json_body_configured = config_json_body.len() == config_json_body_wire.len();
    let map_records = family
        .read
        .as_ref()
        .map(|read| read.map_records.clone())
        .unwrap_or_default();
    if map_records.len() > 1
        || map_records
            .iter()
            .any(|(path, value)| path.trim().is_empty() || value.trim().is_empty())
    {
        return invalid(
            path,
            &format!("family {} map records are invalid", family.id),
        );
    }
    let provider_contract_verified = canonical_family_locator(base_url.as_deref(), &family.path)
        .is_some_and(|path| {
            verified.contains(&(
                family.id.clone(),
                match method {
                    HttpMethod::Get => "GET".to_owned(),
                    HttpMethod::Post => "POST".to_owned(),
                },
                path,
            ))
        });
    let authoritative = generic_runtime_supported
        && provider_contract_verified
        && path_parameters_configured
        && config_query_configured
        && config_headers_configured
        && config_json_body_configured
        && config_attributes_configured;
    let projection_authoritative =
        provider_contract_verified && projection_class.can_be_authoritative();
    let mut unsupported_reasons = Vec::new();
    if !auth_runtime_supported {
        unsupported_reasons.push(UnsupportedReasonCode::UnsupportedAuthModel);
    }
    if !classifier_supported {
        unsupported_reasons.push(UnsupportedReasonCode::BespokeRuntime);
    }
    if !provider_contract_verified {
        unsupported_reasons.push(UnsupportedReasonCode::MissingProviderProof);
        unsupported_reasons.push(UnsupportedReasonCode::IncompleteRuntimeFamilyProof);
    }
    if !path_parameters_configured {
        unsupported_reasons.push(UnsupportedReasonCode::UnboundPathConfigParameter);
    }
    if !config_query_configured {
        unsupported_reasons.push(UnsupportedReasonCode::UnboundConfigQueryParameter);
    }
    if !config_headers_configured {
        unsupported_reasons.push(UnsupportedReasonCode::UnboundConfigHeader);
    }
    if !config_json_body_configured {
        unsupported_reasons.push(UnsupportedReasonCode::UnboundConfigJsonBody);
    }
    if !config_attributes_configured {
        unsupported_reasons.push(UnsupportedReasonCode::UnboundConfigAttribute);
    }
    if !projection_class.can_be_authoritative() {
        unsupported_reasons.push(UnsupportedReasonCode::BespokeRuntime);
        unsupported_reasons.push(UnsupportedReasonCode::UnsupportedProjectionTemplate);
    }
    if matches!(
        compile_pagination(path, family.pagination.as_ref().cloned())?,
        Pagination::NextUrl { .. }
    ) {
        unsupported_reasons.push(UnsupportedReasonCode::UnsupportedPaginationGrammar);
    }
    unsupported_reasons.sort();
    unsupported_reasons.dedup();
    let family_id = nonempty(path, "family id", family.id)?;
    let id_field = validate_id_field(path, &family_id, family.id_field)?;
    Ok(CompiledFamily {
        authoritative,
        projection_authoritative,
        id: family_id,
        base_url,
        method,
        path: family.path,
        record_selector,
        scalar_record_field,
        id_template,
        id_field,
        name_field: optional(family.name_field),
        static_query: family.static_query,
        config_query,
        config_headers,
        config_attributes,
        static_json_body,
        config_json_body,
        map_records,
        event_attributes: family.event.attributes,
        event_static_attributes: family.event.static_attributes,
        exact_event_attributes: family.event.exact_attributes,
        pagination: compile_pagination(path, family.pagination)?,
        cursor_in_json_body,
        path_parameters,
        projection: Projection {
            class: projection_class,
            template,
            fields: projection.fields,
            static_fields: projection.static_fields,
        },
        unsupported_reasons,
    })
}

fn config_binding(
    requested: &str,
    config_fields: &BTreeMap<&str, bool>,
) -> Option<PathParameterBinding> {
    if config_fields.contains_key(requested) {
        return Some(PathParameterBinding::ScalarConfig {
            field: requested.to_owned(),
        });
    }
    let plural = format!("{requested}s");
    config_fields
        .contains_key(plural.as_str())
        .then_some(PathParameterBinding::CsvFanout { field: plural })
}

fn config_query_binding(
    requested: &str,
    config_fields: &BTreeMap<&str, bool>,
) -> Option<PathParameterBinding> {
    let plural = format!("{requested}s");
    if config_fields.contains_key(plural.as_str()) {
        return Some(PathParameterBinding::CsvFanout { field: plural });
    }
    config_fields.get(requested).map(|required| {
        if *required {
            PathParameterBinding::ScalarConfig {
                field: requested.to_owned(),
            }
        } else {
            PathParameterBinding::OptionalScalarConfig {
                field: requested.to_owned(),
            }
        }
    })
}

fn valid_id_template(template: &str) -> bool {
    if template.is_empty()
        || template.len() > 1_024
        || template.trim() != template
        || template.chars().any(char::is_control)
    {
        return false;
    }
    let mut rest = template;
    let mut placeholders = 0usize;
    while let Some(start) = rest.find("${") {
        if rest[..start].contains('{') || rest[..start].contains('}') {
            return false;
        }
        let field_start = start + 2;
        let Some(relative_end) = rest[field_start..].find('}') else {
            return false;
        };
        let field_end = field_start + relative_end;
        let field = &rest[field_start..field_end];
        if field.is_empty()
            || field.len() > 128
            || field.split('.').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return false;
        }
        placeholders += 1;
        rest = &rest[field_end + 1..];
    }
    placeholders > 0 && !rest.contains('{') && !rest.contains('}')
}

fn valid_singleton_id_literal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn validate_id_field(
    path: &Path,
    family_id: &str,
    expression: String,
) -> Result<String, CatalogError> {
    const MAX_CANDIDATES: usize = 8;
    const MAX_COMPOSITE_PARTS: usize = 8;
    const MAX_EXPRESSION_BYTES: usize = 2_048;
    const MAX_PATH_BYTES: usize = 128;

    let expression = nonempty(path, "family id_field", expression)?;
    let candidates = expression.split('|').collect::<Vec<_>>();
    if expression.len() > MAX_EXPRESSION_BYTES {
        return invalid(
            path,
            &format!("family {family_id} id_field exceeds the {MAX_EXPRESSION_BYTES}-byte limit"),
        );
    }
    if candidates.len() > MAX_CANDIDATES {
        return invalid(
            path,
            &format!("family {family_id} id_field exceeds the {MAX_CANDIDATES}-candidate limit"),
        );
    }
    if candidates.iter().any(|candidate| {
        candidate.is_empty()
            || candidate.trim() != *candidate
            || candidate.split('+').count() > MAX_COMPOSITE_PARTS
            || candidate.split('+').any(|path| {
                path.is_empty()
                    || path.len() > MAX_PATH_BYTES
                    || path.split('.').any(|part| {
                        part.is_empty()
                            || !part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            })
                    })
            })
    }) {
        return invalid(path, &format!("family {family_id} id_field is invalid"));
    }
    Ok(expression)
}

fn compile_pagination(
    path: &Path,
    wire: Option<PaginationWire>,
) -> Result<Pagination, CatalogError> {
    let Some(wire) = wire else {
        return Ok(Pagination::None);
    };
    let page_size = match wire.page_size {
        0 => 100,
        value if value <= MAX_PAGE_SIZE => value,
        value => return invalid(path, &format!("page size {value} exceeds {MAX_PAGE_SIZE}")),
    };
    Ok(match wire.r#type.as_str() {
        "" | "none" => Pagination::None,
        "cursor" => Pagination::Cursor {
            parameter: if wire.cursor_param.is_empty() {
                "cursor".to_owned()
            } else {
                wire.cursor_param
            },
            response_path: if !wire.cursor_json_path.is_empty() {
                wire.cursor_json_path
            } else if !wire.next_cursor_keys.is_empty() {
                wire.next_cursor_keys
                    .iter()
                    .map(|key| {
                        if key.starts_with('$') {
                            key.clone()
                        } else {
                            format!("$.{key}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            } else {
                "$.next_cursor".to_owned()
            },
            page_size_parameter: optional(wire.page_size_param),
            page_size,
        },
        "page" => Pagination::Page {
            parameter: if wire.page_param.is_empty() {
                "page".to_owned()
            } else {
                wire.page_param
            },
            start: wire.start_page.unwrap_or(1),
            page_size_parameter: optional(wire.page_size_param),
            page_size,
        },
        "offset" => Pagination::Offset {
            parameter: if !wire.offset_param.is_empty() {
                wire.offset_param
            } else if !wire.cursor_param.is_empty() {
                wire.cursor_param
            } else {
                "offset".to_owned()
            },
            limit_parameter: if !wire.limit_param.is_empty() {
                wire.limit_param
            } else if !wire.page_size_param.is_empty() {
                wire.page_size_param
            } else {
                "limit".to_owned()
            },
            page_size,
        },
        "link" => Pagination::Link {
            header: if wire.link_header.is_empty() {
                "Link".to_owned()
            } else {
                wire.link_header
            },
        },
        "next_url" => Pagination::NextUrl {
            response_path: required(path, "next_url_json_path", wire.next_url_json_path)?,
        },
        other => return invalid(path, &format!("unsupported pagination type {other}")),
    })
}

fn verified_families(proof: Option<&ProofManifestWire>) -> BTreeSet<(String, String, String)> {
    let Some(proof) = proof else {
        return BTreeSet::new();
    };
    let Some(api) = &proof.provider_api else {
        return BTreeSet::new();
    };
    let proof_is_complete = api.status == "verified"
        && api.basis == "declared"
        && (!api.spec_url.is_empty() || !api.references.is_empty());
    if !proof_is_complete {
        return BTreeSet::new();
    }
    let runtime: BTreeSet<_> = proof.runtime_families.iter().cloned().collect();
    api.families
        .iter()
        .filter(|family| {
            runtime.contains(&family.id)
                && !family.path.is_empty()
                && (family.method.is_empty() || family.method == "GET" || family.method == "POST")
        })
        .filter_map(|family| {
            canonical_contract_locator(&family.path).map(|path| {
                (
                    family.id.clone(),
                    if family.method.is_empty() {
                        "GET".to_owned()
                    } else {
                        family.method.clone()
                    },
                    path,
                )
            })
        })
        .collect()
}

fn family_plan_digest(source: &CompiledSource, family: &CompiledFamily) -> String {
    let payload = serde_json::json!({
        "source_id": source.id(),
        "family_id": family.id(),
        "base_url": family.base_url(),
        "method": match family.method() {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        },
        "path": family.path(),
        "record_selector": family.record_selector(),
        "id_field": family.id_field(),
        "projection_template": family.projection().template(),
        "static_query": family.static_query(),
        "config_query": family.config_query().keys().collect::<Vec<_>>(),
        "config_headers": family.config_headers().keys().collect::<Vec<_>>(),
        "static_json_body": family.static_json_body(),
        "cursor_in_json_body": family.cursor_in_json_body(),
        "path_parameters": family.path_parameters().keys().collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&payload).expect("family plan digest payload serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_path_template(path: &str) -> Option<String> {
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    if !path.starts_with('/') {
        return None;
    }
    let mut canonical = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            canonical.push('/');
        }
        if path_parameter(segment).is_some() {
            canonical.push_str("{}");
        } else {
            if segment.contains('{') || segment.contains('}') {
                return None;
            }
            canonical.push_str(segment);
        }
    }
    if let Some(query) = query {
        if query.contains('{') || query.contains('}') {
            return None;
        }
        canonical.push('?');
        canonical.push_str(query);
    }
    Some(canonical)
}

fn canonical_family_locator(base_url: Option<&str>, path: &str) -> Option<String> {
    let base_url = base_url.unwrap_or_default().trim().trim_end_matches('/');
    if base_url.starts_with("https://") && !base_url.contains("${") {
        return canonical_contract_locator(&format!("{base_url}{path}"));
    }
    canonical_path_template(path)
}

fn canonical_contract_locator(locator: &str) -> Option<String> {
    if locator.starts_with('/') {
        return canonical_path_template(locator);
    }
    let remainder = locator.strip_prefix("https://")?;
    let (host, path) = remainder.split_once('/')?;
    if host.is_empty()
        || host.contains('@')
        || host
            .chars()
            .any(|character| matches!(character, '?' | '#' | '\\'))
    {
        return None;
    }
    canonical_path_template(&format!("/{path}")).map(|path| format!("https://{host}{path}"))
}

fn path_parameter(segment: &str) -> Option<&str> {
    let parameter = segment
        .strip_prefix("${config.")
        .and_then(|value| value.strip_suffix('}'))
        .or_else(|| {
            segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
        })?;
    (!parameter.is_empty()
        && parameter
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(parameter)
}

struct SourceManifests {
    proofs: BTreeMap<String, ProofManifestWire>,
    push_sources: BTreeMap<String, CompiledPushSource>,
}

fn load_source_manifests(root: &Path) -> Result<SourceManifests, CatalogError> {
    let mut proofs = BTreeMap::new();
    let mut push_sources = BTreeMap::new();
    let entries = fs::read_dir(root).map_err(|error| CatalogError::Io {
        path: root.to_path_buf(),
        message: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| CatalogError::Io {
            path: root.to_path_buf(),
            message: error.to_string(),
        })?;
        if !entry
            .file_type()
            .map_err(|error| CatalogError::Io {
                path: entry.path(),
                message: error.to_string(),
            })?
            .is_dir()
        {
            continue;
        }
        let path = entry.path().join("catalog.yaml");
        if !path.is_file() {
            continue;
        }
        let bytes = read_file(&path)?;
        let proof: ProofManifestWire =
            serde_saphyr::from_slice(&bytes).map_err(|error| CatalogError::Decode {
                path: path.clone(),
                message: error.to_string(),
            })?;
        if proof.collection_mode.trim() == "push" {
            let push_source = compile_push_source(&path, &proof)?;
            if push_sources
                .insert(push_source.id.clone(), push_source.clone())
                .is_some()
            {
                return Err(CatalogError::DuplicateSource(push_source.id));
            }
        } else if !matches!(proof.collection_mode.trim(), "" | "pull") {
            return invalid(&path, "collection_mode must be pull or push");
        }
        if proofs.insert(proof.id.clone(), proof).is_some() {
            return Err(CatalogError::DuplicateSource(
                entry.file_name().to_string_lossy().into(),
            ));
        }
    }
    Ok(SourceManifests {
        proofs,
        push_sources,
    })
}

fn compile_push_source(
    path: &Path,
    manifest: &ProofManifestWire,
) -> Result<CompiledPushSource, CatalogError> {
    let source_id = validate_push_identifier(path, "push source id", &manifest.id)?;
    let display_name = nonempty(path, "name", manifest.name.clone())?;
    if manifest.emitted_kinds.is_empty() {
        return invalid(path, "push source must emit at least one event kind");
    }
    let emitted_kinds = manifest
        .emitted_kinds
        .iter()
        .map(|kind| kind.trim().to_owned())
        .collect::<BTreeSet<_>>();
    if emitted_kinds.len() != manifest.emitted_kinds.len() {
        return invalid(path, "push source emitted_kinds must be unique");
    }
    let mut families = BTreeMap::new();
    for contract in &manifest.event_contracts {
        let event_kind = contract.kind.trim();
        let family_id = event_kind
            .strip_prefix(&format!("{source_id}."))
            .ok_or_else(|| CatalogError::Invalid {
                path: path.to_path_buf(),
                message: format!("push event kind {event_kind} must use source prefix {source_id}"),
            })?;
        let family_id = validate_push_identifier(path, "push family id", family_id)?;
        if !emitted_kinds.contains(event_kind) {
            return invalid(
                path,
                &format!("push event kind {event_kind} is not listed in emitted_kinds"),
            );
        }
        let schema_ref = contract.schema_ref.trim();
        let expected_schema = format!("{source_id}/{family_id}/v1");
        if schema_ref != expected_schema {
            return invalid(
                path,
                &format!("push family {family_id} schema_ref must be {expected_schema}"),
            );
        }
        let required_attributes = compile_push_fields(
            path,
            family_id.as_str(),
            "required attribute",
            &contract.required_attributes,
        )?;
        let required_payload_fields = compile_push_fields(
            path,
            family_id.as_str(),
            "required payload field",
            &contract.required_payload_fields,
        )?;
        let family = CompiledPushFamily {
            id: family_id.clone(),
            event_kind: event_kind.to_owned(),
            schema_ref: schema_ref.to_owned(),
            required_attributes,
            required_payload_fields,
        };
        if families.insert(family_id.clone(), family).is_some() {
            return invalid(path, &format!("duplicate push family {family_id}"));
        }
    }
    if families.len() != emitted_kinds.len() {
        return invalid(
            path,
            "every push emitted kind must have exactly one event_contract",
        );
    }
    Ok(CompiledPushSource {
        id: source_id,
        display_name,
        families,
    })
}

fn compile_push_fields(
    path: &Path,
    family_id: &str,
    field_kind: &str,
    fields: &[String],
) -> Result<Vec<String>, CatalogError> {
    let mut compiled = BTreeSet::new();
    for field in fields {
        let field = validate_push_identifier(path, field_kind, field)?;
        if !compiled.insert(field) {
            return invalid(
                path,
                &format!("push family {family_id} {field_kind}s must be unique"),
            );
        }
    }
    Ok(compiled.into_iter().collect())
}

fn validate_push_identifier(path: &Path, field: &str, value: &str) -> Result<String, CatalogError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return invalid(path, &format!("{field} is invalid"));
    }
    Ok(value.to_owned())
}

fn yaml_files(root: &Path) -> Result<Vec<PathBuf>, CatalogError> {
    let mut result = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| CatalogError::Io {
            path: directory.clone(),
            message: error.to_string(),
        })? {
            let entry = entry.map_err(|error| CatalogError::Io {
                path: directory.clone(),
                message: error.to_string(),
            })?;
            let file_type = entry.file_type().map_err(|error| CatalogError::Io {
                path: entry.path(),
                message: error.to_string(),
            })?;
            if file_type.is_symlink() {
                return invalid(&entry.path(), "symlinks are not allowed");
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("yaml" | "yml")
            ) {
                result.push(entry.path());
            }
        }
    }
    Ok(result)
}

fn source_id(definition_id: &str, explicit: Option<&String>) -> String {
    if let Some(explicit) = explicit
        && !explicit.trim().is_empty()
    {
        return explicit.trim().to_owned();
    }
    definition_id
        .trim()
        .strip_prefix("builtin-")
        .unwrap_or(definition_id.trim())
        .to_owned()
}

fn read_file(path: &Path) -> Result<Vec<u8>, CatalogError> {
    fs::read(path).map_err(|error| CatalogError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

fn required(path: &Path, field: &str, value: String) -> Result<String, CatalogError> {
    nonempty(path, field, value)
}

fn nonempty(path: &Path, field: &str, value: String) -> Result<String, CatalogError> {
    let value = value.trim();
    if value.is_empty() {
        return invalid(path, &format!("{field} is required"));
    }
    Ok(value.to_owned())
}

fn optional(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn invalid<T>(path: &Path, message: &str) -> Result<T, CatalogError> {
    Err(CatalogError::Invalid {
        path: path.to_path_buf(),
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn compile_auth_fixture(
        model: &str,
        auth_fields: &str,
        method: &str,
        pagination: &str,
    ) -> Result<CompiledSource, CatalogError> {
        compile_auth_fixture_with_credential_fields(
            model,
            "      - key: api_token",
            auth_fields,
            method,
            pagination,
        )
    }

    fn compile_auth_fixture_with_credential_fields(
        model: &str,
        credential_fields: &str,
        auth_fields: &str,
        method: &str,
        pagination: &str,
    ) -> Result<CompiledSource, CatalogError> {
        let yaml = format!(
            r#"entries:
- classifier_output: supported
  definition:
    id: builtin-test
    source_id: test
    display_name: Test
    auth:
      model: {model}
      credential_fields:
{credential_fields}
{auth_fields}
    resource_families:
    - id: items
      method: {method}
      path: /items
      id_field: id
      pagination:
{pagination}
      projection:
        template: asset
"#
        );
        let mut file: EntryFileWire = serde_saphyr::from_slice(yaml.as_bytes()).unwrap();
        compile_source(
            Path::new("auth-fixture.yaml"),
            file.entries.remove(0),
            &BTreeMap::new(),
        )
    }

    fn invalid_message<T: fmt::Debug>(result: Result<T, CatalogError>) -> String {
        match result.unwrap_err() {
            CatalogError::Invalid { message, .. } => message,
            error => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn request_auth_grammar_rejects_unsafe_ambiguous_and_unbound_bodies() {
        let invalid_name = compile_auth_fixture(
            "api_key",
            "      json_body_parameters:\n        \"bad name\": api_token",
            "POST",
            "        type: none",
        );
        assert_eq!(
            invalid_message(invalid_name),
            "auth JSON body parameter name is invalid"
        );

        let undeclared = compile_auth_fixture(
            "api_key",
            "      json_body_parameters:\n        token: missing",
            "POST",
            "        type: none",
        );
        assert!(invalid_message(undeclared).contains("undeclared credential field missing"));

        let wrong_model = compile_auth_fixture(
            "bearer_token",
            "      json_body_parameters:\n        token: api_token",
            "POST",
            "        type: none",
        );
        assert_eq!(
            invalid_message(wrong_model),
            "auth request parameters are supported only for api_key authentication"
        );

        let ambiguous = compile_auth_fixture(
            "api_key",
            "      query_parameters:\n        key: api_token\n      json_body_parameters:\n        token: api_token",
            "POST",
            "        type: none",
        );
        assert_eq!(
            invalid_message(ambiguous),
            "api_key authentication must use exactly one credential placement"
        );

        let get_body = compile_auth_fixture(
            "api_key",
            "      json_body_parameters:\n        token: api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(get_body),
            "JSON body authentication requires POST for every source family"
        );

        let page_body_cursor = compile_auth_fixture(
            "api_key",
            "      json_body_parameters:\n        token: api_token",
            "POST",
            "        type: page\n        cursor_in_json_body: true",
        );
        assert!(
            invalid_message(page_body_cursor)
                .contains("JSON-body cursor requires POST cursor pagination")
        );

        let unbound_body_cursor = compile_auth_fixture(
            "api_key",
            "      token_header: X-API-Key",
            "POST",
            "        type: cursor\n        cursor_in_json_body: true",
        );
        assert_eq!(
            invalid_message(unbound_body_cursor),
            "JSON body cursor placement requires a static JSON body or JSON body authentication"
        );
    }

    #[test]
    fn request_auth_grammar_rejects_unsafe_ambiguous_and_unbound_headers() {
        let invalid_name = compile_auth_fixture(
            "api_key",
            "      header_parameters:\n        \"bad header\": api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(invalid_name),
            "auth header parameter name is invalid"
        );

        let non_ascii_name = compile_auth_fixture(
            "api_key",
            "      header_parameters:\n        X-Api-Kéy: api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(non_ascii_name),
            "auth header parameter name is invalid"
        );

        let duplicate_name = compile_auth_fixture(
            "api_key",
            "      header_parameters:\n        X-API-Key: api_token\n        x-api-key: api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(duplicate_name),
            "auth header parameter names must be unique"
        );

        let undeclared = compile_auth_fixture(
            "api_key",
            "      header_parameters:\n        X-API-Key: missing",
            "GET",
            "        type: none",
        );
        assert!(
            invalid_message(undeclared).contains("references undeclared credential field missing")
        );

        let empty_credential_field = compile_auth_fixture_with_credential_fields(
            "api_key",
            "      - key: \"\"",
            "      header_parameters:\n        X-API-Key: \"\"",
            "GET",
            "        type: none",
        );
        assert!(
            invalid_message(empty_credential_field)
                .contains("references undeclared credential field")
        );

        let wrong_model = compile_auth_fixture(
            "bearer_token",
            "      header_parameters:\n        X-API-Key: api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(wrong_model),
            "auth request parameters are supported only for api_key authentication"
        );

        let ambiguous = compile_auth_fixture(
            "api_key",
            "      token_header: X-API-Key\n      header_parameters:\n        X-Store-Key: api_token",
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(ambiguous),
            "api_key authentication must use exactly one credential placement"
        );

        let too_many_headers = (0..17)
            .map(|index| format!("        X-Key-{index}: api_token"))
            .collect::<Vec<_>>()
            .join("\n");
        let over_limit = compile_auth_fixture(
            "api_key",
            &format!("      header_parameters:\n{too_many_headers}"),
            "GET",
            "        type: none",
        );
        assert_eq!(
            invalid_message(over_limit),
            "auth header parameters exceed the 16-header limit"
        );

        let invalid_scalar_field = compile_auth_fixture(
            "api_key",
            "      token_header: X-API-Key",
            "GET",
            "        type: none\n      read:\n        scalar_record_field: \"bad field\"",
        );
        assert_eq!(
            invalid_message(invalid_scalar_field),
            "family scalar_record_field is invalid"
        );
    }

    #[test]
    fn id_field_candidates_and_composites_are_bounded_and_path_only() {
        let path = Path::new("id-field-fixture.yaml");
        assert_eq!(
            validate_id_field(
                path,
                "components",
                "metadata.uid|metadata.name|name".to_owned()
            )
            .unwrap(),
            "metadata.uid|metadata.name|name"
        );
        assert_eq!(
            validate_id_field(path, "audit_events", "date+type+actingUserId".to_owned()).unwrap(),
            "date+type+actingUserId"
        );
        assert_eq!(
            invalid_message(validate_id_field(
                path,
                "components",
                "metadata.uid||name".to_owned()
            )),
            "family components id_field is invalid"
        );
        assert_eq!(
            invalid_message(validate_id_field(
                path,
                "audit_events",
                "date++actingUserId".to_owned()
            )),
            "family audit_events id_field is invalid"
        );
        assert_eq!(
            invalid_message(validate_id_field(
                path,
                "audit_events",
                (0..9)
                    .map(|index| format!("part{index}"))
                    .collect::<Vec<_>>()
                    .join("+")
            )),
            "family audit_events id_field is invalid"
        );
        assert_eq!(
            invalid_message(validate_id_field(
                path,
                "components",
                (0..9)
                    .map(|index| format!("candidate{index}"))
                    .collect::<Vec<_>>()
                    .join("|")
            )),
            "family components id_field exceeds the 8-candidate limit"
        );
    }

    #[test]
    fn backstage_is_compiled_as_a_verified_authoritative_source() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let backstage = catalog.get("backstage").unwrap();
        assert_eq!(backstage.authority(), CollectionAuthority::Authoritative);
        let component = backstage
            .families()
            .iter()
            .find(|family| family.id() == "component")
            .unwrap();
        assert!(component.is_authoritative());
        assert_eq!(component.id_field(), "metadata.uid|metadata.name|name");
        assert_eq!(component.record_selector(), "$.items[*]");
        assert_eq!(
            component.pagination(),
            &Pagination::Cursor {
                parameter: "cursor".to_owned(),
                response_path: "$.pageInfo.nextCursor".to_owned(),
                page_size_parameter: Some("limit".to_owned()),
                page_size: 100,
            }
        );
        let system = backstage
            .families()
            .iter()
            .find(|family| family.id() == "system")
            .unwrap();
        assert!(system.is_authoritative());
        assert_eq!(system.static_query().get("filter").unwrap(), "kind=system");
        assert_eq!(system.record_selector(), "$.items[*]");
    }

    #[test]
    fn datadog_compiles_exact_provider_runtime_contract() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let datadog = catalog.get("datadog").unwrap();
        assert_eq!(
            datadog.auth_header_parameters(),
            &BTreeMap::from([
                ("DD-API-KEY".to_owned(), "api_key".to_owned()),
                (
                    "DD-APPLICATION-KEY".to_owned(),
                    "application_key".to_owned(),
                ),
            ])
        );
        assert_eq!(datadog.families().len(), 8);
        assert!(
            datadog
                .families()
                .iter()
                .all(|family| family.is_authoritative() && family.is_projection_authoritative())
        );
        let family = |id: &str| {
            datadog
                .families()
                .iter()
                .find(|family| family.id() == id)
                .unwrap()
        };
        assert!(matches!(
            family("users").pagination(),
            Pagination::Cursor {
                parameter,
                response_path,
                page_size_parameter: Some(page_size_parameter),
                page_size: 100,
            } if parameter == "page[cursor]"
                && response_path == "$.meta.page.after|$.meta.page.cursor"
                && page_size_parameter == "page[size]"
        ));
        assert!(matches!(
            family("monitors").pagination(),
            Pagination::Page {
                parameter,
                start: 0,
                page_size_parameter: Some(page_size_parameter),
                page_size: 100,
            } if parameter == "page" && page_size_parameter == "page_size"
        ));
        assert!(matches!(
            family("slos").pagination(),
            Pagination::Offset {
                parameter,
                limit_parameter,
                page_size: 100,
            } if parameter == "offset" && limit_parameter == "limit"
        ));
        assert!(matches!(
            family("dashboards").pagination(),
            Pagination::Offset {
                parameter,
                limit_parameter,
                page_size: 100,
            } if parameter == "start" && limit_parameter == "count"
        ));
        assert!(matches!(
            family("incidents").pagination(),
            Pagination::Cursor {
                parameter,
                response_path,
                page_size_parameter: Some(page_size_parameter),
                page_size: 100,
            } if parameter == "page[offset]"
                && response_path == "$.meta.pagination.next_offset"
                && page_size_parameter == "page[size]"
        ));
        assert!(matches!(
            family("audit_events").pagination(),
            Pagination::Cursor {
                parameter,
                response_path,
                page_size_parameter: Some(page_size_parameter),
                page_size: 100,
            } if parameter == "page[cursor]"
                && response_path == "$.meta.page.after|$.meta.page.cursor|$.links.next"
                && page_size_parameter == "page[limit]"
        ));
    }

    #[test]
    fn compiles_the_complete_checked_in_catalog() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let summary = catalog.summary();
        assert_eq!(summary.sources, 800);
        assert_eq!(summary.families, 4_019);
        assert_eq!(summary.push_sources, 1);
        assert_eq!(summary.push_families, 10);
        assert_eq!(
            summary.projection_classes.values().sum::<usize>(),
            summary.families
        );
        assert_eq!(
            summary
                .projection_classes
                .get(&ProjectionClass::Bespoke)
                .copied()
                .unwrap_or_default(),
            3
        );
        for class in [
            ProjectionClass::Identity,
            ProjectionClass::Access,
            ProjectionClass::Resource,
            ProjectionClass::Finding,
            ProjectionClass::Activity,
        ] {
            assert!(
                summary
                    .projection_classes
                    .get(&class)
                    .copied()
                    .unwrap_or_default()
                    > 0
            );
        }
        assert!(summary.authoritative_sources > 0);
        assert!(summary.authoritative_sources < summary.sources);
        assert_eq!(
            summary.sources,
            summary.authoritative_sources + summary.shadow_only_sources
        );
        let unresolved_api_key_placement = catalog
            .sources()
            .filter(|source| {
                source.authority() == CollectionAuthority::Authoritative
                    && source.auth() == &AuthModel::ApiKey
                    && source.token_header().is_empty()
                    && source.auth_header_parameters().is_empty()
                    && source.auth_query_parameters().is_empty()
                    && source.auth_json_body_parameters().is_empty()
            })
            .map(CompiledSource::id)
            .collect::<Vec<_>>();
        assert!(
            unresolved_api_key_placement.is_empty(),
            "authoritative API-key sources have no credential placement: {unresolved_api_key_placement:?}"
        );
        assert_eq!(
            catalog.get("elevenlabs").unwrap().token_header(),
            "xi-api-key"
        );
        assert_eq!(catalog.get("snyk").unwrap().token_header(), "Authorization");
        assert_eq!(catalog.get("snyk").unwrap().token_scheme(), "Token");
        let okta_group_membership = catalog
            .get("okta")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "group_membership")
            .unwrap();
        assert_eq!(
            okta_group_membership.projection().template(),
            "group_membership"
        );
        assert_eq!(
            okta_group_membership
                .projection()
                .fields()
                .get("group_id")
                .map(String::as_str),
            Some("group_id")
        );
        assert_eq!(
            okta_group_membership
                .projection()
                .fields()
                .get("member_id")
                .map(String::as_str),
            Some("member_id|member_user_id|user_id|id")
        );
        // The checked-in catalog also describes events produced by hand-written
        // connectors. Those exact, singular family IDs are durable protocol
        // names: replay must not guess that `application` means the separate
        // declarative `applications` endpoint.
        let okta_application = catalog
            .get("okta")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "application")
            .unwrap();
        assert_eq!(
            okta_application.projection().template(),
            "identity_application"
        );
        assert_eq!(
            okta_application
                .projection()
                .fields()
                .get("app_id")
                .map(String::as_str),
            Some("app_id|id")
        );
        assert_eq!(
            catalog.get("airbrake").unwrap().auth_query_parameters(),
            &BTreeMap::from([("key".to_owned(), "token".to_owned())])
        );
        assert_eq!(
            catalog.get("alchemer").unwrap().auth_query_parameters(),
            &BTreeMap::from([
                ("api_token".to_owned(), "api_token".to_owned()),
                ("api_token_secret".to_owned(), "api_token_secret".to_owned()),
            ])
        );
        assert_eq!(
            catalog.get("akeyless").unwrap().auth_json_body_parameters(),
            &BTreeMap::from([("token".to_owned(), "api_token".to_owned())])
        );
        assert_eq!(
            catalog.get("meraki").unwrap().token_header(),
            "Authorization"
        );
        assert_eq!(catalog.get("meraki").unwrap().token_scheme(), "Bearer");
        let meraki_event_type = catalog
            .get("meraki")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "eventtype")
            .unwrap();
        assert_eq!(meraki_event_type.id_field(), "type");
        assert_eq!(
            meraki_event_type
                .projection()
                .fields()
                .get("id")
                .map(String::as_str),
            Some("type")
        );
        assert_eq!(
            meraki_event_type
                .projection()
                .fields()
                .get("provider_id")
                .map(String::as_str),
            Some("type")
        );
        assert_eq!(
            meraki_event_type
                .projection()
                .fields()
                .get("event_type")
                .map(String::as_str),
            Some("type")
        );
        let meraki_organization = catalog
            .get("meraki")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "organization")
            .unwrap();
        assert_eq!(
            meraki_organization.pagination(),
            &Pagination::Link {
                header: "Link".to_owned()
            }
        );
        assert_eq!(
            meraki_organization.static_query(),
            &BTreeMap::from([("perPage".to_owned(), "9000".to_owned())])
        );
        assert_eq!(
            meraki_organization
                .projection()
                .fields()
                .get("group_id")
                .map(String::as_str),
            Some("id")
        );
        assert_eq!(
            meraki_organization
                .projection()
                .fields()
                .get("group_name")
                .map(String::as_str),
            Some("name")
        );
        let meraki_auth_user = catalog
            .get("meraki")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "merakiauthuser")
            .unwrap();
        assert_eq!(
            meraki_auth_user
                .projection()
                .fields()
                .get("user_id")
                .map(String::as_str),
            Some("id")
        );
        assert_eq!(
            meraki_auth_user
                .projection()
                .fields()
                .get("display_name")
                .map(String::as_str),
            Some("name")
        );
        assert_eq!(
            meraki_auth_user
                .projection()
                .fields()
                .get("email")
                .map(String::as_str),
            Some("email")
        );
        let meraki_access_policy = catalog
            .get("meraki")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "accesspolicy")
            .unwrap();
        assert_eq!(meraki_access_policy.id_field(), "accessPolicyNumber");
        assert_eq!(
            meraki_access_policy
                .projection()
                .fields()
                .get("id")
                .map(String::as_str),
            Some("accessPolicyNumber")
        );
        assert_eq!(
            meraki_access_policy
                .projection()
                .fields()
                .get("policy_id")
                .map(String::as_str),
            Some("accessPolicyNumber")
        );
        assert_eq!(
            meraki_access_policy
                .projection()
                .fields()
                .get("policy_name")
                .map(String::as_str),
            Some("name")
        );
        assert_eq!(
            catalog.get("api2cart").unwrap().auth_header_parameters(),
            &BTreeMap::from([
                ("x-api-key".to_owned(), "api_key".to_owned()),
                ("x-store-key".to_owned(), "store_key".to_owned()),
            ])
        );
        assert_eq!(
            catalog.get("botify").unwrap().token_header(),
            "Authorization"
        );
        assert_eq!(catalog.get("botify").unwrap().token_scheme(), "Token");
        let botify = catalog.get("botify").unwrap();
        let out_of_config = botify
            .families()
            .iter()
            .find(|family| family.id() == "out_of_config")
            .unwrap();
        assert_eq!(out_of_config.scalar_record_field(), Some("url"));
        assert!(matches!(
            out_of_config.pagination(),
            Pagination::Page {
                page_size_parameter: Some(parameter),
                page_size: 100,
                ..
            } if parameter == "size"
        ));
        let mastodon = catalog.get("mastodon").unwrap();
        let mastodon_account = mastodon
            .families()
            .iter()
            .find(|family| family.id() == "account")
            .unwrap();
        assert_eq!(
            mastodon_account.pagination(),
            &Pagination::Link {
                header: "Link".to_owned()
            }
        );
        assert_eq!(
            mastodon_account.static_query(),
            &BTreeMap::from([("limit".to_owned(), "80".to_owned())])
        );
        assert_eq!(
            mastodon_account
                .projection()
                .fields()
                .get("user_id")
                .map(String::as_str),
            Some("id")
        );
        let mastodon_activity = mastodon
            .families()
            .iter()
            .find(|family| family.id() == "activity")
            .unwrap();
        assert_eq!(mastodon_activity.id_field(), "week");
        assert_eq!(
            mastodon_activity
                .projection()
                .fields()
                .get("provider_id")
                .map(String::as_str),
            Some("week")
        );
        assert_eq!(
            mastodon_activity
                .projection()
                .static_fields()
                .get("event_type")
                .map(String::as_str),
            Some("instance_activity")
        );
        let mastodon_credential = mastodon
            .families()
            .iter()
            .find(|family| family.id() == "verify_credential")
            .unwrap();
        assert_eq!(mastodon_credential.record_selector(), "$");
        assert_eq!(mastodon_credential.id_field(), "id");
        assert_eq!(mastodon_credential.projection().template(), "identity_user");
        assert_eq!(
            mastodon_credential
                .projection()
                .fields()
                .get("login")
                .map(String::as_str),
            Some("acct|username")
        );
        let mastodon_notification = mastodon
            .families()
            .iter()
            .find(|family| family.id() == "notification")
            .unwrap();
        assert_eq!(
            mastodon_notification.pagination(),
            &Pagination::Link {
                header: "Link".to_owned()
            }
        );
        assert_eq!(
            mastodon_notification.static_query(),
            &BTreeMap::from([("limit".to_owned(), "80".to_owned())])
        );
        assert_eq!(
            mastodon_notification
                .projection()
                .fields()
                .get("alert_source")
                .map(String::as_str),
            Some("status.url|account.url")
        );
        assert_eq!(
            mastodon_notification
                .projection()
                .fields()
                .get("resource_id")
                .map(String::as_str),
            Some("status.id|account.id|id")
        );
        let abuseipdb = catalog.get("abuseipdb").unwrap();
        let abuseipdb_reports = abuseipdb
            .families()
            .iter()
            .find(|family| family.id() == "reports")
            .unwrap();
        assert_eq!(
            abuseipdb_reports.pagination(),
            &Pagination::Page {
                parameter: "page".to_owned(),
                start: 1,
                page_size_parameter: Some("perPage".to_owned()),
                page_size: 100,
            }
        );
        assert_eq!(
            abuseipdb_reports.id_template(),
            Some("${reportedAt}:${reporterId}")
        );
        assert_eq!(
            abuseipdb_reports.config_query().get("ipAddress"),
            Some(&PathParameterBinding::ScalarConfig {
                field: "ip_address".to_owned()
            })
        );
        assert_eq!(
            abuseipdb_reports.config_query().get("maxAgeInDays"),
            Some(&PathParameterBinding::OptionalScalarConfig {
                field: "max_age_in_days".to_owned()
            })
        );
        assert!(
            !abuseipdb_reports
                .projection()
                .fields()
                .contains_key("finding_id")
        );
        let abuseipdb_blacklist = abuseipdb
            .families()
            .iter()
            .find(|family| family.id() == "ip_addresses")
            .unwrap();
        assert_eq!(abuseipdb_blacklist.pagination(), &Pagination::None);
        assert_eq!(
            abuseipdb_blacklist.static_query(),
            &BTreeMap::from([
                ("confidenceMinimum".to_owned(), "90".to_owned()),
                ("limit".to_owned(), "10000".to_owned()),
            ])
        );
        for family in catalog.get("akeyless").unwrap().families() {
            assert_eq!(
                family.cursor_in_json_body(),
                family.id() != "analytics",
                "{} JSON-body cursor placement",
                family.id()
            );
        }
    }

    #[test]
    fn trusted_endpoint_is_a_push_contract_not_an_http_poller() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        assert!(catalog.get("trusted_endpoint").is_none());
        let source = catalog.push_source("trusted_endpoint").unwrap();
        assert_eq!(source.id(), "trusted_endpoint");
        assert_eq!(source.display_name(), "Trusted Endpoint");
        let families = source
            .families()
            .map(|family| family.id())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            families,
            BTreeSet::from([
                "action_outcome",
                "agent_execution_receipt",
                "agent_identity",
                "ai_session_summary",
                "ai_workflow_risk",
                "grc_evidence",
                "host_posture",
                "repo_worktree_context",
                "security_finding",
                "trust_gate_decision",
            ])
        );
        for family in source.families() {
            assert_eq!(
                family.event_kind(),
                format!("trusted_endpoint.{}", family.id())
            );
            assert_eq!(
                family.schema_ref(),
                format!("trusted_endpoint/{}/v1", family.id())
            );
            assert!(
                catalog.admits_event_family("trusted_endpoint", family.id()),
                "push family {} was not admitted",
                family.id()
            );
        }
        let receipt = source.family("agent_execution_receipt").unwrap();
        let required_attributes = receipt
            .required_attributes()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required_payload_fields = receipt
            .required_payload_fields()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let producer_authority_fields =
            BTreeSet::from(["provider_binding", "receipt_digest", "sequence"]);
        assert!(required_attributes.is_superset(&producer_authority_fields));
        assert!(required_payload_fields.is_superset(&producer_authority_fields));
        assert!(!catalog.admits_event_family("trusted_endpoint", "unknown"));
    }

    #[test]
    fn pull_and_push_source_ids_cannot_intersect() {
        let pull_sources = BTreeMap::from([("shared_source".to_owned(), ())]);
        let push_sources = BTreeMap::from([(
            "shared_source".to_owned(),
            CompiledPushSource {
                id: "shared_source".to_owned(),
                display_name: "Shared Source".to_owned(),
                families: BTreeMap::new(),
            },
        )]);
        assert_eq!(
            reject_dual_mode_source_ids(pull_sources.keys(), &push_sources),
            Err(CatalogError::DuplicateSource("shared_source".to_owned()))
        );

        let disjoint_pull_sources = BTreeMap::from([("pull_source".to_owned(), ())]);
        assert_eq!(
            reject_dual_mode_source_ids(disjoint_pull_sources.keys(), &push_sources),
            Ok(())
        );
    }

    #[test]
    fn verified_source_is_authoritative_but_unproven_source_is_not() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        assert_eq!(
            catalog.get("aws_bedrock").unwrap().authority(),
            CollectionAuthority::Authoritative
        );
        assert_eq!(
            catalog.get("duo").unwrap().authority(),
            CollectionAuthority::Authoritative
        );
        assert_eq!(
            catalog.get("telnyx").unwrap().authority(),
            CollectionAuthority::Authoritative
        );
        for source_id in [
            "abuseipdb",
            "akeneo",
            "akeyless",
            "apacta",
            "appwrite",
            "airbrake",
            "alchemer",
            "airtable",
            "anchore",
            "api2cart",
            "azure_openai",
            "beezup",
            "botify",
            "box",
            "cloudflare_workers_ai",
            "elevenlabs",
            "fivetran",
            "google_vertex_ai",
            "jira",
            "mastodon",
            "meraki",
            "onelogin",
            "qdrant_cloud",
            "snyk",
        ] {
            assert_eq!(
                catalog.get(source_id).unwrap().authority(),
                CollectionAuthority::Authoritative,
                "{source_id} has verified parameterized provider paths"
            );
        }
        assert_eq!(
            catalog.get("agiloft").unwrap().authority(),
            CollectionAuthority::ShadowOnly
        );
    }

    #[test]
    fn retired_static_loader_sources_are_fully_rust_authoritative() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        for source_id in [
            "abnormal_security",
            "abuseipdb",
            "activecampaign",
            "activtrak",
            "acunetix",
            "ada_support",
            "addigy",
            "adobe_workfront",
            "adp_workforce_now",
            "aha",
            "airbrake",
            "airbyte_cloud",
            "aircall",
            "airfocus",
            "airtable",
            "akeneo",
            "akeyless",
            "alation",
            "alchemer",
            "alteryx",
            "amplitude",
            "anchore",
            "anomalo",
            "apache",
            "apacta",
            "api2cart",
            "apideck",
            "apigee",
            "apollo",
            "appwrite",
            "authentik_cloud",
            "aws_bedrock",
            "azure_openai",
            "backstage",
            "beezup",
            "bitwarden",
            "botify",
            "box",
            "cloudflare",
            "cloudflare_workers_ai",
            "cloudflare_zero_trust",
            "cohere",
            "conjur",
            "datadog",
            "deepseek",
            "digitalocean",
            "duo",
            "elevenlabs",
            "fivetran",
            "gitguardian",
            "gitlab",
            "google_vertex_ai",
            "hashicorp_vault",
            "increase",
            "jira",
            "jumpcloud",
            "langchain",
            "mailchimp",
            "mastodon",
            "meraki",
            "microsoft_entra_id",
            "new_relic",
            "openai",
            "qdrant_cloud",
            "slack",
            "telnyx",
            "twilio",
        ] {
            let source = catalog.get(source_id).unwrap();
            assert_eq!(
                source.authority(),
                CollectionAuthority::Authoritative,
                "{source_id} must keep complete Rust collection authority"
            );
            assert!(
                source
                    .families()
                    .iter()
                    .all(CompiledFamily::is_authoritative),
                "{source_id} contains a non-authoritative collection family"
            );
            assert!(
                source
                    .families()
                    .iter()
                    .all(CompiledFamily::is_projection_authoritative),
                "{source_id} contains a non-authoritative projection family"
            );
        }
    }

    #[test]
    fn standard_source_plan_index_matches_compiled_authoritative_plans() {
        let root = repository_root();
        let index =
            fs::read_to_string(root.join("internal/sourceregistry/standard_source_plan_index.txt"))
                .unwrap();
        let mut lines = index.lines();
        assert_eq!(lines.next(), Some("standard-source-plan-index/v1"));
        let entries = lines
            .map(|line| {
                let (source_id, families) = line.split_once('\t').unwrap();
                (source_id, families.split(',').collect::<Vec<_>>())
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            entries.keys().copied().collect::<Vec<_>>(),
            [
                "abnormal_security",
                "abuseipdb",
                "activecampaign",
                "activtrak",
                "acunetix",
                "ada_support",
                "addigy",
                "adobe_workfront",
                "adp_workforce_now",
                "aha",
                "airbrake",
                "airbyte_cloud",
                "aircall",
                "airfocus",
                "airtable",
                "akeneo",
                "akeyless",
                "alation",
                "alchemer",
                "alteryx",
                "amplitude",
                "anchore",
                "anomalo",
                "apache",
                "apacta",
                "api2cart",
                "apideck",
                "apollo",
                "appwrite",
                "aws_bedrock",
                "azure_openai",
                "backstage",
                "beezup",
                "bitwarden",
                "botify",
                "box",
                "cloudflare",
                "cloudflare_workers_ai",
                "cohere",
                "conjur",
                "datadog",
                "deepseek",
                "digitalocean",
                "duo",
                "elevenlabs",
                "fivetran",
                "gitlab",
                "google_vertex_ai",
                "increase",
                "jira",
                "jumpcloud",
                "langchain",
                "mastodon",
                "meraki",
                "microsoft_entra_id",
                "new_relic",
                "openai",
                "qdrant_cloud",
                "slack",
                "telnyx",
                "twilio",
            ]
        );

        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        for (source_id, indexed_families) in entries {
            let source = catalog.get(source_id).unwrap();
            assert_eq!(source.authority(), CollectionAuthority::Authoritative);
            assert!(
                source
                    .families()
                    .iter()
                    .all(CompiledFamily::is_authoritative)
            );
            assert!(
                source
                    .families()
                    .iter()
                    .all(CompiledFamily::is_projection_authoritative)
            );
            let mut compiled_families = source
                .families()
                .iter()
                .map(CompiledFamily::id)
                .collect::<Vec<_>>();
            compiled_families.sort_unstable();
            assert_eq!(indexed_families, compiled_families);
        }
    }

    #[test]
    fn oauth_client_credentials_contract_is_compiled_without_credential_material() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let oauth = catalog
            .get("auth0")
            .unwrap()
            .oauth_client_credentials()
            .unwrap();
        assert_eq!(oauth.token_url(), "https://${config.domain}/oauth/token");
        assert_eq!(oauth.scope_separator(), " ");
        assert_eq!(oauth.token_request_auth_method(), "client_secret_post");
        assert_eq!(
            oauth.token_params().get("audience").map(String::as_str),
            Some("https://${config.domain}/api/v2/")
        );
        assert!(oauth.scopes().contains(&"read:users".to_owned()));
    }

    #[test]
    fn oauth_authorization_code_contract_is_compiled_for_every_catalog_source() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let actual = catalog
            .sources()
            .filter(|source| source.oauth_authorization_code().is_some())
            .map(CompiledSource::id)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                "azure_devops",
                "bitbucket_cloud",
                "dracoon",
                "drchrono",
                "dropbox_business",
                "google_drive",
                "hubspot",
                "miro",
                "runscope",
                "salesforce",
                "servicenow",
                "signl4",
                "slack",
                "square",
            ]
        );
        let drchrono = catalog
            .get("drchrono")
            .unwrap()
            .oauth_authorization_code()
            .unwrap();
        assert_eq!(drchrono.token_url(), "https://drchrono.com/o/token/");
        assert_eq!(drchrono.token_request_auth_method(), "client_secret_basic");
        assert!(drchrono.scopes().contains(&"patients:read".to_owned()));
        assert_eq!(drchrono.scope_separator(), " ");
        assert!(drchrono.token_params().is_empty());
        assert_eq!(
            catalog
                .get("signl4")
                .unwrap()
                .oauth_authorization_code()
                .unwrap()
                .token_url(),
            "https://connect.signl4.com/identity/connect/token"
        );
    }

    #[test]
    fn precomputed_signature_contract_is_executable_but_remains_shadow_only() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let actual = catalog
            .sources()
            .filter(|source| source.auth() == &AuthModel::Signature)
            .map(CompiledSource::id)
            .collect::<Vec<_>>();
        assert_eq!(actual, vec!["netsuite", "veracode"]);

        for source_id in actual {
            let source = catalog.get(source_id).unwrap();
            assert!(source.auth().supports_generic_runtime());
            assert_eq!(source.token_header(), "Authorization");
            assert_eq!(source.token_scheme(), "Signature");
            assert_eq!(source.authority(), CollectionAuthority::ShadowOnly);
            for family in source.families() {
                assert!(
                    !family
                        .unsupported_reasons()
                        .contains(&UnsupportedReasonCode::UnsupportedAuthModel)
                );
                assert!(
                    family
                        .unsupported_reasons()
                        .contains(&UnsupportedReasonCode::MissingProviderProof)
                );
            }
        }
    }

    #[test]
    fn bespoke_classifier_is_not_reported_as_an_auth_failure() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();

        for source_id in ["auth0", "kubernetes"] {
            let source = catalog.get(source_id).unwrap();
            assert!(source.auth().supports_generic_runtime());
            for family in source.families() {
                assert!(
                    !family
                        .unsupported_reasons()
                        .contains(&UnsupportedReasonCode::UnsupportedAuthModel)
                );
                assert!(
                    family
                        .unsupported_reasons()
                        .contains(&UnsupportedReasonCode::BespokeRuntime)
                );
            }
        }
    }

    #[test]
    fn composite_id_templates_are_closed_and_bounded() {
        for valid in [
            "${reportedAt}:${reporterId}",
            "${namespace}/${name}",
            "prefix-${nested.value}",
        ] {
            assert!(valid_id_template(valid), "{valid}");
        }
        for invalid in [
            "",
            "literal-only",
            "${}",
            "${missing",
            "${bad field}",
            "${nested..value}",
            "${field}}",
            " ${field}",
        ] {
            assert!(!valid_id_template(invalid), "{invalid}");
        }
        assert!(!valid_id_template(&format!(
            "${{field}}{}",
            "x".repeat(1_024)
        )));
        assert!(valid_singleton_id_literal("organization:data_retention"));
        for invalid in [
            "",
            " leading",
            "trailing ",
            "contains${field}",
            "line\nbreak",
        ] {
            assert!(!valid_singleton_id_literal(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn scoped_provider_paths_bind_only_declared_runtime_config() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();

        let airtable = catalog.get("airtable").unwrap();
        assert_eq!(airtable.authority(), CollectionAuthority::Authoritative);
        for family_id in ["users", "audit_events"] {
            let family = airtable
                .families()
                .iter()
                .find(|family| family.id() == family_id)
                .unwrap();
            assert_eq!(
                family.path_parameters().get("enterprise_account_id"),
                Some(&PathParameterBinding::ScalarConfig {
                    field: "enterprise_account_id".to_owned()
                })
            );
        }

        let anchore = catalog.get("anchore").unwrap();
        assert_eq!(anchore.authority(), CollectionAuthority::Authoritative);
        for family in anchore.families() {
            assert_eq!(
                family.path_parameters().get("app_id"),
                Some(&PathParameterBinding::ScalarConfig {
                    field: "app_id".to_owned()
                })
            );
            assert_eq!(
                family.path_parameters().get("version_id"),
                Some(&PathParameterBinding::ScalarConfig {
                    field: "version_id".to_owned()
                })
            );
        }
    }

    #[test]
    fn plural_config_fields_compile_to_explicit_csv_fanout_bindings() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let family = catalog
            .get("box")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "group_memberships")
            .unwrap();
        assert_eq!(
            family.path_parameters().get("group_id"),
            Some(&PathParameterBinding::CsvFanout {
                field: "group_ids".to_owned()
            })
        );
    }

    #[test]
    fn slack_membership_scope_compiles_to_collection_authority() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let family = catalog
            .get("slack")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "channel_member")
            .unwrap();
        assert!(family.is_authoritative());
        assert_eq!(
            family.config_query().get("channel"),
            Some(&PathParameterBinding::OptionalScalarConfig {
                field: "channel_id".to_owned()
            })
        );
    }

    #[test]
    fn explicit_fanout_binding_maps_a_provider_slot_to_its_configured_list() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let family = catalog
            .get("fivetran")
            .unwrap()
            .families()
            .iter()
            .find(|family| family.id() == "connector_metadata_details")
            .unwrap();
        assert_eq!(
            family.path_parameters().get("service"),
            Some(&PathParameterBinding::CsvFanout {
                field: "connector_services".to_owned()
            })
        );
        assert_eq!(
            family.config_attributes().get("service"),
            family.path_parameters().get("service")
        );
    }

    #[test]
    fn bespoke_collection_does_not_block_a_verified_native_projection() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let auth0 = catalog.get("auth0").unwrap();
        assert_eq!(auth0.authority(), CollectionAuthority::ShadowOnly);
        let grants = auth0
            .families()
            .iter()
            .find(|family| family.id() == "grants")
            .unwrap();
        assert!(!grants.is_authoritative());
        assert!(grants.is_projection_authoritative());
    }

    #[test]
    fn provider_path_templates_match_slots_but_not_literal_scope() {
        assert_eq!(
            canonical_path_template("/sim_cards/{id}/wireless_connectivity_logs"),
            Some("/sim_cards/{}/wireless_connectivity_logs".to_owned())
        );
        assert_eq!(
            canonical_path_template("/sim_cards/${config.sim_card_id}/wireless_connectivity_logs"),
            Some("/sim_cards/{}/wireless_connectivity_logs".to_owned())
        );
        assert_ne!(
            canonical_path_template("/accounts/{id}/users"),
            canonical_path_template("/organizations/{id}/users")
        );
        assert_eq!(canonical_path_template("/accounts/prefix-{id}/users"), None);
        assert_eq!(canonical_path_template("/accounts/${config.id/users"), None);
        assert_eq!(
            canonical_family_locator(Some("https://api.slack.com/audit/v1"), "/logs"),
            canonical_contract_locator("https://api.slack.com/audit/v1/logs")
        );
        assert_eq!(
            canonical_contract_locator("https://user@example.test/logs"),
            None
        );
    }

    #[test]
    fn unsupported_feature_report_classifies_every_family_with_reason_codes() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let report = catalog.unsupported_feature_report();
        assert_eq!(report.total_sources, 800);
        assert_eq!(report.total_families, 4_019);
        assert_eq!(report.families.len(), report.total_families);
        assert!(report.missing_family_reports.is_empty());
        assert_eq!(
            report.total_families,
            report.rust_authoritative_families
                + report.shadow_only_families
                + report.projection_only_families
                + report.unsupported_families
        );
        for family in &report.families {
            if family.classification != CatalogFamilyClassification::RustAuthoritative {
                assert!(
                    !family.reason_codes.is_empty(),
                    "{}:{} lacks unsupported reason codes",
                    family.source_id,
                    family.family_id
                );
            }
            assert!(!family.safe_detail.contains("sentinel-secret-value"));
            assert!(!family.safe_detail.contains("sentinel-token-value"));
        }
        assert!(
            report
                .reason_code_counts
                .contains_key(&UnsupportedReasonCode::MissingProviderAuthorityEvidence)
        );
        println!(
            "unsupported_feature_report total_sources={} total_families={} rust_authoritative={} shadow_only={} projection_only={} unsupported={} missing_family_reports={:?} reason_code_counts={:?}",
            report.total_sources,
            report.total_families,
            report.rust_authoritative_families,
            report.shadow_only_families,
            report.projection_only_families,
            report.unsupported_families,
            report.missing_family_reports,
            report.reason_code_counts
        );
    }

    #[test]
    fn authority_readiness_defaults_to_shadow_until_provider_proof_is_complete() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let report = catalog.authority_readiness_report();
        assert_eq!(report.total_families, 4_019);
        assert_eq!(report.rust_authoritative_families, 0);
        assert_eq!(report.shadow_or_go_families, report.total_families);
        let aws_bedrock = report
            .families
            .iter()
            .find(|family| family.source_id == "aws_bedrock")
            .expect("aws_bedrock readiness row");
        assert_eq!(aws_bedrock.engine, "go_or_shadow_only");
        assert_eq!(aws_bedrock.authority_epoch, 0);
        assert_eq!(aws_bedrock.plan_digest.len(), 64);
        for required in [
            "fixture_corpus_revision",
            "rollback_receipt",
            "promotion_receipt",
            "worker_runtime_build_identity",
        ] {
            assert!(
                aws_bedrock.blocking_reasons.contains(&required.to_owned()),
                "{required}"
            );
        }
        println!(
            "authority_readiness total_families={} rust_authoritative={} shadow_or_go={} sample_plan_digest={}",
            report.total_families,
            report.rust_authoritative_families,
            report.shadow_or_go_families,
            aws_bedrock.plan_digest
        );
    }

    #[test]
    fn conjur_and_langsmith_compile_exact_request_contracts() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();

        let conjur = catalog.get("conjur").unwrap();
        assert_eq!(conjur.auth(), &AuthModel::Basic);
        assert_eq!(conjur.configurable_auth_models(), &[AuthModel::Basic]);
        assert_eq!(conjur.families().len(), 4);
        let resource = conjur
            .families()
            .iter()
            .find(|family| family.id() == "resource_3")
            .unwrap();
        assert_eq!(
            resource.path(),
            "/resources/${config.account}/${config.kind}"
        );
        assert_eq!(
            resource.map_records().get("data.key_info"),
            Some(&"resource".to_owned())
        );
        assert!(matches!(
            resource.pagination(),
            Pagination::Offset {
                parameter,
                limit_parameter,
                page_size: 100
            } if parameter == "offset" && limit_parameter == "limit"
        ));

        let langsmith = catalog.get("langchain").unwrap();
        assert_eq!(
            langsmith.configurable_auth_models(),
            &[AuthModel::ApiKey, AuthModel::BearerToken]
        );
        assert_eq!(langsmith.families().len(), 13);
        let run = langsmith
            .families()
            .iter()
            .find(|family| family.id() == "run")
            .unwrap();
        assert_eq!(run.method(), HttpMethod::Post);
        assert_eq!(run.path(), "/api/v1/runs/query");
        assert_eq!(run.config_json_body().len(), 6);
        assert_eq!(
            run.static_json_body().get("limit"),
            Some(&serde_json::json!(100))
        );
        assert!(matches!(
            run.pagination(),
            Pagination::Cursor { parameter, response_path, .. }
                if parameter == "cursor" && response_path == "$.cursors.next"
        ));
        let audit = langsmith
            .families()
            .iter()
            .find(|family| family.id() == "audit_log")
            .unwrap();
        assert!(matches!(
            audit.pagination(),
            Pagination::Cursor { parameter, response_path, .. }
                if parameter == "cursor" && response_path == "$.cursor"
        ));
        for family_id in [
            "workspace_member",
            "project",
            "run",
            "feedback",
            "dataset",
            "usage_limit",
            "audit_log",
        ] {
            let family = langsmith
                .families()
                .iter()
                .find(|family| family.id() == family_id)
                .unwrap();
            assert_eq!(
                family
                    .config_headers()
                    .get("X-Organization-Id")
                    .map(PathParameterBinding::field),
                Some("organization_id")
            );
            assert_eq!(
                family
                    .config_headers()
                    .get("X-Tenant-Id")
                    .map(PathParameterBinding::field),
                Some("workspace_id")
            );
        }
    }

    #[test]
    fn canonical_digest_vectors_are_stable_for_catalog_plans() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let source = catalog.get("okta").unwrap();
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == "group_membership")
            .unwrap();
        let first = family_plan_digest(source, family);
        let second = family_plan_digest(source, family);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        println!("canonical_digest okta/group_membership plan={first}");
    }
}
