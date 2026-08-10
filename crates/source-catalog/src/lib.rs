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
    method: HttpMethod,
    path: String,
    record_selector: String,
    scalar_record_field: Option<String>,
    id_template: Option<String>,
    id_field: String,
    name_field: Option<String>,
    static_query: BTreeMap<String, String>,
    config_query: BTreeMap<String, PathParameterBinding>,
    config_attributes: BTreeMap<String, PathParameterBinding>,
    pagination: Pagination,
    cursor_in_json_body: bool,
    path_parameters: BTreeMap<String, PathParameterBinding>,
    projection: Projection,
    authoritative: bool,
    projection_authoritative: bool,
}

impl CompiledFamily {
    pub fn id(&self) -> &str {
        &self.id
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

    pub fn config_attributes(&self) -> &BTreeMap<String, PathParameterBinding> {
        &self.config_attributes
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledSource {
    id: String,
    display_name: String,
    auth: AuthModel,
    token_header: String,
    token_scheme: String,
    auth_header_parameters: BTreeMap<String, String>,
    auth_query_parameters: BTreeMap<String, String>,
    auth_json_body_parameters: BTreeMap<String, String>,
    authority: CollectionAuthority,
    families: Vec<CompiledFamily>,
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
    pub authoritative_sources: usize,
    pub authoritative_families: usize,
    pub shadow_only_sources: usize,
    pub projection_classes: BTreeMap<ProjectionClass, usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCatalog {
    sources: BTreeMap<String, CompiledSource>,
}

impl SourceCatalog {
    /// Loads the complete definition catalog and joins it to provider proof
    /// manifests. Missing or unverified proof can only produce shadow data.
    pub fn load(
        definition_root: impl AsRef<Path>,
        source_root: impl AsRef<Path>,
    ) -> Result<Self, CatalogError> {
        let proofs = load_proofs(source_root.as_ref())?;
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
                let source = compile_source(&path, entry, &proofs)?;
                if sources.insert(source.id.clone(), source.clone()).is_some() {
                    return Err(CatalogError::DuplicateSource(source.id));
                }
            }
        }
        Ok(Self { sources })
    }

    pub fn get(&self, source_id: &str) -> Option<&CompiledSource> {
        self.sources.get(source_id)
    }

    pub fn sources(&self) -> impl Iterator<Item = &CompiledSource> {
        self.sources.values()
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
            authoritative_sources,
            authoritative_families,
            shadow_only_sources: self.sources.len() - authoritative_sources,
            projection_classes,
        }
    }
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
}

#[derive(Deserialize)]
struct CredentialFieldWire {
    key: String,
}

#[derive(Deserialize)]
struct FamilyWire {
    id: String,
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
    pagination: Option<PaginationWire>,
    projection: Option<ProjectionWire>,
}

#[derive(Default, Deserialize)]
struct FamilyConfigWire {
    #[serde(default)]
    config_query: BTreeMap<String, String>,
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
}

#[derive(Deserialize)]
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
    start_page: usize,
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
    provider_api: Option<ProviderApiWire>,
    #[serde(default)]
    runtime_families: Vec<String>,
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
    let generic_runtime_supported = classifier_supported
        && auth.supports_generic_runtime()
        && (auth != AuthModel::ApiKey
            || !token_header.is_empty()
            || !auth_header_parameters.is_empty()
            || !auth_query_parameters.is_empty()
            || !auth_json_body_parameters.is_empty());
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
        && families.iter().any(CompiledFamily::cursor_in_json_body)
    {
        return invalid(
            path,
            "JSON body cursor placement requires JSON body authentication",
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
        token_header,
        token_scheme,
        auth_header_parameters,
        auth_query_parameters,
        auth_json_body_parameters,
        authority,
        families,
    })
}

fn compile_family(
    path: &Path,
    family: FamilyWire,
    verified: &BTreeSet<(String, String, String)>,
    generic_runtime_supported: bool,
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
    if id_template
        .as_deref()
        .is_some_and(|template| !valid_id_template(template))
    {
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
    let provider_contract_verified = canonical_path_template(&family.path).is_some_and(|path| {
        verified.contains(&(
            family.id.clone(),
            match method {
                HttpMethod::Get => "GET".to_owned(),
                HttpMethod::Post => "POST".to_owned(),
            },
            path,
        ))
    });
    Ok(CompiledFamily {
        authoritative: generic_runtime_supported
            && provider_contract_verified
            && path_parameters_configured
            && config_query_configured
            && config_attributes_configured,
        projection_authoritative: provider_contract_verified
            && projection_class.can_be_authoritative(),
        id: nonempty(path, "family id", family.id)?,
        method,
        path: family.path,
        record_selector,
        scalar_record_field,
        id_template,
        id_field: nonempty(path, "family id_field", family.id_field)?,
        name_field: optional(family.name_field),
        static_query: family.static_query,
        config_query,
        config_attributes,
        pagination: compile_pagination(path, family.pagination)?,
        cursor_in_json_body,
        path_parameters,
        projection: Projection {
            class: projection_class,
            template,
            fields: projection.fields,
            static_fields: projection.static_fields,
        },
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
            } else if let Some(key) = wire.next_cursor_keys.first() {
                format!("$.{key}")
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
            start: wire.start_page.max(1),
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
            canonical_path_template(&family.path).map(|path| {
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

fn load_proofs(root: &Path) -> Result<BTreeMap<String, ProofManifestWire>, CatalogError> {
    let mut proofs = BTreeMap::new();
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
        if proofs.insert(proof.id.clone(), proof).is_some() {
            return Err(CatalogError::DuplicateSource(
                entry.file_name().to_string_lossy().into(),
            ));
        }
    }
    Ok(proofs)
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

    fn invalid_message(result: Result<CompiledSource, CatalogError>) -> String {
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
            "JSON body cursor placement requires JSON body authentication"
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
    fn compiles_the_complete_checked_in_catalog() {
        let root = repository_root();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let summary = catalog.summary();
        assert_eq!(summary.sources, 794);
        assert_eq!(summary.families, 3_892);
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
    fn undeclared_query_scope_cannot_become_collection_authority() {
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
        assert!(!family.is_authoritative());
        assert!(family.config_query().is_empty());
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
    }
}
