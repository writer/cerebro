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
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
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
    id_field: String,
    name_field: Option<String>,
    static_query: BTreeMap<String, String>,
    pagination: Pagination,
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

    pub fn id_field(&self) -> &str {
        &self.id_field
    }

    pub fn name_field(&self) -> Option<&str> {
        self.name_field.as_deref()
    }

    pub fn static_query(&self) -> &BTreeMap<String, String> {
        &self.static_query
    }

    pub fn pagination(&self) -> &Pagination {
        &self.pagination
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
    resource_families: Vec<FamilyWire>,
}

#[derive(Deserialize)]
struct AuthWire {
    model: String,
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
    pagination: Option<PaginationWire>,
    projection: Option<ProjectionWire>,
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
    let generic_runtime_supported = classifier_supported && auth.supports_generic_runtime();
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
        )?);
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
        authority,
        families,
    })
}

fn compile_family(
    path: &Path,
    family: FamilyWire,
    verified: &BTreeSet<(String, String, String)>,
    generic_runtime_supported: bool,
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
    if !family.path.starts_with('/') {
        return invalid(
            path,
            &format!("family {} path must start with /", family.id),
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
    let provider_contract_verified = verified.contains(&(
        family.id.clone(),
        match method {
            HttpMethod::Get => "GET".to_owned(),
            HttpMethod::Post => "POST".to_owned(),
        },
        family.path.clone(),
    ));
    Ok(CompiledFamily {
        authoritative: generic_runtime_supported && provider_contract_verified,
        projection_authoritative: provider_contract_verified
            && projection_class.can_be_authoritative(),
        id: nonempty(path, "family id", family.id)?,
        method,
        path: family.path,
        record_selector,
        id_field: nonempty(path, "family id_field", family.id_field)?,
        name_field: optional(family.name_field),
        static_query: family.static_query,
        pagination: compile_pagination(path, family.pagination)?,
        projection: Projection {
            class: projection_class,
            template,
            fields: projection.fields,
            static_fields: projection.static_fields,
        },
    })
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
        .map(|family| {
            (
                family.id.clone(),
                if family.method.is_empty() {
                    "GET".to_owned()
                } else {
                    family.method.clone()
                },
                family.path.clone(),
            )
        })
        .collect()
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
        assert_eq!(summary.families, 3_891);
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
            catalog.get("box").unwrap().authority(),
            CollectionAuthority::Authoritative
        );
        assert_eq!(
            catalog.get("aws_bedrock").unwrap().authority(),
            CollectionAuthority::Authoritative
        );
        assert_eq!(
            catalog.get("agiloft").unwrap().authority(),
            CollectionAuthority::ShadowOnly
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
}
