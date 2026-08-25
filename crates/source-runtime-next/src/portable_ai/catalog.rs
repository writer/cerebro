use std::{collections::BTreeMap, sync::LazyLock};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthOperation {
    Bearer,
    ApiKeyHeader,
    Basic,
    AwsSigV4,
    ElevenLabsApiKey,
    LangSmith,
    MicrosoftFoundryApiKey,
    PineconeApiKey,
    QdrantApiKey,
}

impl AuthOperation {
    pub(super) const fn host_operation(self) -> &'static str {
        match self {
            Self::Bearer => "source.bearer",
            Self::ApiKeyHeader => "google.api_key_header",
            Self::Basic => "langfuse.basic",
            Self::AwsSigV4 => "aws.sigv4",
            Self::ElevenLabsApiKey => "elevenlabs.xi_api_key",
            Self::LangSmith => "langsmith.x_api_key",
            Self::MicrosoftFoundryApiKey => "microsoft_foundry.api_key",
            Self::PineconeApiKey => "pinecone.api_key",
            Self::QdrantApiKey => "qdrant.api_key",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Pagination {
    None,
    Cursor {
        parameter: String,
        json_path: String,
        page_size_parameter: Option<String>,
        page_size: usize,
        in_json_body: bool,
    },
    NextUrl {
        json_path: String,
    },
    Link {
        header: String,
        page_size_parameter: Option<String>,
        page_size: usize,
    },
    Page {
        parameter: String,
        start_page: usize,
        page_size_parameter: Option<String>,
        page_size: usize,
    },
    Offset {
        parameter: String,
        start: usize,
        page_size_parameter: String,
        page_size: usize,
        inject_first: bool,
    },
}

#[derive(Debug)]
pub(super) struct Family {
    pub(super) id: String,
    pub(super) kernel: String,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) record_selector: String,
    pub(super) id_paths: Vec<String>,
    pub(super) name_paths: Vec<String>,
    pub(super) kind: String,
    pub(super) schema_ref: String,
    pub(super) urn_kind: String,
    pub(super) required_attributes: Vec<String>,
    pub(super) required_payload_fields: Vec<String>,
    pub(super) projection_fields: BTreeMap<String, Vec<String>>,
    pub(super) static_attributes: BTreeMap<String, String>,
    pub(super) config_attributes: BTreeMap<String, String>,
    pub(super) static_headers: BTreeMap<String, String>,
    pub(super) config_headers: BTreeMap<String, String>,
    pub(super) static_json_body: BTreeMap<String, serde_json::Value>,
    pub(super) config_json_body: BTreeMap<String, String>,
    pub(super) config_query: BTreeMap<String, String>,
    pub(super) static_query: BTreeMap<String, String>,
    pub(super) pagination: Pagination,
}

#[derive(Debug)]
pub(super) struct Source {
    pub(super) id: String,
    pub(super) origin_template: String,
    pub(super) auth: AuthOperation,
    pub(super) required_config: Vec<String>,
    pub(super) allowed_config: Vec<String>,
    pub(super) static_headers: BTreeMap<String, String>,
    pub(super) families: Vec<&'static Family>,
}

#[derive(Deserialize)]
struct DefinitionCatalog {
    entries: Vec<DefinitionEntry>,
}

#[derive(Deserialize)]
struct DefinitionEntry {
    definition: DefinitionWire,
}

#[derive(Deserialize)]
struct DefinitionWire {
    source_id: String,
    auth: AuthWire,
    #[serde(default)]
    config_fields: Vec<ConfigFieldWire>,
    transport: TransportWire,
    resource_families: Vec<FamilyWire>,
}

#[derive(Deserialize)]
struct AuthWire {
    model: String,
}

#[derive(Deserialize)]
struct ConfigFieldWire {
    key: String,
    #[serde(default)]
    required: bool,
}

#[derive(Deserialize)]
struct TransportWire {
    base_url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct FamilyWire {
    id: String,
    method: String,
    path: String,
    #[serde(default)]
    record_selector: String,
    id_field: String,
    #[serde(default)]
    name_field: String,
    event: EventWire,
    projection: ProjectionWire,
    #[serde(default)]
    static_headers: BTreeMap<String, String>,
    #[serde(default)]
    read: ReadWire,
    #[serde(default)]
    config: FamilyConfigWire,
    #[serde(default)]
    config_query: BTreeMap<String, String>,
    #[serde(default)]
    static_query: BTreeMap<String, String>,
    #[serde(default)]
    pagination: PaginationWire,
}

#[derive(Deserialize)]
struct EventWire {
    kind: String,
    schema_ref: String,
    urn_kind: String,
    #[serde(default)]
    required_payload_fields: Vec<String>,
}

#[derive(Deserialize)]
struct ProjectionWire {
    #[serde(default)]
    fields: BTreeMap<String, String>,
    #[serde(default)]
    static_fields: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
struct FamilyConfigWire {
    #[serde(default)]
    config_query: BTreeMap<String, String>,
    #[serde(default)]
    config_attributes: BTreeMap<String, String>,
    #[serde(default)]
    config_headers: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
struct ReadWire {
    #[serde(default)]
    static_json_body: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    config_json_body: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
struct PaginationWire {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    cursor_param: String,
    #[serde(default)]
    cursor_json_path: String,
    #[serde(default, alias = "next_link_json_path")]
    next_url_json_path: String,
    #[serde(default)]
    link_header: String,
    #[serde(default)]
    page_size_param: String,
    #[serde(default)]
    page_size: usize,
    #[serde(default)]
    page_param: String,
    #[serde(default)]
    start_page: usize,
    #[serde(default)]
    offset_param: String,
    #[serde(default)]
    limit_param: String,
    #[serde(default)]
    inject_first_page: bool,
    #[serde(default)]
    cursor_in_json_body: bool,
}

#[derive(Deserialize)]
struct SourceCatalog {
    event_contracts: Vec<EventContractWire>,
}

#[derive(Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    #[serde(default)]
    required_attributes: Vec<String>,
    #[serde(default)]
    required_payload_fields: Vec<String>,
}

struct EmbeddedSource {
    definition: &'static [u8],
    catalog: &'static [u8],
}

macro_rules! embedded_source {
    ($id:literal) => {
        EmbeddedSource {
            definition: include_bytes!(concat!(
                "../../../../internal/connectorcatalog/catalog/ai-governance/",
                $id,
                ".yaml"
            )),
            catalog: include_bytes!(concat!("../../../../sources/", $id, "/catalog.yaml")),
        }
    };
}

const EMBEDDED: [EmbeddedSource; 25] = [
    embedded_source!("aws_bedrock"),
    embedded_source!("azure_openai"),
    embedded_source!("cerebras"),
    embedded_source!("cloudflare_workers_ai"),
    embedded_source!("cohere"),
    embedded_source!("elevenlabs"),
    embedded_source!("fireworks_ai"),
    embedded_source!("google_gemini"),
    embedded_source!("google_vertex_ai"),
    embedded_source!("groq"),
    embedded_source!("huggingface"),
    embedded_source!("ibm_watsonx_ai"),
    embedded_source!("langchain"),
    embedded_source!("langfuse"),
    embedded_source!("microsoft_foundry"),
    embedded_source!("mistral"),
    embedded_source!("openrouter"),
    embedded_source!("perplexity"),
    embedded_source!("pinecone"),
    embedded_source!("qdrant_cloud"),
    embedded_source!("replicate"),
    embedded_source!("stability_ai"),
    embedded_source!("together_ai"),
    embedded_source!("writer"),
    embedded_source!("xai"),
];

pub(super) static SOURCES: LazyLock<Vec<&'static Source>> = LazyLock::new(|| {
    EMBEDDED
        .iter()
        .map(compile_source)
        .collect::<Result<Vec<_>, _>>()
        .expect("checked-in portable AI source catalogs must compile")
});

fn compile_source(embedded: &EmbeddedSource) -> Result<&'static Source, String> {
    let mut definitions: DefinitionCatalog = serde_saphyr::from_slice(embedded.definition)
        .map_err(|error| format!("definition YAML: {error}"))?;
    if definitions.entries.len() != 1 {
        return Err("definition catalog must contain one source".to_owned());
    }
    let definition = definitions.entries.remove(0).definition;
    let source_catalog: SourceCatalog = serde_saphyr::from_slice(embedded.catalog)
        .map_err(|error| format!("source catalog YAML: {error}"))?;
    let contracts = source_catalog
        .event_contracts
        .into_iter()
        .map(|contract| (contract.kind.clone(), contract))
        .collect::<BTreeMap<_, _>>();
    let auth = match (
        definition.source_id.as_str(),
        definition.auth.model.as_str(),
    ) {
        (_, "bearer_token") => AuthOperation::Bearer,
        ("google_gemini", "api_key") => AuthOperation::ApiKeyHeader,
        ("elevenlabs", "api_key") => AuthOperation::ElevenLabsApiKey,
        ("langchain", "api_key") => AuthOperation::LangSmith,
        ("langfuse", "basic") => AuthOperation::Basic,
        ("microsoft_foundry", "api_key") => AuthOperation::MicrosoftFoundryApiKey,
        ("pinecone", "api_key") => AuthOperation::PineconeApiKey,
        ("qdrant_cloud", "api_key") => AuthOperation::QdrantApiKey,
        ("aws_bedrock", "aws_sigv4") => AuthOperation::AwsSigV4,
        (_, other) => return Err(format!("unsupported {} auth {other}", definition.source_id)),
    };
    let families = definition
        .resource_families
        .into_iter()
        .map(|family| {
            if family.method != "GET" && family.method != "POST" {
                return Err(format!(
                    "{}.{} uses unsupported method {}",
                    definition.source_id, family.id, family.method
                ));
            }
            let contract = contracts
                .get(&family.event.kind)
                .ok_or_else(|| format!("{} contract is missing", family.event.kind))?;
            if contract.schema_ref != family.event.schema_ref
                || contract.required_payload_fields.iter().any(|required| {
                    !family.event.required_payload_fields.iter().any(|declared| {
                        declared
                            .split('|')
                            .map(str::trim)
                            .any(|candidate| candidate == required)
                    })
                })
            {
                return Err(format!("{} event contracts drifted", family.event.kind));
            }
            let projection_fields = family
                .projection
                .fields
                .into_iter()
                .map(|(key, paths)| {
                    (
                        key,
                        paths
                            .split('|')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    )
                })
                .collect();
            let mut config_query = family.config_query;
            config_query.extend(family.config.config_query);
            let compiled = Family {
                kernel: format!("{}.{}", definition.source_id, family.id),
                id: family.id,
                method: family.method,
                path: family.path,
                record_selector: if family.record_selector.is_empty() {
                    "$".to_owned()
                } else {
                    family.record_selector
                },
                id_paths: split_paths(&family.id_field),
                name_paths: split_paths(&family.name_field),
                kind: family.event.kind,
                schema_ref: family.event.schema_ref,
                urn_kind: family.event.urn_kind,
                required_attributes: contract.required_attributes.clone(),
                required_payload_fields: family.event.required_payload_fields,
                projection_fields,
                static_attributes: family.projection.static_fields,
                config_attributes: family.config.config_attributes,
                static_headers: family.static_headers,
                config_headers: family.config.config_headers,
                static_json_body: family.read.static_json_body,
                config_json_body: family.read.config_json_body,
                config_query,
                static_query: family.static_query,
                pagination: compile_pagination(family.pagination)?,
            };
            Ok::<_, String>(&*Box::leak(Box::new(compiled)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if families.is_empty() {
        return Err(format!("{} has no runtime families", definition.source_id));
    }
    let required_config = definition
        .config_fields
        .iter()
        .filter(|field| field.required)
        .map(|field| field.key.clone())
        .collect();
    let allowed_config = definition
        .config_fields
        .iter()
        .map(|field| field.key.clone())
        .collect();
    Ok(&*Box::leak(Box::new(Source {
        id: definition.source_id,
        origin_template: definition.transport.base_url,
        auth,
        required_config,
        allowed_config,
        static_headers: definition.transport.headers,
        families,
    })))
}

fn compile_pagination(wire: PaginationWire) -> Result<Pagination, String> {
    match wire.kind.as_str() {
        "" | "none" => Ok(Pagination::None),
        "cursor" if !wire.cursor_param.is_empty() && !wire.cursor_json_path.is_empty() => {
            Ok(Pagination::Cursor {
                parameter: wire.cursor_param,
                json_path: wire.cursor_json_path,
                page_size_parameter: (!wire.page_size_param.is_empty())
                    .then_some(wire.page_size_param),
                page_size: wire.page_size,
                in_json_body: wire.cursor_in_json_body,
            })
        }
        "next_url" if !wire.next_url_json_path.is_empty() => Ok(Pagination::NextUrl {
            json_path: wire.next_url_json_path,
        }),
        "link" => Ok(Pagination::Link {
            header: if wire.link_header.is_empty() {
                "Link".to_owned()
            } else {
                wire.link_header
            },
            page_size_parameter: (!wire.page_size_param.is_empty()).then_some(wire.page_size_param),
            page_size: wire.page_size,
        }),
        "page" if !wire.page_param.is_empty() => Ok(Pagination::Page {
            parameter: wire.page_param,
            start_page: wire.start_page.max(1),
            page_size_parameter: (!wire.page_size_param.is_empty()).then_some(wire.page_size_param),
            page_size: wire.page_size,
        }),
        "offset" if !wire.offset_param.is_empty() && !wire.limit_param.is_empty() => {
            Ok(Pagination::Offset {
                parameter: wire.offset_param,
                start: wire.start_page,
                page_size_parameter: wire.limit_param,
                page_size: wire.page_size,
                inject_first: wire.inject_first_page,
            })
        }
        other => Err(format!("unsupported pagination {other}")),
    }
}

fn split_paths(value: &str) -> Vec<String> {
    value
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}
