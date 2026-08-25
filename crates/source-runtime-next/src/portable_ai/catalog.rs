use std::{collections::BTreeMap, sync::LazyLock};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthOperation {
    Bearer,
    ApiKeyHeader,
    Basic,
    AwsSigV4,
}

impl AuthOperation {
    pub(super) const fn host_operation(self) -> &'static str {
        match self {
            Self::Bearer => "source.bearer",
            Self::ApiKeyHeader => "google.api_key_header",
            Self::Basic => "langfuse.basic",
            Self::AwsSigV4 => "aws.sigv4",
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
}

#[derive(Deserialize)]
struct FamilyWire {
    id: String,
    method: String,
    path: String,
    record_selector: String,
    id_field: String,
    #[serde(default)]
    name_field: String,
    event: EventWire,
    projection: ProjectionWire,
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

const EMBEDDED: [EmbeddedSource; 10] = [
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/aws_bedrock.yaml"
        ),
        catalog: include_bytes!("../../../../sources/aws_bedrock/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/azure_openai.yaml"
        ),
        catalog: include_bytes!("../../../../sources/azure_openai/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/cohere.yaml"
        ),
        catalog: include_bytes!("../../../../sources/cohere/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/google_gemini.yaml"
        ),
        catalog: include_bytes!("../../../../sources/google_gemini/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/google_vertex_ai.yaml"
        ),
        catalog: include_bytes!("../../../../sources/google_vertex_ai/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/groq.yaml"
        ),
        catalog: include_bytes!("../../../../sources/groq/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/huggingface.yaml"
        ),
        catalog: include_bytes!("../../../../sources/huggingface/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/langfuse.yaml"
        ),
        catalog: include_bytes!("../../../../sources/langfuse/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/mistral.yaml"
        ),
        catalog: include_bytes!("../../../../sources/mistral/catalog.yaml"),
    },
    EmbeddedSource {
        definition: include_bytes!(
            "../../../../internal/connectorcatalog/catalog/ai-governance/perplexity.yaml"
        ),
        catalog: include_bytes!("../../../../sources/perplexity/catalog.yaml"),
    },
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
    let auth = match definition.auth.model.as_str() {
        "bearer_token" => AuthOperation::Bearer,
        "api_key" if definition.source_id == "google_gemini" => AuthOperation::ApiKeyHeader,
        "basic" if definition.source_id == "langfuse" => AuthOperation::Basic,
        "aws_sigv4" if definition.source_id == "aws_bedrock" => AuthOperation::AwsSigV4,
        other => return Err(format!("unsupported {} auth {other}", definition.source_id)),
    };
    let families = definition
        .resource_families
        .into_iter()
        .map(|family| {
            if family.method != "GET" {
                return Err(format!("{}.{} is not GET", definition.source_id, family.id));
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
                record_selector: family.record_selector,
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
