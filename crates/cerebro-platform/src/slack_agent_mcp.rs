use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};

use cerebro_agent_runtime::{
    AgentRuntimeError, AgentTurnRequest, EvidenceRecord, ToolAuthorityClass, ToolCall,
    ToolDescriptor, ToolEffectClass, ToolResult, ToolResultState,
    session::{SemanticEvidenceAtomization, SemanticEvidenceEnvelope, semantic_evidence_atoms},
};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    Client, Url,
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const MCP_URL_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_URL";
const MCP_TOKEN_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_BEARER_TOKEN";
const MCP_SELECTION_SIGNING_KEY_ENV: &str = "CEREBRO_SLACK_AGENT_CAPABILITY_SIGNING_KEY";
const MCP_TOOLSETS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_TOOLSETS";
const MCP_OBSERVE_TOOLS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_OBSERVE_TOOLS";
const MCP_PROPOSE_TOOLS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_PROPOSE_TOOLS";
const MCP_ACTUATE_TOOLS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_ACTUATE_TOOLS";
const MCP_USER_AGENT: &str = concat!("cerebro-platform/", env!("CARGO_PKG_VERSION"));
const MAX_MCP_TOOLS: usize = 256;
const MAX_SCHEMA_BYTES: usize = 8 * 1024;
const MAX_MCP_RESPONSE_BYTES: usize = 1024 * 1024;
const SEMANTIC_EVIDENCE_META_KEY: &str = "cerebro.semantic_evidence";
const CAPABILITY_SELECTION_PREFIX: &str = "capability-selection-v1";

pub struct McpAgentTools {
    client: Client,
    endpoint: Url,
    bearer_token: String,
    selection_signing_key: String,
    toolsets: String,
    descriptors: Vec<ToolDescriptor>,
    tools: BTreeMap<String, BoundMcpTool>,
}

#[derive(Clone)]
struct BoundMcpTool {
    mcp_name: String,
    descriptor: ToolDescriptor,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct McpToolWire {
    name: String,
    #[serde(default)]
    title: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(default)]
    annotations: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct McpToolsListResult {
    tools: Vec<McpToolWire>,
    #[serde(default, rename = "nextCursor")]
    next_cursor: Option<String>,
}

impl McpAgentTools {
    pub fn is_configured() -> bool {
        env::var(MCP_URL_ENV).is_ok_and(|value| !value.trim().is_empty())
    }

    pub fn authority_policy_configured() -> bool {
        [
            MCP_OBSERVE_TOOLS_ENV,
            MCP_PROPOSE_TOOLS_ENV,
            MCP_ACTUATE_TOOLS_ENV,
        ]
        .iter()
        .any(|name| env::var(name).is_ok_and(|value| !value.trim().is_empty()))
    }

    pub async fn from_env(tenant_id: &str) -> Result<Option<Self>, String> {
        let raw_url = env::var(MCP_URL_ENV).unwrap_or_default();
        if raw_url.trim().is_empty() {
            return Ok(None);
        }
        let endpoint = validated_endpoint(raw_url.trim())?;
        let bearer_token = required_env(MCP_TOKEN_ENV)?;
        let toolsets = env::var(MCP_TOOLSETS_ENV)
            .unwrap_or_else(|_| "task".into())
            .trim()
            .to_owned();
        if toolsets.is_empty() || toolsets.len() > 256 {
            return Err("MCP toolset selection is invalid".into());
        }
        let observe_tools = configured_tool_names(MCP_OBSERVE_TOOLS_ENV)?;
        let propose_tools = configured_tool_names(MCP_PROPOSE_TOOLS_ENV)?;
        let actuate_tools = configured_tool_names(MCP_ACTUATE_TOOLS_ENV)?;
        let authority_policy_configured =
            !observe_tools.is_empty() || !propose_tools.is_empty() || !actuate_tools.is_empty();
        let selection_signing_key = selection_signing_key(
            env::var(MCP_SELECTION_SIGNING_KEY_ENV).ok(),
            &bearer_token,
            authority_policy_configured,
        )?;
        if !observe_tools.is_disjoint(&propose_tools)
            || !observe_tools.is_disjoint(&actuate_tools)
            || !propose_tools.is_disjoint(&actuate_tools)
        {
            return Err("an MCP tool must have exactly one host-owned authority class".into());
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| error.to_string())?;
        let listed = list_tools(&client, &endpoint, &bearer_token, &toolsets, tenant_id).await?;
        if listed.len() > MAX_MCP_TOOLS {
            return Err("MCP tool catalog exceeds the bounded limit".into());
        }
        let listed_names = listed
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<BTreeSet<_>>();
        if observe_tools
            .iter()
            .chain(&propose_tools)
            .chain(&actuate_tools)
            .any(|name| !listed_names.contains(name.as_str()))
        {
            return Err("configured MCP authority policy names an unavailable tool".into());
        }
        let tools = bind_tools(listed, &observe_tools, &propose_tools, &actuate_tools)?;
        let descriptors = tools.values().map(|tool| tool.descriptor.clone()).collect();
        Ok(Some(Self {
            client,
            endpoint,
            bearer_token,
            selection_signing_key,
            toolsets,
            descriptors,
            tools,
        }))
    }

    pub fn descriptors(&self) -> &[ToolDescriptor] {
        &self.descriptors
    }

    pub fn descriptor(&self, tool_id: &str) -> Option<&ToolDescriptor> {
        self.tools.get(tool_id).map(|tool| &tool.descriptor)
    }

    pub fn issue_selection_ref(
        &self,
        request: &AgentTurnRequest,
        descriptor: &ToolDescriptor,
        query_digest: &str,
    ) -> Result<String, String> {
        if !self.tools.contains_key(&descriptor.tool_id) || !is_sha256_digest(query_digest) {
            return Err("capability selection target is invalid".into());
        }
        let actor_digest = hex_digest(&Sha256::digest(request.actor_ref.as_bytes()));
        let signature =
            self.selection_signature(request, descriptor, query_digest, &actor_digest)?;
        Ok(format!(
            "{CAPABILITY_SELECTION_PREFIX}:{}:{}:{actor_digest}:{signature}",
            descriptor.tool_id,
            query_digest.trim_start_matches("sha256:")
        ))
    }

    pub fn verify_selection_ref(
        &self,
        request: &AgentTurnRequest,
        selection_ref: &str,
    ) -> Result<ToolDescriptor, String> {
        let mut fields = selection_ref.split(':');
        if fields.next() != Some(CAPABILITY_SELECTION_PREFIX) {
            return Err("capability selection reference has an unsupported version".into());
        }
        let tool_id = fields
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "capability selection reference omitted its tool id".to_owned())?;
        let query_digest = fields
            .next()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(|value| format!("sha256:{value}"))
            .ok_or_else(|| {
                "capability selection reference has an invalid query digest".to_owned()
            })?;
        let actor_digest = fields
            .next()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| {
                "capability selection reference has an invalid actor scope".to_owned()
            })?;
        let signature = fields
            .next()
            .and_then(decode_hex)
            .filter(|value| value.len() == 32)
            .ok_or_else(|| "capability selection reference has an invalid signature".to_owned())?;
        if fields.next().is_some() {
            return Err("capability selection reference has unexpected fields".into());
        }
        let request_actor_digest = hex_digest(&Sha256::digest(request.actor_ref.as_bytes()));
        if request.actor_ref != "cerebro-scheduler" && request_actor_digest != actor_digest {
            return Err("capability selection reference belongs to another actor".into());
        }
        let descriptor = self
            .tools
            .get(tool_id)
            .map(|tool| tool.descriptor.clone())
            .ok_or_else(|| "capability selection target is no longer bound".to_owned())?;
        let mac = self.selection_mac(request, &descriptor, &query_digest, actor_digest)?;
        mac.verify_slice(&signature)
            .map_err(|_| "capability selection reference does not match this scope".to_owned())?;
        Ok(descriptor)
    }

    fn selection_signature(
        &self,
        request: &AgentTurnRequest,
        descriptor: &ToolDescriptor,
        query_digest: &str,
        actor_digest: &str,
    ) -> Result<String, String> {
        let mac = self.selection_mac(request, descriptor, query_digest, actor_digest)?;
        Ok(hex_digest(&mac.finalize().into_bytes()))
    }

    fn selection_mac(
        &self,
        request: &AgentTurnRequest,
        descriptor: &ToolDescriptor,
        query_digest: &str,
        actor_digest: &str,
    ) -> Result<Hmac<Sha256>, String> {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(self.selection_signing_key.as_bytes())
                .map_err(|_| "capability selection signer could not initialize".to_owned())?;
        for value in [
            CAPABILITY_SELECTION_PREFIX,
            request.tenant_id.as_str(),
            actor_digest,
            request.thread_ref.as_str(),
            request.context_scope_ref.as_deref().unwrap_or(""),
            descriptor.tool_id.as_str(),
            descriptor.title.as_str(),
            descriptor.summary.as_str(),
            authority_name(descriptor.authority_class),
            effect_name(descriptor.effect_class),
            descriptor.input_schema_ref.as_str(),
            descriptor.result_schema_ref.as_str(),
            query_digest,
        ] {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value.as_bytes());
        }
        Ok(mac)
    }

    pub async fn invoke(
        &self,
        request: &AgentTurnRequest,
        call: &ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let tool = self
            .tools
            .get(&call.tool_id)
            .ok_or_else(|| AgentRuntimeError::ToolUnavailable(call.tool_id.clone()))?;
        let response = match self
            .post(
                request,
                json!({
                    "jsonrpc": "2.0",
                    "id": call.call_id,
                    "method": "tools/call",
                    "params": {
                        "name": tool.mcp_name,
                        "arguments": &call.input,
                    },
                }),
            )
            .await
        {
            Ok(response) => response,
            Err(error) if tool.descriptor.authority_class == ToolAuthorityClass::Actuate => {
                return Err(error);
            }
            Err(_) => {
                return Ok(ToolResult {
                    state: ToolResultState::Failed,
                    summary: format!("MCP tool {} was unavailable.", tool.mcp_name),
                    data: json!({"error_kind": "capability_gateway_unavailable"}),
                    evidence: vec![],
                    blocker: Some(format!(
                        "The {} capability gateway could not complete this call.",
                        tool.descriptor.title
                    )),
                });
            }
        };
        if let Some(error) = response.error {
            if tool.descriptor.authority_class == ToolAuthorityClass::Actuate {
                return Err(AgentRuntimeError::ModelUnavailable(format!(
                    "MCP actuation {} returned an ambiguous error",
                    tool.mcp_name
                )));
            }
            return Ok(ToolResult {
                state: ToolResultState::Failed,
                summary: format!("MCP tool {} failed.", tool.mcp_name),
                data: json!({
                    "error_code": error.code,
                    "error_message": bounded_error(&error.message),
                }),
                evidence: vec![],
                blocker: Some(format!(
                    "The {} capability returned an MCP error.",
                    tool.descriptor.title
                )),
            });
        }
        let result = response.result.ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall("MCP tool response omitted its result".into())
        })?;
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let semantic_envelope = semantic_evidence_envelope(&result)?;
        let data = result
            .get("structuredContent")
            .cloned()
            .unwrap_or_else(|| result.clone());
        let normalized = normalize_tool_result(data, is_error);
        if tool.descriptor.authority_class == ToolAuthorityClass::Actuate
            && normalized.state != ToolResultState::Succeeded
        {
            return Err(AgentRuntimeError::ModelUnavailable(format!(
                "MCP actuation {} did not return a verified success result",
                tool.mcp_name
            )));
        }
        let state = normalized.state;
        let data = normalized.data;
        let complete = state == ToolResultState::Succeeded;
        let evidence = if state == ToolResultState::Failed {
            vec![]
        } else {
            vec![mcp_evidence(
                request,
                call,
                &tool.mcp_name,
                &data,
                complete,
                semantic_envelope.as_ref(),
            )?]
        };
        Ok(ToolResult {
            state,
            summary: format!(
                "MCP tool {} returned {}.",
                tool.mcp_name,
                match state {
                    ToolResultState::Succeeded => "a complete result",
                    ToolResultState::Partial => "a partial result",
                    ToolResultState::Failed => "a blocked result",
                    ToolResultState::OutcomeUnknown => "an unknown outcome",
                }
            ),
            data,
            evidence,
            blocker: normalized.blocker.or_else(|| {
                (state != ToolResultState::Succeeded).then(|| {
                    format!(
                        "The {} capability did not return a complete result.",
                        tool.descriptor.title
                    )
                })
            }),
        })
    }

    async fn post(
        &self,
        request: &AgentTurnRequest,
        body: Value,
    ) -> Result<JsonRpcResponse, AgentRuntimeError> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json, text/event-stream")
            .header(USER_AGENT, MCP_USER_AGENT)
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer_token))
            .header("MCP-Protocol-Version", "2025-03-26")
            .header("X-Cerebro-MCP-Toolsets", &self.toolsets)
            .header("X-Cerebro-Tenant", &request.tenant_id)
            .json(&body)
            .send()
            .await
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(AgentRuntimeError::ModelUnavailable(format!(
                "MCP gateway returned status {}",
                response.status()
            )));
        }
        bounded_json(response)
            .await
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))
    }
}

struct NormalizedToolResult {
    state: ToolResultState,
    data: Value,
    blocker: Option<String>,
}

fn normalize_tool_result(data: Value, is_error: bool) -> NormalizedToolResult {
    let declared_state = data.get("state").and_then(Value::as_str);
    let state = if is_error || declared_state == Some("blocked") {
        ToolResultState::Failed
    } else if declared_state == Some("partial") {
        ToolResultState::Partial
    } else {
        ToolResultState::Succeeded
    };
    NormalizedToolResult {
        state,
        data,
        blocker: None,
    }
}

fn bind_tools(
    listed: Vec<McpToolWire>,
    observe_tools: &BTreeSet<String>,
    propose_tools: &BTreeSet<String>,
    actuate_tools: &BTreeSet<String>,
) -> Result<BTreeMap<String, BoundMcpTool>, String> {
    let mut tools = BTreeMap::new();
    for tool in listed {
        if tool.name.is_empty()
            || tool.name.len() > 256
            || !tool.name.bytes().all(valid_tool_name_byte)
        {
            return Err("MCP tool catalog contains an invalid tool name".into());
        }
        // The Rust Slack loop owns reasoning. Binding this tool would create a
        // second model loop in the Go MCP service and bypass Rust's session plan.
        if tool.name == "cerebro.graph.reason" {
            continue;
        }
        let read_only = annotation_bool(&tool.annotations, "readOnlyHint");
        let (authority_class, effect_class) = if actuate_tools.contains(&tool.name) {
            if read_only {
                return Err(format!(
                    "read-only MCP tool {} cannot be configured as actuate",
                    tool.name
                ));
            }
            (ToolAuthorityClass::Actuate, ToolEffectClass::ExternalEffect)
        } else if propose_tools.contains(&tool.name) {
            if !read_only {
                return Err(format!(
                    "write-capable MCP tool {} cannot be configured as propose",
                    tool.name
                ));
            }
            (ToolAuthorityClass::Propose, ToolEffectClass::Read)
        } else if observe_tools.contains(&tool.name) {
            if !read_only {
                return Err(format!(
                    "write-capable MCP tool {} cannot be configured as observe",
                    tool.name
                ));
            }
            (ToolAuthorityClass::Observe, ToolEffectClass::Read)
        } else {
            continue;
        };
        let tool_id = format!("mcp.{}", tool.name);
        let schema =
            serde_json::to_string(&tool.input_schema).map_err(|error| error.to_string())?;
        if schema.len() > MAX_SCHEMA_BYTES {
            return Err(format!("MCP tool {} input schema is too large", tool.name));
        }
        let descriptor = ToolDescriptor {
            tool_id: tool_id.clone(),
            title: nonempty(&tool.title, &tool.name),
            summary: format!("{} Input JSON Schema: {schema}", tool.description.trim()),
            authority_class,
            effect_class,
            input_schema_ref: format!("mcp://{}/input", tool.name),
            result_schema_ref: format!("mcp://{}/output", tool.name),
        };
        if tools
            .insert(
                tool_id,
                BoundMcpTool {
                    mcp_name: tool.name,
                    descriptor,
                },
            )
            .is_some()
        {
            return Err("MCP tool catalog repeats a tool id".into());
        }
    }
    Ok(tools)
}

async fn list_tools(
    client: &Client,
    endpoint: &Url,
    bearer_token: &str,
    toolsets: &str,
    tenant_id: &str,
) -> Result<Vec<McpToolWire>, String> {
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    let mut listed = Vec::new();
    loop {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
        let response = client
            .post(endpoint.clone())
            .header(ACCEPT, "application/json, text/event-stream")
            .header(USER_AGENT, MCP_USER_AGENT)
            .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
            .header("MCP-Protocol-Version", "2025-03-26")
            .header("X-Cerebro-MCP-Toolsets", toolsets)
            .header("X-Cerebro-Tenant", tenant_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": format!("slack-agent-tools-list-{}", listed.len()),
                "method": "tools/list",
                "params": params,
            }))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "MCP tools/list returned status {}",
                response.status()
            ));
        }
        let response = bounded_json::<JsonRpcResponse>(response).await?;
        if let Some(error) = response.error {
            return Err(format!(
                "MCP tools/list returned error {}: {}",
                error.code,
                bounded_error(&error.message)
            ));
        }
        let page = parse_listed_tools(
            response
                .result
                .ok_or_else(|| "MCP tools/list omitted its result".to_owned())?,
        )?;
        listed.extend(page.tools);
        if listed.len() > MAX_MCP_TOOLS {
            return Err("MCP tool catalog exceeds the bounded limit".into());
        }
        let Some(next_cursor) = page.next_cursor else {
            return Ok(listed);
        };
        if next_cursor.is_empty()
            || next_cursor.len() > 1024
            || !seen_cursors.insert(next_cursor.clone())
        {
            return Err("MCP tools/list returned an invalid pagination cursor".into());
        }
        cursor = Some(next_cursor);
    }
}

fn parse_listed_tools(result: Value) -> Result<McpToolsListResult, String> {
    serde_json::from_value(result).map_err(|error| error.to_string())
}

async fn bounded_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MCP_RESPONSE_BYTES as u64)
    {
        return Err("MCP response exceeds the bounded limit".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len().saturating_add(chunk.len()) > MAX_MCP_RESPONSE_BYTES {
            return Err("MCP response exceeds the bounded limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

fn mcp_evidence(
    request: &AgentTurnRequest,
    call: &ToolCall,
    tool_name: &str,
    data: &Value,
    complete: bool,
    semantic_envelope: Option<&SemanticEvidenceEnvelope>,
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let fresh_until = observed_at
        .checked_add(Duration::minutes(5))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
    let response_bytes = if let Some(semantic_envelope) = semantic_envelope {
        serde_json::to_vec(&json!({
            "data": data,
            "semantic_evidence": semantic_envelope,
        }))
    } else {
        serde_json::to_vec(data)
    }
    .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let response_digest = hex_digest(&Sha256::digest(response_bytes));
    let identity = format!(
        "{}:{}:{}:{}:{response_digest}",
        request.tenant_id,
        request.request_id,
        call.call_id,
        call.input_digest()
    );
    let digest = hex_digest(&Sha256::digest(identity.as_bytes()));
    let observed_at = observed_at
        .format(&Rfc3339)
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let fresh_until = fresh_until
        .format(&Rfc3339)
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let mut evidence = EvidenceRecord {
        evidence_ref: format!("evidence://mcp/{tool_name}/{digest}"),
        statement: format!(
            "The tenant-scoped MCP tool {tool_name} returned this bounded result; complete={complete}; response_digest=sha256:{response_digest}."
        ),
        observed_at,
        fresh_until: Some(fresh_until),
        complete,
        atoms: Vec::new(),
    };
    if let Some(envelope) = semantic_envelope {
        evidence.atoms = semantic_evidence_atoms(SemanticEvidenceAtomization {
            evidence_ref: &evidence.evidence_ref,
            envelope: envelope.clone(),
            observed_at: &evidence.observed_at,
            fresh_until: evidence.fresh_until.as_deref(),
            complete,
        })?;
    }
    Ok(evidence)
}

fn semantic_evidence_envelope(
    result: &Value,
) -> Result<Option<SemanticEvidenceEnvelope>, AgentRuntimeError> {
    let Some(value) = result
        .get("_meta")
        .and_then(|meta| meta.get(SEMANTIC_EVIDENCE_META_KEY))
    else {
        return Ok(None);
    };
    let envelope: SemanticEvidenceEnvelope =
        serde_json::from_value(value.clone()).map_err(|error| {
            AgentRuntimeError::InvalidToolCall(format!(
                "MCP semantic evidence envelope is invalid: {error}"
            ))
        })?;
    let canonical = serde_json::to_value(&envelope).map_err(|error| {
        AgentRuntimeError::InvalidToolCall(format!(
            "MCP semantic evidence envelope is invalid: {error}"
        ))
    })?;
    if canonical != *value {
        return Err(AgentRuntimeError::InvalidToolCall(
            "MCP semantic evidence envelope contains unknown or non-canonical fields".into(),
        ));
    }
    Ok(Some(envelope))
}

fn configured_tool_names(name: &str) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for value in env::var(name).unwrap_or_default().split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value.len() > 256 || !value.bytes().all(valid_tool_name_byte) {
            return Err(format!("{name} contains an invalid tool name"));
        }
        names.insert(value.to_owned());
    }
    Ok(names)
}

fn valid_tool_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn authority_name(authority: ToolAuthorityClass) -> &'static str {
    match authority {
        ToolAuthorityClass::Observe => "observe",
        ToolAuthorityClass::Propose => "propose",
        ToolAuthorityClass::Actuate => "actuate",
    }
}

fn effect_name(effect: ToolEffectClass) -> &'static str {
    match effect {
        ToolEffectClass::Read => "read",
        ToolEffectClass::Write => "write",
        ToolEffectClass::ExternalEffect => "external_effect",
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn annotation_bool(annotations: &BTreeMap<String, Value>, key: &str) -> bool {
    annotations
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn validated_endpoint(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    let secure = url.scheme() == "https";
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (!secure && !loopback) || !url.username().is_empty() || url.password().is_some() {
        return Err("MCP URL must use HTTPS or loopback and cannot contain credentials".into());
    }
    Ok(url)
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(value.to_owned())
}

fn selection_signing_key(
    configured: Option<String>,
    bearer_token: &str,
    required: bool,
) -> Result<String, String> {
    let key = configured.unwrap_or_default().trim().to_owned();
    if key.is_empty() && !required {
        return Ok(key);
    }
    if key.len() < 32 || key == bearer_token {
        return Err("capability signing key must be distinct and at least 32 bytes".into());
    }
    Ok(key)
}

fn nonempty(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn bounded_error(value: &str) -> String {
    value.trim().chars().take(512).collect()
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, http::StatusCode, routing::post};
    use cerebro_agent_runtime::session::{
        AGENT_SEMANTIC_EVIDENCE_V1, AuthorityBindingState, AuthorityDuty, EvidenceAssertion,
        SemanticEvidenceAssertion,
    };

    #[test]
    fn parses_and_receipt_binds_versioned_semantic_evidence_metadata() {
        let result = json!({
            "structuredContent": {"owner_present": true},
            "_meta": {
                (SEMANTIC_EVIDENCE_META_KEY): {
                    "schema_version": AGENT_SEMANTIC_EVIDENCE_V1,
                    "assertions": [{
                        "kind": "authority_binding",
                        "subject_ref": "finding:one",
                        "duty": "remediation",
                        "state": {"state": "present_identity_not_returned"}
                    }]
                }
            }
        });
        let envelope = semantic_evidence_envelope(&result).unwrap().unwrap();
        let request = turn_request();
        let call = ToolCall {
            call_id: "semantic-call".into(),
            tool_id: "mcp.cerebro.finding.read".into(),
            purpose: "Read the finding authority.".into(),
            input: json!({"subject_ref": "finding:one"}),
        };
        let evidence = mcp_evidence(
            &request,
            &call,
            "cerebro.finding.read",
            &result["structuredContent"],
            true,
            Some(&envelope),
        )
        .unwrap();

        assert_eq!(evidence.atoms.len(), 1);
        assert_eq!(
            evidence.atoms[0].subject_ref.as_deref(),
            Some("finding:one")
        );
        assert!(matches!(
            &evidence.atoms[0].assertion,
            EvidenceAssertion::Semantic {
                assertion: SemanticEvidenceAssertion::AuthorityBinding {
                    duty: AuthorityDuty::Remediation,
                    state: AuthorityBindingState::PresentIdentityNotReturned,
                    ..
                }
            }
        ));
    }

    #[test]
    fn preserves_pre_semantic_mcp_response_digests() {
        let request = turn_request();
        let call = ToolCall {
            call_id: "legacy-digest-call".into(),
            tool_id: "mcp.cerebro.finding.read".into(),
            purpose: "Read the finding.".into(),
            input: json!({"subject_ref": "finding:one"}),
        };
        let data = json!({"owner_present": false});
        let expected_digest = hex_digest(&Sha256::digest(serde_json::to_vec(&data).unwrap()));

        let evidence =
            mcp_evidence(&request, &call, "cerebro.finding.read", &data, true, None).unwrap();

        assert!(
            evidence
                .statement
                .contains(&format!("response_digest=sha256:{expected_digest}"))
        );
    }

    #[test]
    fn rejects_malformed_or_unsupported_semantic_evidence_metadata() {
        let malformed = json!({
            "_meta": {
                (SEMANTIC_EVIDENCE_META_KEY): {
                    "schema_version": AGENT_SEMANTIC_EVIDENCE_V1,
                    "assertions": [],
                    "unexpected": true
                }
            }
        });
        assert!(semantic_evidence_envelope(&malformed).is_err());

        let malformed_assertion = json!({
            "_meta": {
                (SEMANTIC_EVIDENCE_META_KEY): {
                    "schema_version": AGENT_SEMANTIC_EVIDENCE_V1,
                    "assertions": [{
                        "kind": "authority_binding",
                        "subject_ref": "finding:one",
                        "duty": "remediation",
                        "state": {
                            "state": "not_observed",
                            "unexpected": true
                        }
                    }]
                }
            }
        });
        assert!(semantic_evidence_envelope(&malformed_assertion).is_err());

        let unsupported = SemanticEvidenceEnvelope {
            schema_version: "agent-semantic-evidence/v2".into(),
            assertions: vec![SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref: "finding:one".into(),
                duty: AuthorityDuty::Remediation,
                state: AuthorityBindingState::NotObserved,
            }],
        };
        let request = turn_request();
        let call = ToolCall {
            call_id: "unsupported-semantic-call".into(),
            tool_id: "mcp.cerebro.finding.read".into(),
            purpose: "Read the finding authority.".into(),
            input: json!({"subject_ref": "finding:one"}),
        };
        assert!(
            mcp_evidence(
                &request,
                &call,
                "cerebro.finding.read",
                &json!({"owner_present": false}),
                true,
                Some(&unsupported),
            )
            .is_err()
        );
    }

    #[test]
    fn binds_read_tools_and_omits_unapproved_write_tools() {
        let tools = bind_tools(
            vec![tool("cerebro.read", true), tool("cerebro.write", false)],
            &BTreeSet::from(["cerebro.read".into()]),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();

        assert_eq!(tools.len(), 1);
        assert_eq!(
            tools["mcp.cerebro.read"].descriptor.authority_class,
            ToolAuthorityClass::Observe
        );
        assert!(!tools.contains_key("mcp.cerebro.write"));
    }

    #[test]
    fn provider_read_only_annotations_cannot_grant_observe_authority() {
        let tools = bind_tools(
            vec![tool("cerebro.read", true)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(tools.is_empty());

        let result = bind_tools(
            vec![tool("cerebro.write", false)],
            &BTreeSet::from(["cerebro.write".into()]),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn explicit_policy_separates_proposals_from_exact_approval_effects() {
        let tools = bind_tools(
            vec![tool("cerebro.plan", true), tool("cerebro.apply", false)],
            &BTreeSet::new(),
            &BTreeSet::from(["cerebro.plan".into()]),
            &BTreeSet::from(["cerebro.apply".into()]),
        )
        .unwrap();

        assert_eq!(
            tools["mcp.cerebro.plan"].descriptor.authority_class,
            ToolAuthorityClass::Propose
        );
        assert_eq!(
            tools["mcp.cerebro.apply"].descriptor.authority_class,
            ToolAuthorityClass::Actuate
        );
        assert_eq!(
            tools["mcp.cerebro.apply"].descriptor.effect_class,
            ToolEffectClass::ExternalEffect
        );
    }

    #[test]
    fn authority_policy_cannot_promote_a_read_tool_to_actuation() {
        let result = bind_tools(
            vec![tool("cerebro.read", true)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::from(["cerebro.read".into()]),
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_provider_supplied_tool_names_outside_the_bounded_id_contract() {
        let result = bind_tools(
            vec![tool("cerebro:read", true)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn capability_selection_refs_are_scope_and_descriptor_bound() {
        let tools = bind_tools(
            vec![tool("slack.thread.read", true)],
            &BTreeSet::from(["slack.thread.read".into()]),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let descriptors = tools.values().map(|tool| tool.descriptor.clone()).collect();
        let mut mcp = McpAgentTools {
            client: Client::new(),
            endpoint: Url::parse("http://127.0.0.1:8080/mcp").unwrap(),
            bearer_token: "selection-signing-secret".into(),
            selection_signing_key: "host-only-selection-signing-secret".into(),
            toolsets: "task".into(),
            descriptors,
            tools,
        };
        let request = turn_request();
        let descriptor = mcp.descriptors()[0].clone();
        let query_digest = format!("sha256:{}", "a".repeat(64));
        let selection_ref = mcp
            .issue_selection_ref(&request, &descriptor, &query_digest)
            .unwrap();

        assert_eq!(
            mcp.verify_selection_ref(&request, &selection_ref).unwrap(),
            descriptor
        );

        let mut another_actor = request.clone();
        another_actor.actor_ref = "slack-user://another".into();
        assert!(
            mcp.verify_selection_ref(&another_actor, &selection_ref)
                .is_err()
        );

        let mut later_turn_in_same_scope = request.clone();
        later_turn_in_same_scope.request_id = "request://scheduled-wake".into();
        assert!(
            mcp.verify_selection_ref(&later_turn_in_same_scope, &selection_ref)
                .is_ok()
        );

        let mut scheduled_wake = request.clone();
        scheduled_wake.request_id = "request://scheduled-wake".into();
        scheduled_wake.actor_ref = "cerebro-scheduler".into();
        assert!(
            mcp.verify_selection_ref(&scheduled_wake, &selection_ref)
                .is_ok()
        );

        let forged = format!("{selection_ref}0");
        assert!(mcp.verify_selection_ref(&request, &forged).is_err());

        mcp.tools
            .get_mut(&descriptor.tool_id)
            .unwrap()
            .descriptor
            .summary
            .push_str(" Contract drifted.");
        assert!(mcp.verify_selection_ref(&request, &selection_ref).is_err());
    }

    #[test]
    fn remote_plaintext_and_embedded_credentials_are_rejected() {
        assert!(validated_endpoint("http://cerebro.example.com/api/v1/mcp").is_err());
        assert!(validated_endpoint("https://token@cerebro.example.com/api/v1/mcp").is_err());
        assert!(validated_endpoint("http://127.0.0.1:8080/api/v1/mcp").is_ok());
        assert!(validated_endpoint("https://cerebro.example.com/api/v1/mcp").is_ok());
    }

    #[test]
    fn empty_host_authority_policy_does_not_require_a_signing_key() {
        assert_eq!(
            selection_signing_key(None, "mcp-bearer", false).unwrap(),
            ""
        );
        assert!(selection_signing_key(None, "mcp-bearer", true).is_err());
        assert!(selection_signing_key(Some("mcp-bearer".into()), "mcp-bearer", true).is_err());
        assert!(
            selection_signing_key(
                Some("host-only-capability-signing-secret".into()),
                "mcp-bearer",
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn parses_standard_mcp_tools_list_result() {
        let listed = parse_listed_tools(json!({
            "tools": [{
                "name": "cerebro.read",
                "title": "Read",
                "description": "Read current evidence.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false
                },
                "annotations": {
                    "readOnlyHint": true
                }
            }],
            "nextCursor": null
        }))
        .unwrap();

        assert_eq!(listed.tools.len(), 1);
        assert_eq!(listed.tools[0].name, "cerebro.read");
        assert_eq!(
            listed.tools[0].annotations.get("readOnlyHint"),
            Some(&json!(true))
        );
        assert!(listed.next_cursor.is_none());
    }

    #[test]
    fn rust_agent_never_binds_the_nested_go_graph_reasoning_agent() {
        let tools = bind_tools(
            vec![
                tool("cerebro.graph.reason", true),
                tool("cerebro.risk.summary", true),
                tool("cerebro.findings.search", true),
            ],
            &BTreeSet::from([
                "cerebro.graph.reason".into(),
                "cerebro.risk.summary".into(),
                "cerebro.findings.search".into(),
            ]),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();

        assert!(!tools.contains_key("mcp.cerebro.graph.reason"));
        assert!(tools.contains_key("mcp.cerebro.risk.summary"));
        assert!(tools.contains_key("mcp.cerebro.findings.search"));
    }

    #[tokio::test]
    async fn actuation_transport_failures_remain_outcome_unknown_to_the_runtime() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/mcp", post(|| async { StatusCode::BAD_GATEWAY })),
            )
            .await
            .unwrap();
        });
        let tools = bind_tools(
            vec![tool("slack.message.send", false)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::from(["slack.message.send".into()]),
        )
        .unwrap();
        let descriptors = tools.values().map(|tool| tool.descriptor.clone()).collect();
        let mcp = McpAgentTools {
            client: Client::new(),
            endpoint: Url::parse(&format!("http://{address}/mcp")).unwrap(),
            bearer_token: "tenant-token".into(),
            selection_signing_key: "host-only-selection-signing-secret".into(),
            toolsets: "task".into(),
            descriptors,
            tools,
        };
        let call = ToolCall {
            call_id: "send-one".into(),
            tool_id: "mcp.slack.message.send".into(),
            purpose: "Send the approved message.".into(),
            input: json!({"channel_id": "channel-one", "text": "hello"}),
        };

        let result = mcp.invoke(&turn_request(), &call).await;
        server.abort();

        assert!(matches!(
            result,
            Err(AgentRuntimeError::ModelUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn loads_every_bounded_page_from_a_stateless_mcp_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/mcp", post(paginated_tools)))
                .await
                .unwrap();
        });
        let endpoint = Url::parse(&format!("http://{address}/mcp")).unwrap();
        let client = Client::new();

        let listed = list_tools(&client, &endpoint, "tenant-token", "task", "tenant-a")
            .await
            .unwrap();
        server.abort();

        assert_eq!(
            listed
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cerebro.first", "cerebro.second"]
        );
    }

    async fn paginated_tools(
        headers: axum::http::HeaderMap,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer tenant-token");
        assert_eq!(headers.get("User-Agent").unwrap(), MCP_USER_AGENT);
        assert_eq!(headers.get("MCP-Protocol-Version").unwrap(), "2025-03-26");
        assert_eq!(headers.get("X-Cerebro-MCP-Toolsets").unwrap(), "task");
        assert_eq!(headers.get("X-Cerebro-Tenant").unwrap(), "tenant-a");
        let cursor = request["params"]["cursor"].as_str();
        let (name, next_cursor) = match cursor {
            None => ("cerebro.first", Some("page-2")),
            Some("page-2") => ("cerebro.second", None),
            _ => panic!("unexpected cursor"),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "tools": [{
                    "name": name,
                    "title": name,
                    "description": "Read current evidence.",
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": false
                    },
                    "annotations": {
                        "readOnlyHint": true
                    }
                }],
                "nextCursor": next_cursor
            }
        }))
    }

    fn tool(name: &str, read_only: bool) -> McpToolWire {
        McpToolWire {
            name: name.into(),
            title: name.into(),
            description: format!("Use {name}."),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
            }),
            annotations: BTreeMap::from([("readOnlyHint".into(), json!(read_only))]),
        }
    }

    fn turn_request() -> AgentTurnRequest {
        AgentTurnRequest {
            schema_version: "agent-turn-request/v1".into(),
            tenant_id: "tenant-a".into(),
            request_id: "request-a".into(),
            thread_ref: "slack-thread://a".into(),
            context_scope_ref: None,
            actor_ref: "slack-user://a".into(),
            assessment_at: "2026-07-31T12:00:00Z".into(),
            message: "Continue the analysis.".into(),
            history: vec![],
            history_metadata: vec![],
            working_state: None,
            effect_authorizations: vec![],
        }
    }
}
