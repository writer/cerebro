use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};

use cerebro_agent_runtime::{
    AgentRuntimeError, AgentTurnRequest, EvidenceRecord, ToolAuthorityClass, ToolCall,
    ToolDescriptor, ToolEffectClass, ToolResult, ToolResultState,
};
use reqwest::{
    Client, Url,
    header::{ACCEPT, AUTHORIZATION},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const MCP_URL_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_URL";
const MCP_TOKEN_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_BEARER_TOKEN";
const MCP_TOOLSETS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_TOOLSETS";
const MCP_PROPOSE_TOOLS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_PROPOSE_TOOLS";
const MCP_ACTUATE_TOOLS_ENV: &str = "CEREBRO_SLACK_AGENT_MCP_ACTUATE_TOOLS";
const GRAPH_REASON_TOOL: &str = "cerebro.graph.reason";
const MAX_MCP_TOOLS: usize = 256;
const MAX_SCHEMA_BYTES: usize = 8 * 1024;
const MAX_MCP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_GRAPH_REASON_HISTORY_ITEMS: usize = 12;
const MAX_GRAPH_REASON_HISTORY_ITEM_BYTES: usize = 4 * 1024;

pub struct McpAgentTools {
    client: Client,
    endpoint: Url,
    bearer_token: String,
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

    pub async fn from_env() -> Result<Option<Self>, String> {
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
        let propose_tools = configured_tool_names(MCP_PROPOSE_TOOLS_ENV)?;
        let actuate_tools = configured_tool_names(MCP_ACTUATE_TOOLS_ENV)?;
        if !propose_tools.is_disjoint(&actuate_tools) {
            return Err("an MCP tool cannot be both propose and actuate".into());
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| error.to_string())?;
        let listed = list_tools(&client, &endpoint, &bearer_token, &toolsets).await?;
        if listed.len() > MAX_MCP_TOOLS {
            return Err("MCP tool catalog exceeds the bounded limit".into());
        }
        let listed_names = listed
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<BTreeSet<_>>();
        if propose_tools
            .iter()
            .chain(&actuate_tools)
            .any(|name| !listed_names.contains(name.as_str()))
        {
            return Err("configured MCP authority policy names an unavailable tool".into());
        }
        let tools = bind_tools(listed, &propose_tools, &actuate_tools)?;
        let descriptors = tools.values().map(|tool| tool.descriptor.clone()).collect();
        Ok(Some(Self {
            client,
            endpoint,
            bearer_token,
            toolsets,
            descriptors,
            tools,
        }))
    }

    pub fn descriptors(&self) -> &[ToolDescriptor] {
        &self.descriptors
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
                        "arguments": tool_arguments(request, &tool.mcp_name, &call.input),
                    },
                }),
            )
            .await
        {
            Ok(response) => response,
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
        let data = result
            .get("structuredContent")
            .cloned()
            .unwrap_or_else(|| result.clone());
        let normalized = normalize_tool_result(&tool.mcp_name, data, is_error);
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

fn tool_arguments(request: &AgentTurnRequest, tool_name: &str, input: &Value) -> Value {
    let mut arguments = input.clone();
    if tool_name != GRAPH_REASON_TOOL {
        return arguments;
    }
    let Some(arguments) = arguments.as_object_mut() else {
        return arguments;
    };
    let history = request
        .history
        .iter()
        .rev()
        .take(MAX_GRAPH_REASON_HISTORY_ITEMS)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|message| {
            json!({
                "role": message.role,
                "content": truncate_utf8(
                    message.content.trim(),
                    MAX_GRAPH_REASON_HISTORY_ITEM_BYTES,
                ),
            })
        })
        .collect::<Vec<_>>();
    if !history.is_empty() {
        arguments.insert("history".into(), Value::Array(history));
    }
    Value::Object(arguments.clone())
}

fn normalize_tool_result(tool_name: &str, data: Value, is_error: bool) -> NormalizedToolResult {
    if tool_name == GRAPH_REASON_TOOL {
        return normalize_graph_reason_result(data, is_error);
    }
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

fn normalize_graph_reason_result(data: Value, is_error: bool) -> NormalizedToolResult {
    let refusal_code = data
        .get("unsupported_query")
        .filter(|value| !value.is_null())
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if is_error || refusal_code.is_some() {
        return blocked_graph_reason_result(refusal_code.unwrap_or("unsupported_query"));
    }

    let validation = data.get("citation_validation");
    let citations_ok = validation
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let row_urn_count = validation
        .and_then(|value| value.get("row_urn_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let referenced_urn_count = validation
        .and_then(|value| value.get("referenced_urn_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let answer = data
        .get("answer_markdown")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if !citations_ok
        || row_urn_count == 0
        || referenced_urn_count == 0
        || referenced_urn_count > row_urn_count
        || answer.is_none()
    {
        return blocked_graph_reason_result("grounding_validation_failed");
    }

    NormalizedToolResult {
        state: ToolResultState::Succeeded,
        data: json!({
            "state": "complete",
            "answer_markdown": answer.expect("validated above"),
            "citation_validation": {
                "ok": true,
                "referenced_urn_count": referenced_urn_count,
                "row_urn_count": row_urn_count,
            },
        }),
        blocker: None,
    }
}

fn blocked_graph_reason_result(reason_code: &str) -> NormalizedToolResult {
    NormalizedToolResult {
        state: ToolResultState::Failed,
        data: json!({
            "state": "blocked",
            "reason_code": bounded_reason_code(reason_code),
        }),
        blocker: Some(
            "Graph reasoning did not produce a grounded answer. Continue with other bounded evidence capabilities."
                .into(),
        ),
    }
}

fn bounded_reason_code(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(64)
        .collect()
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

fn bind_tools(
    listed: Vec<McpToolWire>,
    propose_tools: &BTreeSet<String>,
    actuate_tools: &BTreeSet<String>,
) -> Result<BTreeMap<String, BoundMcpTool>, String> {
    let mut tools = BTreeMap::new();
    for tool in listed {
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
        } else if read_only {
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
            .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
            .header("MCP-Protocol-Version", "2025-03-26")
            .header("X-Cerebro-MCP-Toolsets", toolsets)
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
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let fresh_until = observed_at
        .checked_add(Duration::minutes(5))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
    let response_digest = hex_digest(&Sha256::digest(
        serde_json::to_vec(data)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
    ));
    let identity = format!(
        "{}:{}:{}:{}:{response_digest}",
        request.tenant_id,
        request.request_id,
        call.call_id,
        call.input_digest()
    );
    let digest = hex_digest(&Sha256::digest(identity.as_bytes()));
    Ok(EvidenceRecord {
        evidence_ref: format!("evidence://mcp/{tool_name}/{digest}"),
        statement: format!(
            "The tenant-scoped MCP tool {tool_name} returned this bounded result; complete={complete}; response_digest=sha256:{response_digest}."
        ),
        observed_at: observed_at
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        fresh_until: Some(
            fresh_until
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        ),
        complete,
        atoms: Vec::new(),
    })
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
    use axum::{Json, Router, routing::post};
    use cerebro_agent_runtime::{ConversationMessage, ConversationRole};

    #[test]
    fn binds_read_tools_and_omits_unapproved_write_tools() {
        let tools = bind_tools(
            vec![tool("cerebro.read", true), tool("cerebro.write", false)],
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
    fn explicit_policy_separates_proposals_from_exact_approval_effects() {
        let tools = bind_tools(
            vec![tool("cerebro.plan", true), tool("cerebro.apply", false)],
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
            &BTreeSet::from(["cerebro.read".into()]),
        );

        assert!(result.is_err());
    }

    #[test]
    fn remote_plaintext_and_embedded_credentials_are_rejected() {
        assert!(validated_endpoint("http://cerebro.example.com/api/v1/mcp").is_err());
        assert!(validated_endpoint("https://token@cerebro.example.com/api/v1/mcp").is_err());
        assert!(validated_endpoint("http://127.0.0.1:8080/api/v1/mcp").is_ok());
        assert!(validated_endpoint("https://cerebro.example.com/api/v1/mcp").is_ok());
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
    fn graph_reason_carries_bounded_thread_history_into_the_inner_ask() {
        let mut request = turn_request();
        request.history = vec![
            ConversationMessage {
                role: ConversationRole::User,
                content: "Map the control to its expected evidence.".into(),
            },
            ConversationMessage {
                role: ConversationRole::Assistant,
                content: "I found the current control record.".into(),
            },
        ];

        let arguments = tool_arguments(
            &request,
            GRAPH_REASON_TOOL,
            &json!({"question": "Continue the lineage analysis."}),
        );

        assert_eq!(arguments["history"].as_array().unwrap().len(), 2);
        assert_eq!(arguments["history"][0]["role"], "user");
        assert_eq!(
            arguments["history"][1]["content"],
            "I found the current control record."
        );
    }

    #[test]
    fn graph_reason_refusals_are_not_promoted_to_complete_evidence() {
        let normalized = normalize_tool_result(
            GRAPH_REASON_TOOL,
            json!({
                "answer_markdown": "row-expanding query mechanics were rejected",
                "unsupported_query": {
                    "code": "validator_refusal",
                    "reason": "internal query detail"
                }
            }),
            false,
        );

        assert_eq!(normalized.state, ToolResultState::Failed);
        assert_eq!(normalized.data["reason_code"], "validator_refusal");
        assert!(normalized.data.get("answer_markdown").is_none());
        assert!(
            normalized
                .blocker
                .as_deref()
                .unwrap()
                .contains("other bounded evidence capabilities")
        );
    }

    #[test]
    fn graph_reason_requires_the_same_grounding_contract_as_the_slack_ask_path() {
        let rejected = normalize_tool_result(
            GRAPH_REASON_TOOL,
            json!({
                "answer_markdown": "An answer without source-backed citations.",
                "citation_validation": {
                    "ok": true,
                    "referenced_urn_count": 0,
                    "row_urn_count": 0
                }
            }),
            false,
        );
        assert_eq!(rejected.state, ToolResultState::Failed);
        assert_eq!(rejected.data["reason_code"], "grounding_validation_failed");

        let accepted = normalize_tool_result(
            GRAPH_REASON_TOOL,
            json!({
                "answer_markdown": "The current evidence supports the scoped conclusion.",
                "citation_validation": {
                    "ok": true,
                    "referenced_urn_count": 1,
                    "row_urn_count": 2
                },
                "cypher": {"cypher": "internal query"},
                "rows": [{"tenant_id": "hidden"}]
            }),
            false,
        );
        assert_eq!(accepted.state, ToolResultState::Succeeded);
        assert_eq!(
            accepted.data["answer_markdown"],
            "The current evidence supports the scoped conclusion."
        );
        assert!(accepted.data.get("cypher").is_none());
        assert!(accepted.data.get("rows").is_none());
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

        let listed = list_tools(&client, &endpoint, "tenant-token", "task")
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
        assert_eq!(headers.get("MCP-Protocol-Version").unwrap(), "2025-03-26");
        assert_eq!(headers.get("X-Cerebro-MCP-Toolsets").unwrap(), "task");
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
            working_state: None,
            effect_authorizations: vec![],
        }
    }
}
