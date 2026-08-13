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
    input_schema: Value,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum McpPostFailureKind {
    Timeout,
    Unavailable,
    AccessDenied,
    RateLimited,
    Rejected,
    InvalidResponse,
}

struct McpPostFailure {
    kind: McpPostFailureKind,
    runtime_error: AgentRuntimeError,
}

impl McpPostFailureKind {
    const fn guidance(self) -> RecoveryGuidance {
        match self {
            Self::Timeout => RecoveryGuidance {
                error_kind: "capability_gateway_timeout",
                retryable: true,
                operator_action: "Retry after the capability gateway responds again.",
            },
            Self::Unavailable => RecoveryGuidance {
                error_kind: "capability_gateway_unavailable",
                retryable: true,
                operator_action: "Retry after the capability gateway recovers.",
            },
            Self::AccessDenied => RecoveryGuidance {
                error_kind: "capability_gateway_access_denied",
                retryable: false,
                operator_action: "Restore capability gateway access before retrying.",
            },
            Self::RateLimited => RecoveryGuidance {
                error_kind: "capability_gateway_rate_limited",
                retryable: true,
                operator_action: "Retry after the capability gateway rate limit resets.",
            },
            Self::Rejected => RecoveryGuidance {
                error_kind: "capability_gateway_rejected",
                retryable: false,
                operator_action: "Correct the gateway request or configuration before retrying.",
            },
            Self::InvalidResponse => RecoveryGuidance {
                error_kind: "capability_gateway_invalid_response",
                retryable: false,
                operator_action: "Inspect the gateway response contract before retrying.",
            },
        }
    }
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
        validate_provider_input(&tool.input_schema, &call.input)
            .map_err(AgentRuntimeError::InvalidToolCall)?;
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
                return Err(error.runtime_error);
            }
            Err(error) => {
                let guidance = error.kind.guidance();
                return Ok(ToolResult {
                    state: ToolResultState::Failed,
                    summary: format!("MCP tool {} could not complete the call.", tool.mcp_name),
                    data: with_recovery_guidance(json!({}), guidance),
                    evidence: vec![],
                    blocker: Some(format!(
                        "The {} capability gateway could not complete this call. {}",
                        tool.descriptor.title, guidance.operator_action
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
            let guidance = json_rpc_error_guidance(error.code);
            return Ok(ToolResult {
                state: ToolResultState::Failed,
                summary: format!("MCP tool {} failed.", tool.mcp_name),
                data: with_recovery_guidance(
                    json!({
                        "error_code": error.code,
                        "error_message": bounded_error(&error.message),
                    }),
                    guidance,
                ),
                evidence: vec![],
                blocker: Some(format!(
                    "The {} capability returned an MCP error. {}",
                    tool.descriptor.title, guidance.operator_action
                )),
            });
        }
        let result = response.result.ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall("MCP tool response omitted its result".into())
        })?;
        let (is_error, invalid_is_error) = provider_error_signal(&result);
        let semantic_envelope = semantic_evidence_envelope(&result)?;
        let data = result
            .get("structuredContent")
            .cloned()
            .unwrap_or_else(|| result.clone());
        let normalized = normalize_tool_result(data, is_error, invalid_is_error);
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
    ) -> Result<JsonRpcResponse, McpPostFailure> {
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
            .map_err(|error| McpPostFailure {
                kind: if error.is_timeout() {
                    McpPostFailureKind::Timeout
                } else {
                    McpPostFailureKind::Unavailable
                },
                runtime_error: AgentRuntimeError::ModelUnavailable(error.to_string()),
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let kind = if matches!(
                status,
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) {
                McpPostFailureKind::AccessDenied
            } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                McpPostFailureKind::RateLimited
            } else if status.is_server_error() {
                McpPostFailureKind::Unavailable
            } else {
                McpPostFailureKind::Rejected
            };
            return Err(McpPostFailure {
                kind,
                runtime_error: AgentRuntimeError::ModelUnavailable(format!(
                    "MCP gateway returned status {status}"
                )),
            });
        }
        bounded_json(response)
            .await
            .map_err(|error| McpPostFailure {
                kind: McpPostFailureKind::InvalidResponse,
                runtime_error: AgentRuntimeError::InvalidToolCall(error),
            })
    }
}

struct NormalizedToolResult {
    state: ToolResultState,
    data: Value,
    blocker: Option<String>,
}

fn provider_error_signal(result: &Value) -> (bool, Option<Value>) {
    match result.get("isError") {
        None => (false, None),
        Some(Value::Bool(is_error)) => (*is_error, None),
        Some(value) => (false, Some(value.clone())),
    }
}

fn normalize_tool_result(
    data: Value,
    is_error: bool,
    invalid_is_error: Option<Value>,
) -> NormalizedToolResult {
    let (declared_state, invalid_state) = match data.get("state") {
        None => (ToolResultState::Succeeded, false),
        Some(Value::String(state)) => match state.as_str() {
            "complete" | "succeeded" => (ToolResultState::Succeeded, false),
            "partial" => (ToolResultState::Partial, false),
            "blocked" => (ToolResultState::Failed, false),
            "outcome_unknown" => (ToolResultState::OutcomeUnknown, false),
            _ => (ToolResultState::Failed, true),
        },
        Some(_) => (ToolResultState::Failed, true),
    };
    let state = if is_error || invalid_is_error.is_some() {
        ToolResultState::Failed
    } else {
        declared_state
    };
    let blocker = (state != ToolResultState::Succeeded)
        .then(|| provider_blocker(&data))
        .flatten()
        .or_else(|| {
            invalid_state.then(|| "The provider returned an unsupported result state.".into())
        })
        .or_else(|| {
            invalid_is_error
                .is_some()
                .then(|| "The provider returned a non-boolean isError signal.".into())
        });
    let data = if let Some(invalid_is_error) = invalid_is_error {
        json!({
            "provider_result": data,
            "invalid_is_error": invalid_is_error,
            "error_kind": INVALID_PROVIDER_ERROR_SIGNAL_GUIDANCE.error_kind,
            "retryable": INVALID_PROVIDER_ERROR_SIGNAL_GUIDANCE.retryable,
            "operator_action": INVALID_PROVIDER_ERROR_SIGNAL_GUIDANCE.operator_action,
        })
    } else if is_error || state == ToolResultState::Failed {
        let guidance = if invalid_state {
            INVALID_PROVIDER_STATE_GUIDANCE
        } else {
            tool_error_guidance(&data)
        };
        with_recovery_guidance(data, guidance)
    } else {
        data
    };
    NormalizedToolResult {
        state,
        data,
        blocker,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryGuidance {
    error_kind: &'static str,
    retryable: bool,
    operator_action: &'static str,
}

const INVALID_PROVIDER_STATE_GUIDANCE: RecoveryGuidance = RecoveryGuidance {
    error_kind: "invalid_provider_result_state",
    retryable: false,
    operator_action: "Inspect the provider result contract before retrying.",
};

const INVALID_PROVIDER_ERROR_SIGNAL_GUIDANCE: RecoveryGuidance = RecoveryGuidance {
    error_kind: "invalid_provider_error_signal",
    retryable: false,
    operator_action: "Inspect the provider result envelope before retrying.",
};

fn tool_error_guidance(data: &Value) -> RecoveryGuidance {
    let provider_kind = data
        .pointer("/error/kind")
        .or_else(|| data.get("error_kind"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    match provider_kind {
        "not_found" => RecoveryGuidance {
            error_kind: "target_not_found",
            retryable: false,
            operator_action: "Verify the target identifier before retrying.",
        },
        "tenant_forbidden" | "forbidden" | "unauthorized" => RecoveryGuidance {
            error_kind: "capability_access_denied",
            retryable: false,
            operator_action: "Restore capability access before retrying.",
        },
        "invalid_request" | "invalid_argument" | "invalid_params" => RecoveryGuidance {
            error_kind: "invalid_tool_request",
            retryable: false,
            operator_action: "Correct the tool input before retrying.",
        },
        "runtime_unavailable" | "unavailable" | "timeout" => RecoveryGuidance {
            error_kind: "capability_unavailable",
            retryable: true,
            operator_action: "Retry after the capability runtime recovers.",
        },
        "conflict" => RecoveryGuidance {
            error_kind: "capability_conflict",
            retryable: false,
            operator_action: "Refresh current state before proposing another call.",
        },
        "rate_limited" => RecoveryGuidance {
            error_kind: "capability_rate_limited",
            retryable: true,
            operator_action: "Retry later without changing the request.",
        },
        _ => RecoveryGuidance {
            error_kind: "capability_error",
            retryable: false,
            operator_action: "Inspect the provider error before retrying.",
        },
    }
}

const fn json_rpc_error_guidance(code: i64) -> RecoveryGuidance {
    match code {
        -32700 => RecoveryGuidance {
            error_kind: "rpc_parse_error",
            retryable: false,
            operator_action: "Inspect the gateway protocol response before retrying.",
        },
        -32600 => RecoveryGuidance {
            error_kind: "invalid_rpc_request",
            retryable: false,
            operator_action: "Correct the gateway request contract before retrying.",
        },
        -32601 => RecoveryGuidance {
            error_kind: "capability_method_unavailable",
            retryable: false,
            operator_action: "Refresh the capability catalog before retrying.",
        },
        -32602 => RecoveryGuidance {
            error_kind: "invalid_tool_request",
            retryable: false,
            operator_action: "Correct the tool input before retrying.",
        },
        -32603 => RecoveryGuidance {
            error_kind: "provider_internal_error",
            retryable: true,
            operator_action: "Retry after the capability provider recovers.",
        },
        -32099..=-32000 => RecoveryGuidance {
            error_kind: "provider_server_error",
            retryable: true,
            operator_action: "Retry after the capability provider recovers.",
        },
        _ => RecoveryGuidance {
            error_kind: "provider_rpc_error",
            retryable: false,
            operator_action: "Inspect the provider error before retrying.",
        },
    }
}

fn with_recovery_guidance(data: Value, guidance: RecoveryGuidance) -> Value {
    let mut object = match data {
        Value::Object(object) => object,
        provider_result => {
            serde_json::Map::from_iter([("provider_result".to_owned(), provider_result)])
        }
    };
    object.insert("error_kind".into(), json!(guidance.error_kind));
    object.insert("retryable".into(), json!(guidance.retryable));
    object.insert("operator_action".into(), json!(guidance.operator_action));
    Value::Object(object)
}

fn provider_blocker(data: &Value) -> Option<String> {
    for field in ["blocker", "reason"] {
        if let Some(value) = data.get(field).and_then(Value::as_str) {
            let value = bounded_error(value);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    if let Some(value) = data.pointer("/error/message").and_then(Value::as_str) {
        let value = bounded_error(value);
        if !value.is_empty() {
            return Some(value);
        }
    }
    let reasons = data
        .get("partial_reasons")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let reasons = bounded_error(&reasons);
    (!reasons.is_empty()).then_some(reasons)
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
        validate_input_schema(&tool.name, &tool.input_schema)?;
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
                    input_schema: tool.input_schema,
                },
            )
            .is_some()
        {
            return Err("MCP tool catalog repeats a tool id".into());
        }
    }
    Ok(tools)
}

fn validate_provider_input(schema: &Value, input: &Value) -> Result<(), String> {
    let schema = schema
        .as_object()
        .ok_or_else(|| "provider input contract is unavailable".to_owned())?;
    let input = input
        .as_object()
        .ok_or_else(|| "provider input must be an object".to_owned())?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .filter(|field| !input.contains_key(**field))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "provider input is missing required fields: {}",
            missing.join(", ")
        ));
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
        let unknown = input
            .keys()
            .filter(|field| !properties.contains_key(*field))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format!(
                "provider input contains unsupported fields: {}",
                unknown.join(", ")
            ));
        }
    }
    for (field, value) in input {
        let Some(contract) = properties.get(field).and_then(Value::as_object) else {
            continue;
        };
        if let Some(allowed) = contract.get("enum").and_then(Value::as_array)
            && !allowed.contains(value)
        {
            return Err(format!(
                "provider input field {field} is outside its allowed values"
            ));
        }
        let accepted_types = match contract.get("type") {
            Some(Value::String(kind)) => vec![kind.as_str()],
            Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !accepted_types.is_empty()
            && !accepted_types
                .iter()
                .any(|kind| provider_value_matches_type(value, kind))
        {
            return Err(format!("provider input field {field} has an invalid type"));
        }
    }
    Ok(())
}

fn provider_value_matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn validate_input_schema(tool_name: &str, schema: &Value) -> Result<(), String> {
    let schema = schema
        .as_object()
        .ok_or_else(|| format!("MCP tool {tool_name} input schema must be an object"))?;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "MCP tool {tool_name} input schema must declare an object input"
        ));
    }
    if schema
        .get("properties")
        .is_some_and(|value| !value.is_object())
    {
        return Err(format!(
            "MCP tool {tool_name} input schema properties must be an object"
        ));
    }
    for (field, contract) in schema
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let Some(contract) = contract.as_object() else {
            if contract.is_boolean() {
                continue;
            }
            return Err(format!(
                "MCP tool {tool_name} input schema field {field} must be a schema"
            ));
        };
        if let Some(declared_type) = contract.get("type") {
            let types = match declared_type {
                Value::String(kind) => vec![kind.as_str()],
                Value::Array(kinds) if !kinds.is_empty() => {
                    kinds.iter().filter_map(Value::as_str).collect()
                }
                _ => Vec::new(),
            };
            let unique = types.iter().copied().collect::<BTreeSet<_>>();
            if types.is_empty()
                || types.len() != unique.len()
                || types.iter().any(|kind| {
                    !matches!(
                        *kind,
                        "array" | "boolean" | "integer" | "null" | "number" | "object" | "string"
                    )
                })
            {
                return Err(format!(
                    "MCP tool {tool_name} input schema field {field} has an invalid type"
                ));
            }
        }
        if contract.get("enum").is_some_and(|value| !value.is_array()) {
            return Err(format!(
                "MCP tool {tool_name} input schema field {field} enum must be an array"
            ));
        }
    }
    if let Some(required) = schema.get("required") {
        let required = required.as_array().ok_or_else(|| {
            format!("MCP tool {tool_name} input schema required must be an array")
        })?;
        let required_fields = required
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if required_fields.len() != required.len() {
            return Err(format!(
                "MCP tool {tool_name} input schema required fields must be unique strings"
            ));
        }
    }
    if schema
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean() && !value.is_object())
    {
        return Err(format!(
            "MCP tool {tool_name} input schema additionalProperties is invalid"
        ));
    }
    Ok(())
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
    fn preserves_provider_declared_unknown_outcomes() {
        let normalized = normalize_tool_result(
            json!({
                "state": "outcome_unknown",
                "operation_ref": "operation-one",
            }),
            false,
            None,
        );

        assert_eq!(normalized.state, ToolResultState::OutcomeUnknown);
        assert_eq!(normalized.data["operation_ref"], "operation-one");
    }

    #[test]
    fn fails_closed_on_invalid_provider_result_states() {
        for state in [json!("Complete"), json!("future_state"), json!(""), json!(7), Value::Null]
        {
            let normalized = normalize_tool_result(json!({"state": state}), false, None);
            assert_eq!(normalized.state, ToolResultState::Failed);
            assert_eq!(
                normalized.blocker.as_deref(),
                Some("The provider returned an unsupported result state.")
            );
            assert_eq!(
                normalized.data["error_kind"],
                "invalid_provider_result_state"
            );
            assert_eq!(normalized.data["retryable"], false);
        }

        let absent = normalize_tool_result(json!({"records": []}), false, None);
        assert_eq!(absent.state, ToolResultState::Succeeded);
        let succeeded = normalize_tool_result(json!({"state": "succeeded"}), false, None);
        assert_eq!(succeeded.state, ToolResultState::Succeeded);
    }

    #[test]
    fn fails_closed_on_non_boolean_provider_error_signals() {
        for invalid in [json!("false"), json!(1), Value::Null, json!({"value": false})] {
            let result = json!({"isError": invalid});
            let (is_error, invalid_is_error) = provider_error_signal(&result);
            assert!(!is_error);
            assert!(invalid_is_error.is_some());

            let normalized = normalize_tool_result(
                json!({"state": "complete", "records": ["record-one"]}),
                is_error,
                invalid_is_error,
            );
            assert_eq!(normalized.state, ToolResultState::Failed);
            assert_eq!(
                normalized.blocker.as_deref(),
                Some("The provider returned a non-boolean isError signal.")
            );
            assert_eq!(
                normalized.data["error_kind"],
                "invalid_provider_error_signal"
            );
            assert_eq!(normalized.data["retryable"], false);
            assert_eq!(
                normalized.data["provider_result"]["records"],
                json!(["record-one"])
            );
        }

        assert_eq!(provider_error_signal(&json!({"isError": true})), (true, None));
        assert_eq!(provider_error_signal(&json!({})), (false, None));
    }

    #[test]
    fn preserves_bounded_provider_recovery_reasons() {
        let blocked = normalize_tool_result(
            json!({"state": "blocked", "blocker": format!("{}tail", "x".repeat(512))}),
            false,
            None,
        );
        assert_eq!(blocked.state, ToolResultState::Failed);
        assert_eq!(blocked.blocker.as_ref().unwrap().chars().count(), 512);
        assert!(!blocked.blocker.as_ref().unwrap().contains("tail"));
        assert_eq!(blocked.data["error_kind"], "capability_error");
        assert_eq!(blocked.data["retryable"], false);
        assert_eq!(
            blocked.data["operator_action"],
            "Inspect the provider error before retrying."
        );

        let unavailable = normalize_tool_result(
            json!({
                "state": "blocked",
                "error": {"kind": "runtime_unavailable", "message": "Runtime is down."},
                "request_ref": "request-one"
            }),
            false,
            None,
        );
        assert_eq!(unavailable.state, ToolResultState::Failed);
        assert_eq!(unavailable.data["error_kind"], "capability_unavailable");
        assert_eq!(unavailable.data["retryable"], true);
        assert_eq!(unavailable.data["request_ref"], "request-one");

        let partial = normalize_tool_result(
            json!({
                "state": "partial",
                "partial_reasons": ["Graph projection is unavailable.", "Runtime state is stale."]
            }),
            false,
            None,
        );
        assert_eq!(partial.state, ToolResultState::Partial);
        assert_eq!(
            partial.blocker.as_deref(),
            Some("Graph projection is unavailable.; Runtime state is stale.")
        );

        let complete = normalize_tool_result(
            json!({"state": "complete", "blocker": "must not shadow success"}),
            false,
            None,
        );
        assert_eq!(complete.state, ToolResultState::Succeeded);
        assert_eq!(complete.blocker, None);
    }

    #[test]
    fn normalizes_tool_level_errors_into_stable_recovery_guidance() {
        let denied = normalize_tool_result(
            json!({
                "error": {
                    "kind": "tenant_forbidden",
                    "message": "Tenant access is not authorized."
                },
                "request_ref": "request-one"
            }),
            true,
            None,
        );
        assert_eq!(denied.state, ToolResultState::Failed);
        assert_eq!(
            denied.blocker.as_deref(),
            Some("Tenant access is not authorized.")
        );
        assert_eq!(denied.data["error_kind"], "capability_access_denied");
        assert_eq!(denied.data["retryable"], false);
        assert_eq!(
            denied.data["operator_action"],
            "Restore capability access before retrying."
        );
        assert_eq!(denied.data["request_ref"], "request-one");

        let unavailable = normalize_tool_result(
            json!({"error": {"kind": "runtime_unavailable", "message": "Runtime is down."}}),
            true,
            None,
        );
        assert_eq!(unavailable.data["error_kind"], "capability_unavailable");
        assert_eq!(unavailable.data["retryable"], true);
    }

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
    fn rejects_ambiguous_mcp_input_contracts_before_binding() {
        let mut missing_object_type = tool("cerebro.missing_type", true);
        missing_object_type.input_schema = json!({"properties": {}});
        assert!(
            bind_tools(
                vec![missing_object_type],
                &BTreeSet::from(["cerebro.missing_type".into()]),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .is_err()
        );

        let mut duplicate_required = tool("cerebro.duplicate_required", true);
        duplicate_required.input_schema = json!({
            "type": "object",
            "properties": {"thread_ref": {"type": "string"}},
            "required": ["thread_ref", "thread_ref"]
        });
        assert!(
            bind_tools(
                vec![duplicate_required],
                &BTreeSet::from(["cerebro.duplicate_required".into()]),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .is_err()
        );

        let mut unknown_property_type = tool("cerebro.unknown_property_type", true);
        unknown_property_type.input_schema = json!({
            "type": "object",
            "properties": {"thread_ref": {"type": "strng"}}
        });
        assert!(
            bind_tools(
                vec![unknown_property_type],
                &BTreeSet::from(["cerebro.unknown_property_type".into()]),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .is_err()
        );

        let mut valid = tool("cerebro.valid", true);
        valid.input_schema = json!({
            "type": "object",
            "properties": {"thread_ref": {"type": "string"}},
            "required": ["thread_ref"],
            "additionalProperties": false
        });
        assert!(
            bind_tools(
                vec![valid],
                &BTreeSet::from(["cerebro.valid".into()]),
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_provider_input_before_mcp_dispatch() {
        let schema = json!({
            "type": "object",
            "properties": {
                "channel_id": {"type": "string"},
                "limit": {"type": "integer"},
                "mode": {"type": "string", "enum": ["recent", "thread"]}
            },
            "required": ["channel_id"],
            "additionalProperties": false
        });

        assert!(
            validate_provider_input(
                &schema,
                &json!({"channel_id": "C123", "limit": 25, "mode": "thread"})
            )
            .is_ok()
        );
        assert_eq!(
            validate_provider_input(&schema, &json!({"limit": 25})).unwrap_err(),
            "provider input is missing required fields: channel_id"
        );
        assert_eq!(
            validate_provider_input(&schema, &json!({"channel_id": 123})).unwrap_err(),
            "provider input field channel_id has an invalid type"
        );
        assert_eq!(
            validate_provider_input(&schema, &json!({"channel_id": "C123", "mode": "archive"}))
                .unwrap_err(),
            "provider input field mode is outside its allowed values"
        );
        assert_eq!(
            validate_provider_input(
                &schema,
                &json!({"channel_id": "C123", "workspace": "wrong"})
            )
            .unwrap_err(),
            "provider input contains unsupported fields: workspace"
        );
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
        let mut send_tool = tool("slack.message.send", false);
        send_tool.input_schema = json!({
            "type": "object",
            "properties": {
                "channel_id": {"type": "string"},
                "text": {"type": "string"}
            },
            "required": ["channel_id", "text"],
            "additionalProperties": false
        });
        let tools = bind_tools(
            vec![send_tool],
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
    async fn non_actuation_transport_failures_return_stable_recovery_guidance() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/mcp", post(|| async { StatusCode::TOO_MANY_REQUESTS })),
            )
            .await
            .unwrap();
        });
        let tools = bind_tools(
            vec![tool("cerebro.findings.search", true)],
            &BTreeSet::from(["cerebro.findings.search".into()]),
            &BTreeSet::new(),
            &BTreeSet::new(),
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
            call_id: "search-one".into(),
            tool_id: "mcp.cerebro.findings.search".into(),
            purpose: "Find current findings.".into(),
            input: json!({}),
        };

        let result = mcp.invoke(&turn_request(), &call).await.unwrap();
        server.abort();

        assert_eq!(result.state, ToolResultState::Failed);
        assert_eq!(result.data["error_kind"], "capability_gateway_rate_limited");
        assert_eq!(result.data["retryable"], true);
        assert_eq!(
            result.data["operator_action"],
            "Retry after the capability gateway rate limit resets."
        );
        assert!(result.evidence.is_empty());
    }

    #[tokio::test]
    async fn json_rpc_errors_return_stable_recovery_guidance() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/mcp",
                    post(|| async {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": "search-one",
                            "error": {
                                "code": -32602,
                                "message": "finding_id is required"
                            }
                        }))
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let tools = bind_tools(
            vec![tool("cerebro.findings.search", true)],
            &BTreeSet::from(["cerebro.findings.search".into()]),
            &BTreeSet::new(),
            &BTreeSet::new(),
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
            call_id: "search-one".into(),
            tool_id: "mcp.cerebro.findings.search".into(),
            purpose: "Find current findings.".into(),
            input: json!({}),
        };

        let result = mcp.invoke(&turn_request(), &call).await.unwrap();
        server.abort();

        assert_eq!(result.state, ToolResultState::Failed);
        assert_eq!(result.data["error_code"], -32602);
        assert_eq!(result.data["error_message"], "finding_id is required");
        assert_eq!(result.data["error_kind"], "invalid_tool_request");
        assert_eq!(result.data["retryable"], false);
        assert_eq!(
            result.data["operator_action"],
            "Correct the tool input before retrying."
        );
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn classifies_standard_and_provider_json_rpc_errors() {
        assert_eq!(
            json_rpc_error_guidance(-32601).error_kind,
            "capability_method_unavailable"
        );
        assert_eq!(
            json_rpc_error_guidance(-32603),
            RecoveryGuidance {
                error_kind: "provider_internal_error",
                retryable: true,
                operator_action: "Retry after the capability provider recovers.",
            }
        );
        assert_eq!(
            json_rpc_error_guidance(-32042).error_kind,
            "provider_server_error"
        );
        assert_eq!(
            json_rpc_error_guidance(7001).error_kind,
            "provider_rpc_error"
        );
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
