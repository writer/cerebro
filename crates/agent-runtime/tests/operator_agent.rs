use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

use async_trait::async_trait;
use cerebro_agent_runtime::{
    AGENT_TURN_REQUEST_V1, AgentModel, AgentRuntimeError, AgentTools, AgentTurnOutcome,
    AgentTurnRequest, ConversationMessage, ConversationRole, CritiqueDecision, CritiqueTurn,
    EffectAuthorization, EvidenceClaim, EvidenceRecord, ExecutionLane, FinalDraft, FinalState,
    ModelDecision, ModelTurn, RouteConfidence, RouteDecision, RouteTurn, ToolAuthorityClass,
    ToolCall, ToolDescriptor, ToolEffectClass, ToolResult, ToolResultState, WorkingOutcome,
    WorkingState, run_turn,
};
use serde_json::json;

struct ScriptedModel {
    routes: Mutex<VecDeque<RouteDecision>>,
    decisions: Mutex<VecDeque<ModelDecision>>,
    critiques: Mutex<VecDeque<CritiqueDecision>>,
}

#[async_trait]
impl AgentModel for ScriptedModel {
    async fn route(&self, _turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        self.routes
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| AgentRuntimeError::InvalidRoute("router script ended".into()))
    }

    async fn next(&self, _turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        self.decisions
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| AgentRuntimeError::InvalidFinal("model script ended".into()))
    }

    async fn critique(&self, _turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        Ok(self
            .critiques
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(CritiqueDecision::Approve))
    }
}

fn route(lane: ExecutionLane) -> RouteDecision {
    RouteDecision {
        lane,
        confidence: RouteConfidence::High,
        reason: format!("The request semantically requires the {lane:?} lane."),
        requires_current_evidence: !matches!(lane, ExecutionLane::Converse),
    }
}

fn scripted(lane: ExecutionLane, decisions: VecDeque<ModelDecision>) -> ScriptedModel {
    ScriptedModel {
        routes: Mutex::new(VecDeque::from([route(lane)])),
        decisions: Mutex::new(decisions),
        critiques: Mutex::new(VecDeque::new()),
    }
}

fn tool_then_repeat_draft(call: ToolCall, draft: FinalDraft) -> VecDeque<ModelDecision> {
    let mut decisions = VecDeque::from([ModelDecision::InvokeTool { call }]);
    decisions.extend((0..5).map(|_| ModelDecision::Finish {
        draft: draft.clone(),
    }));
    decisions
}

struct ScriptedTools {
    descriptors: Vec<ToolDescriptor>,
    results: Mutex<BTreeMap<String, ToolResult>>,
}

struct SchemaRepairModel {
    attempts: Mutex<usize>,
}

struct CriticSchemaRepairModel {
    attempts: Mutex<usize>,
}

#[async_trait]
impl AgentModel for CriticSchemaRepairModel {
    async fn route(&self, _turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        Ok(route(ExecutionLane::Converse))
    }

    async fn next(&self, _turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        Ok(ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Answered,
                headline: "Evidence freshness".into(),
                summary: "Fresh evidence remains valid through its stated observation window."
                    .into(),
                summary_evidence_refs: vec![],
                checked: vec![],
                changed: vec![],
                verified: vec![],
                current_state: vec![],
                next_actions: vec![],
                coverage_notice: None,
                question: None,
            },
        })
    }

    async fn critique(&self, turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        if *attempts == 1 {
            return Err(AgentRuntimeError::InvalidFinal(
                "critic output: expected value at line 1 column 1".into(),
            ));
        }
        assert!(turn.repair_feedback[0].contains("critic decision"));
        Ok(CritiqueDecision::Approve)
    }
}

#[async_trait]
impl AgentModel for SchemaRepairModel {
    async fn route(&self, _turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        Ok(route(ExecutionLane::Converse))
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        if *attempts == 1 {
            return Err(AgentRuntimeError::InvalidFinal(
                "invalid type: map, expected a string".into(),
            ));
        }
        assert!(turn.revision_feedback[0].contains("required JSON schema"));
        Ok(ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Answered,
                headline: "Cerebro capabilities".into(),
                summary: "I can explain security operations concepts.".into(),
                summary_evidence_refs: vec![],
                checked: vec![],
                changed: vec![],
                verified: vec![],
                current_state: vec![],
                next_actions: vec![],
                coverage_notice: None,
                question: None,
            },
        })
    }
}

#[async_trait]
impl AgentTools for ScriptedTools {
    fn catalog(&self) -> Vec<ToolDescriptor> {
        self.descriptors.clone()
    }

    async fn invoke(
        &self,
        _request: &AgentTurnRequest,
        call: &ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        self.results
            .lock()
            .unwrap()
            .remove(&call.call_id)
            .ok_or_else(|| AgentRuntimeError::ToolUnavailable(call.tool_id.clone()))
    }
}

fn request(message: &str) -> AgentTurnRequest {
    AgentTurnRequest {
        schema_version: AGENT_TURN_REQUEST_V1.into(),
        tenant_id: "tenant-one".into(),
        request_id: "request-one".into(),
        thread_ref: "thread-one".into(),
        actor_ref: "actor-one".into(),
        assessment_at: "2026-07-29T20:01:00Z".into(),
        message: message.into(),
        history: vec![ConversationMessage {
            role: ConversationRole::User,
            content: "Check the current runtime before changing it.".into(),
        }],
        working_state: None,
        effect_authorizations: vec![],
    }
}

fn tool(
    tool_id: &str,
    authority_class: ToolAuthorityClass,
    effect_class: ToolEffectClass,
) -> ToolDescriptor {
    ToolDescriptor {
        tool_id: tool_id.into(),
        title: tool_id.replace('_', " "),
        summary: format!("Use {tool_id} for the bounded operator step."),
        authority_class,
        effect_class,
        input_schema_ref: format!("schema://{tool_id}/input/v1"),
        result_schema_ref: format!("schema://{tool_id}/result/v1"),
    }
}

fn evidence(reference: &str, statement: &str) -> EvidenceRecord {
    EvidenceRecord {
        evidence_ref: reference.into(),
        statement: statement.into(),
        observed_at: "2026-07-29T20:00:00Z".into(),
        fresh_until: Some("2026-07-29T20:05:00Z".into()),
        complete: true,
    }
}

fn success(summary: &str, evidence: EvidenceRecord) -> ToolResult {
    ToolResult {
        state: ToolResultState::Succeeded,
        summary: summary.into(),
        data: json!({}),
        evidence: vec![evidence],
        blocker: None,
    }
}

fn claim(text: &str, reference: &str) -> EvidenceClaim {
    EvidenceClaim {
        text: text.into(),
        evidence_refs: vec![reference.into()],
    }
}

fn final_draft() -> FinalDraft {
    FinalDraft {
        state: FinalState::Answered,
        headline: "Runtime updated and verified".into(),
        summary: "The requested runtime change is active. One process restart remains pending."
            .into(),
        summary_evidence_refs: vec!["evidence://after".into()],
        checked: vec![claim(
            "The runtime was using the previous model before the change.",
            "evidence://before",
        )],
        changed: vec![claim(
            "The configured default model now points to the requested release.",
            "evidence://effect",
        )],
        verified: vec![claim(
            "A fresh status read confirms the new configured model.",
            "evidence://after",
        )],
        current_state: vec![claim(
            "The existing gateway process is still serving its prior session until restart.",
            "evidence://after",
        )],
        next_actions: vec!["Restart the gateway in the approved maintenance window.".into()],
        coverage_notice: None,
        question: None,
    }
}

#[tokio::test]
async fn executes_inspect_change_verify_report_loop() {
    let inspect = ToolCall {
        call_id: "inspect".into(),
        tool_id: "runtime_status".into(),
        purpose: "Read the current configuration and process state.".into(),
        input: json!({"runtime_ref": "runtime://one"}),
    };
    let change = ToolCall {
        call_id: "change".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the configured default model.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let verify = ToolCall {
        call_id: "verify".into(),
        tool_id: "runtime_status".into(),
        purpose: "Independently read the state after the effect.".into(),
        input: json!({"runtime_ref": "runtime://one"}),
    };
    let mut turn = request("Change the runtime model and verify it end to end.");
    turn.effect_authorizations.push(EffectAuthorization {
        approval_ref: "approval://runtime-change".into(),
        tenant_id: turn.tenant_id.clone(),
        request_id: turn.request_id.clone(),
        thread_ref: turn.thread_ref.clone(),
        actor_ref: turn.actor_ref.clone(),
        tool_id: change.tool_id.clone(),
        input_digest: change.input_digest(),
    });
    let model = scripted(
        ExecutionLane::Act,
        VecDeque::from([
            ModelDecision::InvokeTool {
                call: inspect.clone(),
            },
            ModelDecision::InvokeTool {
                call: change.clone(),
            },
            ModelDecision::InvokeTool {
                call: verify.clone(),
            },
            ModelDecision::Finish {
                draft: final_draft(),
            },
        ]),
    );
    let tools = ScriptedTools {
        descriptors: vec![
            tool(
                "runtime_status",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            tool(
                "runtime_config_update",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
        ],
        results: Mutex::new(BTreeMap::from([
            (
                inspect.call_id,
                success(
                    "Read the current runtime.",
                    evidence("evidence://before", "The prior model was configured."),
                ),
            ),
            (
                change.call_id,
                success(
                    "Updated the runtime configuration.",
                    evidence("evidence://effect", "The configuration write was accepted."),
                ),
            ),
            (
                verify.call_id,
                success(
                    "Read the runtime after the update.",
                    evidence(
                        "evidence://after",
                        "The new configuration is present; the process restart is pending.",
                    ),
                ),
            ),
        ])),
    };

    let outcome = run_turn(&model, &tools, turn).await.unwrap();
    let AgentTurnOutcome::Delivered {
        lane,
        markdown,
        tool_call_count,
        ..
    } = outcome
    else {
        panic!("expected a delivered answer");
    };
    assert_eq!(lane, ExecutionLane::Act);
    assert_eq!(tool_call_count, 3);
    assert!(markdown.starts_with("**Runtime updated and verified**"));
    assert!(markdown.contains("**Checked**"));
    assert!(markdown.contains("**Changed**"));
    assert!(markdown.contains("**Verified**"));
    assert!(markdown.contains("**Current state**"));
    assert!(markdown.contains("**Next**"));
    assert!(!markdown.contains("Cypher"));
}

#[tokio::test]
async fn requests_exact_approval_before_an_effect() {
    let change = ToolCall {
        call_id: "change".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the runtime configuration.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let model = scripted(
        ExecutionLane::Act,
        VecDeque::from([ModelDecision::InvokeTool {
            call: change.clone(),
        }]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_config_update",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        )],
        results: Mutex::new(BTreeMap::new()),
    };

    let outcome = run_turn(
        &model,
        &tools,
        request("Change the runtime model and verify it."),
    )
    .await
    .unwrap();
    let AgentTurnOutcome::ApprovalRequired { request, .. } = outcome else {
        panic!("expected exact approval request");
    };
    assert_eq!(request.tool_id, change.tool_id);
    assert_eq!(request.input_digest, change.input_digest());
}

#[tokio::test]
async fn rejects_an_approval_bound_to_another_actor_and_thread() {
    let change = ToolCall {
        call_id: "change".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the runtime configuration.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let mut turn = request("Change the runtime model and verify it.");
    turn.effect_authorizations.push(EffectAuthorization {
        approval_ref: "approval://wrong-principal".into(),
        tenant_id: turn.tenant_id.clone(),
        request_id: turn.request_id.clone(),
        thread_ref: "thread-other".into(),
        actor_ref: "actor-other".into(),
        tool_id: change.tool_id.clone(),
        input_digest: change.input_digest(),
    });
    let model = scripted(
        ExecutionLane::Act,
        VecDeque::from([ModelDecision::InvokeTool {
            call: change.clone(),
        }]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_config_update",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        )],
        results: Mutex::new(BTreeMap::new()),
    };

    let outcome = run_turn(&model, &tools, turn).await.unwrap();
    assert!(matches!(outcome, AgentTurnOutcome::ApprovalRequired { .. }));
}

#[tokio::test]
async fn consumes_each_effect_authorization_once() {
    let first = ToolCall {
        call_id: "change-1".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the runtime configuration.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let second = ToolCall {
        call_id: "change-2".into(),
        ..first.clone()
    };
    let mut turn = request("Change the runtime model and verify it.");
    turn.effect_authorizations.push(EffectAuthorization {
        approval_ref: "approval://runtime-change".into(),
        tenant_id: turn.tenant_id.clone(),
        request_id: turn.request_id.clone(),
        thread_ref: turn.thread_ref.clone(),
        actor_ref: turn.actor_ref.clone(),
        tool_id: first.tool_id.clone(),
        input_digest: first.input_digest(),
    });
    let model = scripted(
        ExecutionLane::Act,
        VecDeque::from([
            ModelDecision::InvokeTool {
                call: first.clone(),
            },
            ModelDecision::InvokeTool {
                call: second.clone(),
            },
        ]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_config_update",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        )],
        results: Mutex::new(BTreeMap::from([
            (
                first.call_id,
                success(
                    "Updated the runtime configuration.",
                    evidence("evidence://effect-1", "The first write was accepted."),
                ),
            ),
            (
                second.call_id,
                success(
                    "Updated the runtime configuration again.",
                    evidence("evidence://effect-2", "The second write was accepted."),
                ),
            ),
        ])),
    };

    assert_eq!(
        run_turn(&model, &tools, turn).await,
        Err(AgentRuntimeError::InvalidToolCall(
            "effect authorization was already consumed".into()
        ))
    );
}

#[tokio::test]
async fn rejects_effect_claims_without_later_independent_verification() {
    let change = ToolCall {
        call_id: "change".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the runtime configuration.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let mut turn = request("Change the runtime model.");
    turn.effect_authorizations.push(EffectAuthorization {
        approval_ref: "approval://runtime-change".into(),
        tenant_id: turn.tenant_id.clone(),
        request_id: turn.request_id.clone(),
        thread_ref: turn.thread_ref.clone(),
        actor_ref: turn.actor_ref.clone(),
        tool_id: change.tool_id.clone(),
        input_digest: change.input_digest(),
    });
    let mut draft = final_draft();
    draft.summary_evidence_refs = vec!["evidence://effect".into()];
    draft.checked.clear();
    draft.verified = vec![claim(
        "The effect provider said the write succeeded.",
        "evidence://effect",
    )];
    draft.current_state.clear();
    let model = scripted(
        ExecutionLane::Act,
        tool_then_repeat_draft(change.clone(), draft),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_config_update",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        )],
        results: Mutex::new(BTreeMap::from([(
            change.call_id,
            success(
                "Updated the runtime configuration.",
                evidence("evidence://effect", "The write was accepted."),
            ),
        )])),
    };

    assert_eq!(
        run_turn(&model, &tools, turn).await,
        Err(AgentRuntimeError::OperatingRepairLimit)
    );
}

#[tokio::test]
async fn stops_and_reconciles_outcome_unknown_without_retrying() {
    let effect = ToolCall {
        call_id: "effect".into(),
        tool_id: "runtime_config_update".into(),
        purpose: "Update the runtime configuration.".into(),
        input: json!({"runtime_ref": "runtime://one", "model": "model://next"}),
    };
    let mut turn = request("Change the runtime model.");
    turn.effect_authorizations.push(EffectAuthorization {
        approval_ref: "approval://runtime-change".into(),
        tenant_id: turn.tenant_id.clone(),
        request_id: turn.request_id.clone(),
        thread_ref: turn.thread_ref.clone(),
        actor_ref: turn.actor_ref.clone(),
        tool_id: effect.tool_id.clone(),
        input_digest: effect.input_digest(),
    });
    let model = scripted(
        ExecutionLane::Act,
        VecDeque::from([
            ModelDecision::InvokeTool {
                call: effect.clone(),
            },
            ModelDecision::InvokeTool {
                call: effect.clone(),
            },
        ]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_config_update",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        )],
        results: Mutex::new(BTreeMap::from([(
            effect.call_id,
            ToolResult {
                state: ToolResultState::OutcomeUnknown,
                summary: "The provider connection ended before a receipt was returned.".into(),
                data: json!({}),
                evidence: vec![evidence(
                    "evidence://uncertain-effect",
                    "The effect request was transmitted but no terminal receipt was observed.",
                )],
                blocker: Some("The effect may have happened, so retry is unsafe.".into()),
            },
        )])),
    };

    let outcome = run_turn(&model, &tools, turn).await.unwrap();
    let AgentTurnOutcome::Delivered {
        final_state,
        markdown,
        tool_call_count,
        ..
    } = outcome
    else {
        panic!("expected blocked delivered result");
    };
    assert_eq!(final_state, FinalState::Blocked);
    assert_eq!(tool_call_count, 1);
    assert!(markdown.contains("Outcome not confirmed"));
    assert!(markdown.contains("Reconcile"));
}

#[tokio::test]
async fn rejects_final_claims_that_cite_unobserved_evidence() {
    let lookup = ToolCall {
        call_id: "lookup".into(),
        tool_id: "runtime_status".into(),
        purpose: "Read the current runtime.".into(),
        input: json!({"runtime_ref": "runtime://one"}),
    };
    let draft = FinalDraft {
        state: FinalState::Answered,
        headline: "Runtime checked".into(),
        summary: "The runtime is healthy.".into(),
        summary_evidence_refs: vec!["evidence://invented".into()],
        checked: vec![claim("The runtime is healthy.", "evidence://invented")],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: None,
        question: None,
    };
    let model = scripted(
        ExecutionLane::Lookup,
        tool_then_repeat_draft(lookup.clone(), draft),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_status",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(BTreeMap::from([(
            lookup.call_id,
            success(
                "Read the current runtime.",
                evidence("evidence://actual", "The runtime returned a status record."),
            ),
        )])),
    };

    assert_eq!(
        run_turn(&model, &tools, request("What is the runtime status?")).await,
        Err(AgentRuntimeError::OperatingRepairLimit)
    );
}

#[tokio::test]
async fn refuses_to_present_stale_evidence_as_current() {
    let lookup = ToolCall {
        call_id: "lookup".into(),
        tool_id: "runtime_status".into(),
        purpose: "Read the current runtime.".into(),
        input: json!({"runtime_ref": "runtime://one"}),
    };
    let draft = FinalDraft {
        state: FinalState::Answered,
        headline: "Runtime checked".into(),
        summary: "The runtime is healthy.".into(),
        summary_evidence_refs: vec!["evidence://stale".into()],
        checked: vec![claim("The runtime is healthy.", "evidence://stale")],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: None,
        question: None,
    };
    let model = scripted(
        ExecutionLane::Lookup,
        tool_then_repeat_draft(lookup.clone(), draft),
    );
    let mut stale = evidence(
        "evidence://stale",
        "The runtime returned a healthy status record.",
    );
    stale.fresh_until = Some("2026-07-29T20:00:30Z".into());
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_status",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(BTreeMap::from([(
            lookup.call_id,
            success("Read the current runtime.", stale),
        )])),
    };

    assert_eq!(
        run_turn(&model, &tools, request("What is the runtime status?")).await,
        Err(AgentRuntimeError::OperatingRepairLimit)
    );
}

#[tokio::test]
async fn repairs_a_schema_valid_but_unsafe_route_before_operating() {
    let draft = FinalDraft {
        state: FinalState::Blocked,
        headline: "Current evidence is unavailable".into(),
        summary: "The runtime cannot be assessed without a current observation.".into(),
        summary_evidence_refs: vec![],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec!["Restore the runtime observation source.".into()],
        coverage_notice: Some("No current runtime evidence was available.".into()),
        question: None,
    };
    let model = ScriptedModel {
        routes: Mutex::new(VecDeque::from([
            RouteDecision {
                lane: ExecutionLane::Converse,
                confidence: RouteConfidence::Low,
                reason: "The request sounds conversational.".into(),
                requires_current_evidence: true,
            },
            route(ExecutionLane::Investigate),
        ])),
        decisions: Mutex::new(VecDeque::from([ModelDecision::Finish { draft }])),
        critiques: Mutex::new(VecDeque::new()),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { lane, .. } = run_turn(
        &model,
        &tools,
        request("Tell me what happened with the connector after yesterday's rollout."),
    )
    .await
    .unwrap() else {
        panic!("expected the repaired route to run");
    };
    assert_eq!(lane, ExecutionLane::Investigate);
}

#[tokio::test]
async fn repairs_a_draft_after_independent_critique() {
    let first = FinalDraft {
        state: FinalState::Answered,
        headline: "Cerebro capabilities".into(),
        summary: "I can inspect current security state.".into(),
        summary_evidence_refs: vec![],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: None,
        question: None,
    };
    let mut repaired = first.clone();
    repaired.summary =
        "I can inspect governed security state and report explicit evidence gaps.".into();
    let model = ScriptedModel {
        routes: Mutex::new(VecDeque::from([route(ExecutionLane::Converse)])),
        decisions: Mutex::new(VecDeque::from([
            ModelDecision::Finish { draft: first },
            ModelDecision::Finish { draft: repaired },
        ])),
        critiques: Mutex::new(VecDeque::from([
            CritiqueDecision::Revise {
                issues: vec!["Name the evidence boundary in the capability statement.".into()],
            },
            CritiqueDecision::Approve,
        ])),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } =
        run_turn(&model, &tools, request("What can you do?"))
            .await
            .unwrap()
    else {
        panic!("expected the repaired draft");
    };
    assert!(markdown.contains("explicit evidence gaps"));
}

#[tokio::test]
async fn repairs_a_malformed_operating_decision_without_weakening_the_schema() {
    let model = SchemaRepairModel {
        attempts: Mutex::new(0),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } =
        run_turn(&model, &tools, request("What can you do?"))
            .await
            .unwrap()
    else {
        panic!("expected the repaired operating decision");
    };
    assert!(markdown.contains("security operations concepts"));
    assert_eq!(*model.attempts.lock().unwrap(), 2);
}

#[tokio::test]
async fn repairs_a_malformed_independent_critic_decision() {
    let model = CriticSchemaRepairModel {
        attempts: Mutex::new(0),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } = run_turn(
        &model,
        &tools,
        request("What does evidence freshness mean?"),
    )
    .await
    .unwrap() else {
        panic!("expected the repaired critic decision");
    };
    assert!(markdown.contains("observation window"));
    assert_eq!(*model.attempts.lock().unwrap(), 2);
}

#[tokio::test]
async fn continues_the_exact_durable_mission_instead_of_restarting() {
    let mut turn = request("Keep going.");
    turn.working_state = Some(WorkingState {
        mission_ref: Some("mission://runtime-repair".into()),
        current_request: "Repair the runtime and verify the deployed state.".into(),
        last_outcome: WorkingOutcome::Owned,
        last_blocker: None,
    });
    let model = ScriptedModel {
        routes: Mutex::new(VecDeque::from([
            route(ExecutionLane::Continue),
            route(ExecutionLane::Act),
        ])),
        decisions: Mutex::new(VecDeque::from([ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Blocked,
                headline: "Runtime repair still blocked".into(),
                summary: "The saved repair remains blocked on provider access.".into(),
                summary_evidence_refs: vec![],
                checked: vec![],
                changed: vec![],
                verified: vec![],
                current_state: vec![],
                next_actions: vec!["Resume after provider access is restored.".into()],
                coverage_notice: Some("No new provider observation was available.".into()),
                question: None,
            },
        }])),
        critiques: Mutex::new(VecDeque::new()),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered {
        lane,
        final_state,
        markdown,
        ..
    } = run_turn(&model, &tools, turn).await.unwrap()
    else {
        panic!("expected the saved mission to resume");
    };
    assert_eq!(lane, ExecutionLane::Act);
    assert_eq!(final_state, FinalState::Blocked);
    assert!(markdown.contains("Runtime repair still blocked"));
}
