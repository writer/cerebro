use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

use async_trait::async_trait;
use cerebro_agent_runtime::{
    AGENT_TURN_REQUEST_V1, AgentModel, AgentRuntimeError, AgentTools, AgentTurnOutcome,
    AgentTurnRequest, ConversationMessage, ConversationRole, CritiqueChecks, CritiqueDecision,
    CritiqueTurn, EffectAuthorization, EvidenceClaim, EvidenceRecord, ExecutionLane, FinalDraft,
    FinalState, ModelDecision, ModelTurn, PresentationDecision, PresentationTurn, RouteConfidence,
    RouteDecision, RouteTurn, ToolAuthorityClass, ToolCall, ToolDescriptor, ToolEffectClass,
    ToolResult, ToolResultState, WorkingOutcome, WorkingState, run_turn,
};
use serde_json::json;

struct ScriptedModel {
    routes: Mutex<VecDeque<RouteDecision>>,
    decisions: Mutex<VecDeque<ModelDecision>>,
    presentations: Mutex<VecDeque<PresentationDecision>>,
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

    async fn present(
        &self,
        turn: PresentationTurn,
    ) -> Result<PresentationDecision, AgentRuntimeError> {
        Ok(self
            .presentations
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| PresentationDecision {
                messages: vec![turn.draft.summary],
            }))
    }

    async fn critique(&self, _turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        Ok(self
            .critiques
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(approved_critique))
    }
}

fn approved_critique() -> CritiqueDecision {
    CritiqueDecision::Approve {
        checks: CritiqueChecks {
            answers_newest_request: true,
            conversational: true,
            evidence_boundary_correct: true,
            no_raw_record_dump: true,
            operator_facing: true,
            owns_follow_through: true,
            right_sized: true,
        },
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
        presentations: Mutex::new(VecDeque::new()),
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

struct CriticIssueRepairModel {
    attempts: Mutex<usize>,
}

struct FinalLengthRepairModel {
    attempts: Mutex<usize>,
}

struct FinalHeadlineRepairModel {
    attempts: Mutex<usize>,
}

#[async_trait]
impl AgentModel for FinalHeadlineRepairModel {
    async fn route(&self, _turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        Ok(route(ExecutionLane::Lookup))
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        if *attempts == 1 {
            return Ok(ModelDecision::InvokeTool {
                call: ToolCall {
                    call_id: "headline-read".into(),
                    tool_id: "runtime_status".into(),
                    purpose: "Read the current runtime status.".into(),
                    input: json!({"runtime_ref": "runtime://headline"}),
                },
            });
        }
        if *attempts == 3 {
            assert!(turn.revision_feedback[0].contains("prior headline was 161 bytes"));
            assert!(turn.revision_feedback[0].contains("no longer than 160 bytes"));
        }
        Ok(ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Answered,
                headline: if *attempts == 2 {
                    "x".repeat(161)
                } else {
                    "Runtime status is current".into()
                },
                summary: "The runtime returned a current bounded status observation.".into(),
                summary_evidence_refs: vec!["evidence://headline".into()],
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

    async fn critique(&self, _turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        Ok(approved_critique())
    }
}

#[async_trait]
impl AgentModel for FinalLengthRepairModel {
    async fn route(&self, _turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        Ok(route(ExecutionLane::Converse))
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        let mut attempts = self.attempts.lock().unwrap();
        *attempts += 1;
        let summary = if *attempts == 1 {
            "x".repeat(2_501)
        } else {
            assert!(turn.revision_feedback[0].contains("prior summary was 2501 bytes"));
            assert!(turn.revision_feedback[0].contains("Rewrite it materially shorter"));
            "Owner: <provider admin>. Trigger: approved connector repair. Cerebro re-checks the receipt after the change. Acceptance: a fresh successful receipt with no unresolved gap."
                .into()
        };
        Ok(ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Answered,
                headline: "Connector handoff".into(),
                summary,
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

    async fn critique(&self, _turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        Ok(approved_critique())
    }
}

#[async_trait]
impl AgentModel for CriticIssueRepairModel {
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
        match *attempts {
            1 => Ok(CritiqueDecision::Revise { issues: vec![] }),
            2 => {
                assert!(turn.repair_feedback[0].contains("bounded critic contract"));
                Ok(CritiqueDecision::Revise {
                    issues: (0..17)
                        .map(|index| format!("Bounded critic issue {index}"))
                        .collect(),
                })
            }
            _ => {
                assert!(turn.repair_feedback[0].contains("bounded critic contract"));
                Ok(approved_critique())
            }
        }
    }
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
        Ok(approved_critique())
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

    async fn critique(&self, _turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        Ok(approved_critique())
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

#[tokio::test]
async fn conversational_artifact_edits_do_not_require_system_evidence() {
    let draft = FinalDraft {
        state: FinalState::Answered,
        headline: String::new(),
        summary: "Owner: <named provider admin> — please confirm. Cerebro owns the fresh receipt check after the provider change.".into(),
        summary_evidence_refs: vec!["evidence://history-only".into()],
        checked: vec![],
        changed: vec![claim(
            "The requested owner lines were added to the conversational artifact.",
            "evidence://history-only",
        )],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: Some("No new tool observation was required for this text edit.".into()),
        question: None,
    };
    let model = scripted(
        ExecutionLane::Converse,
        VecDeque::from([ModelDecision::Finish { draft }]),
    );
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } = run_turn(
        &model,
        &tools,
        request("Add the owner placeholder and our re-check responsibility to the handoff."),
    )
    .await
    .unwrap() else {
        panic!("expected a delivered artifact edit")
    };

    assert!(markdown.contains("Owner: <named provider admin>"));
    assert!(!markdown.contains("No new tool observation"));
}

#[tokio::test]
async fn oversized_final_receives_precise_length_feedback_and_repairs() {
    let model = FinalLengthRepairModel {
        attempts: Mutex::new(0),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } = run_turn(
        &model,
        &tools,
        request("Finalize the approved connector handoff for Slack."),
    )
    .await
    .unwrap() else {
        panic!("expected a repaired handoff")
    };

    assert!(markdown.starts_with("Owner: <provider admin>."));
    assert!(markdown.len() < 1_800);
}

#[tokio::test]
async fn oversized_headline_receives_precise_length_feedback_and_repairs() {
    let model = FinalHeadlineRepairModel {
        attempts: Mutex::new(0),
    };
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_status",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(BTreeMap::from([(
            "headline-read".into(),
            success(
                "The runtime returned current status.",
                evidence("evidence://headline", "The runtime status is current."),
            ),
        )])),
    };

    let AgentTurnOutcome::Delivered {
        markdown,
        tool_call_count,
        ..
    } = run_turn(&model, &tools, request("Read the current runtime status."))
        .await
        .unwrap()
    else {
        panic!("expected a repaired grounded answer")
    };

    assert_eq!(tool_call_count, 1);
    assert_eq!(
        markdown,
        "The runtime returned a current bounded status observation."
    );
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
    assert_eq!(
        markdown,
        "The requested runtime change is active. One process restart remains pending."
    );
    assert!(!markdown.contains("Checked"));
    assert!(!markdown.contains("Current state"));
    assert!(!markdown.contains("Cypher"));
}

#[tokio::test]
async fn repairs_a_raw_catalog_dump_into_a_direct_capability_answer() {
    let search = ToolCall {
        call_id: "source-search".into(),
        tool_id: "graph_search".into(),
        purpose: "Inspect the governed evidence available for the named source.".into(),
        input: json!({"query": "Source A", "limit": 25}),
    };
    let raw = FinalDraft {
        state: FinalState::Answered,
        headline: "Source entities summary".into(),
        summary: [
            "# Source Entities Summary",
            "| Source | URN |",
            "|---|---|",
            "| Directory | urn:cerebro:example:source:directory |",
            "| Audit | urn:cerebro:example:source:audit |",
        ]
        .join("\n"),
        summary_evidence_refs: vec!["evidence://source-a".into()],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: None,
        question: None,
    };
    let repaired = FinalDraft {
        state: FinalState::Partial,
        headline: "Source visibility is metadata-backed".into(),
        summary: "I can inspect Source A records that have been collected into Cerebro, including the returned directory and audit evidence. I do not have direct administrative access to Source A from this evidence, and this bounded result does not prove complete source coverage.".into(),
        summary_evidence_refs: vec!["evidence://source-a".into()],
        checked: vec![claim(
            "The bounded source search returned directory and audit evidence.",
            "evidence://source-a",
        )],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: Some(
            "The bounded result does not establish complete source coverage.".into(),
        ),
        question: None,
    };
    let model = scripted(
        ExecutionLane::Lookup,
        VecDeque::from([
            ModelDecision::InvokeTool {
                call: search.clone(),
            },
            ModelDecision::Finish { draft: raw },
            ModelDecision::Finish { draft: repaired },
        ]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "graph_search",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(BTreeMap::from([(
            search.call_id,
            ToolResult {
                state: ToolResultState::Partial,
                summary: "Found bounded evidence for Source A.".into(),
                data: json!({
                    "records": [
                        {"kind": "directory"},
                        {"kind": "audit"}
                    ],
                    "truncated": true
                }),
                evidence: vec![evidence(
                    "evidence://source-a",
                    "The bounded source search returned directory and audit evidence.",
                )],
                blocker: Some("Additional matching records were outside the bounded read.".into()),
            },
        )])),
    };

    let AgentTurnOutcome::Delivered {
        markdown,
        final_state,
        ..
    } = run_turn(
        &model,
        &tools,
        request("What visibility and access do you have for Source A?"),
    )
    .await
    .unwrap()
    else {
        panic!("expected a delivered capability answer");
    };
    assert_eq!(final_state, FinalState::Partial);
    assert!(markdown.starts_with("I can inspect Source A records"));
    assert!(markdown.contains("do not have direct administrative access"));
    assert!(!markdown.contains("urn:cerebro:"));
    assert!(!markdown.contains("|---"));
}

#[tokio::test]
async fn presents_completed_work_as_a_conversational_slack_reply() {
    let draft = FinalDraft {
        state: FinalState::Answered,
        headline: "Control evidence approach".into(),
        summary: "## Checked\nThe control and evidence boundaries are understood.".into(),
        summary_evidence_refs: vec![],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: None,
        question: None,
    };
    let model = ScriptedModel {
        routes: Mutex::new(VecDeque::from([route(ExecutionLane::Converse)])),
        decisions: Mutex::new(VecDeque::from([ModelDecision::Finish { draft }])),
        presentations: Mutex::new(VecDeque::from([
            PresentationDecision {
                messages: vec![
                    "## Evidence\nThe control and evidence boundaries are understood.".into(),
                ],
            },
            PresentationDecision {
                messages: vec!["I can build that lineage. Let me know if you want me to continue.".into()],
            },
            PresentationDecision {
                messages: vec!["The right way to approach this is to build one lineage per control, then compare expected evidence with what the systems actually produce and what the auditor tested.".into()],
            },
        ])),
        critiques: Mutex::new(VecDeque::new()),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } = run_turn(
        &model,
        &tools,
        request("How should I build a control-to-evidence lineage map?"),
    )
    .await
    .unwrap() else {
        panic!("expected a conversational presentation");
    };
    assert!(markdown.starts_with("The right way to approach this"));
    assert!(!markdown.contains("##"));
    assert!(!markdown.contains("Checked"));
}

#[tokio::test]
async fn repairs_internal_query_refusals_into_an_operator_facing_boundary() {
    let lookup = ToolCall {
        call_id: "graph-reason".into(),
        tool_id: "graph_reason".into(),
        purpose: "Inspect current graph evidence for the request.".into(),
        input: json!({"question": "Continue the current analysis."}),
    };
    let leaked = FinalDraft {
        state: FinalState::Blocked,
        headline: "Graph query blocked".into(),
        summary:
            "row-expanding Cypher expressions such as UNWIND, range(), and collect() are forbidden"
                .into(),
        summary_evidence_refs: vec![],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: Some("The read-only Cypher validator refused the draft.".into()),
        question: None,
    };
    let repaired = FinalDraft {
        state: FinalState::Blocked,
        headline: "Current graph answer is unavailable".into(),
        summary: "I could not produce a grounded graph answer for this request. The other bounded evidence capabilities remain available, so the investigation should continue there instead of treating this failed read as a result.".into(),
        summary_evidence_refs: vec![],
        checked: vec![],
        changed: vec![],
        verified: vec![],
        current_state: vec![],
        next_actions: vec![],
        coverage_notice: Some(
            "No source-backed graph observation supports the requested conclusion yet.".into(),
        ),
        question: None,
    };
    let model = scripted(
        ExecutionLane::Investigate,
        VecDeque::from([
            ModelDecision::InvokeTool {
                call: lookup.clone(),
            },
            ModelDecision::Finish { draft: leaked },
            ModelDecision::Finish { draft: repaired },
        ]),
    );
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "graph_reason",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(BTreeMap::from([(
            lookup.call_id,
            ToolResult {
                state: ToolResultState::Failed,
                summary: "Graph reasoning returned a blocked result.".into(),
                data: json!({"state": "blocked", "reason_code": "validator_refusal"}),
                evidence: vec![],
                blocker: Some(
                    "Graph reasoning did not produce a grounded answer. Continue with other bounded evidence capabilities."
                        .into(),
                ),
            },
        )])),
    };

    let AgentTurnOutcome::Delivered { markdown, .. } =
        run_turn(&model, &tools, request("Continue the current analysis."))
            .await
            .unwrap()
    else {
        panic!("expected a delivered blocked boundary");
    };
    assert!(!markdown.contains("Cypher"));
    assert!(!markdown.contains("UNWIND"));
    assert!(markdown.contains("could not produce a grounded graph answer"));
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
        presentations: Mutex::new(VecDeque::new()),
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
        presentations: Mutex::new(VecDeque::new()),
        critiques: Mutex::new(VecDeque::from([
            CritiqueDecision::Revise {
                issues: vec!["Name the evidence boundary in the capability statement.".into()],
            },
            approved_critique(),
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
async fn repairs_empty_and_oversized_critic_issue_lists() {
    let model = CriticIssueRepairModel {
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
        panic!("expected the bounded critic decisions to be repaired");
    };
    assert!(markdown.contains("observation window"));
    assert_eq!(*model.attempts.lock().unwrap(), 3);
}

#[tokio::test]
async fn continues_the_exact_durable_mission_instead_of_restarting() {
    let mut turn = request("Keep going.");
    turn.working_state = Some(WorkingState {
        mission_ref: Some("mission://runtime-repair".into()),
        current_request: "Repair the runtime and verify the deployed state.".into(),
        last_outcome: WorkingOutcome::Owned,
        last_blocker: None,
        active_lane: Some(ExecutionLane::Act),
        requires_current_evidence: Some(true),
        open_loops: vec!["Verify the deployed state.".into()],
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
        presentations: Mutex::new(VecDeque::new()),
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
    assert!(markdown.contains("saved repair remains blocked"));
}

#[tokio::test]
async fn continuation_resumes_the_retained_conversation_lane_without_reads() {
    let mut turn = request("Go on.");
    turn.working_state = Some(WorkingState {
        mission_ref: Some("mission://handoff-draft".into()),
        current_request: "Rewrite the handoff as a concise teammate update.".into(),
        last_outcome: WorkingOutcome::Owned,
        last_blocker: None,
        active_lane: Some(ExecutionLane::Converse),
        requires_current_evidence: Some(false),
        open_loops: vec!["Finish the concise handoff.".into()],
    });
    let model = ScriptedModel {
        routes: Mutex::new(VecDeque::from([RouteDecision {
            lane: ExecutionLane::Continue,
            confidence: RouteConfidence::High,
            reason: "The user asked to resume the durable handoff draft.".into(),
            requires_current_evidence: false,
        }])),
        decisions: Mutex::new(VecDeque::from([ModelDecision::Finish {
            draft: FinalDraft {
                state: FinalState::Answered,
                headline: "Handoff finished".into(),
                summary: "The handoff now names the owner, trigger, and acceptance condition."
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
        }])),
        presentations: Mutex::new(VecDeque::new()),
        critiques: Mutex::new(VecDeque::new()),
    };
    let tools = ScriptedTools {
        descriptors: vec![],
        results: Mutex::new(BTreeMap::new()),
    };

    let AgentTurnOutcome::Delivered { lane, .. } = run_turn(&model, &tools, turn).await.unwrap()
    else {
        panic!("expected the conversational mission to resume")
    };
    assert_eq!(lane, ExecutionLane::Converse);
}

#[tokio::test]
async fn exhausted_tool_budget_forces_a_grounded_finish_instead_of_dropping_the_turn() {
    let calls = (1..=4)
        .map(|index| ToolCall {
            call_id: format!("lookup-{index}"),
            tool_id: "runtime_status".into(),
            purpose: format!("Read bounded status field {index}."),
            input: json!({"field": index}),
        })
        .collect::<Vec<_>>();
    let mut decisions = calls
        .iter()
        .cloned()
        .map(|call| ModelDecision::InvokeTool { call })
        .collect::<VecDeque<_>>();
    decisions.push_back(ModelDecision::Finish {
        draft: FinalDraft {
            state: FinalState::Partial,
            headline: "Bounded status collected".into(),
            summary:
                "Three bounded status fields were observed; the fourth remains a coverage gap."
                    .into(),
            summary_evidence_refs: vec!["evidence://status-1".into()],
            checked: vec![claim(
                "Three bounded status fields were observed.",
                "evidence://status-1",
            )],
            changed: vec![],
            verified: vec![],
            current_state: vec![],
            next_actions: vec!["Resolve the unobserved fourth field.".into()],
            coverage_notice: Some("The fourth field was outside the turn budget.".into()),
            question: None,
        },
    });
    let model = scripted(ExecutionLane::Lookup, decisions);
    let results = calls
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, call)| {
            (
                call.call_id.clone(),
                success(
                    "Returned one bounded status field.",
                    evidence(
                        &format!("evidence://status-{}", index + 1),
                        "The runtime returned one bounded status field.",
                    ),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let tools = ScriptedTools {
        descriptors: vec![tool(
            "runtime_status",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )],
        results: Mutex::new(results),
    };

    let AgentTurnOutcome::Delivered {
        final_state,
        tool_call_count,
        markdown,
        ..
    } = run_turn(&model, &tools, request("Read the bounded runtime status."))
        .await
        .unwrap()
    else {
        panic!("expected a grounded partial answer")
    };
    assert_eq!(final_state, FinalState::Partial);
    assert_eq!(tool_call_count, 3);
    assert!(markdown.contains("fourth remains a coverage gap"));
}
