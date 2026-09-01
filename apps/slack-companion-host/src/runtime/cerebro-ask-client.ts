export type AssistantTurnSourceGapState =
  | "busy"
  | "not_configured"
  | "not_found"
  | "timed_out"
  | "unauthorized"
  | "unavailable";

export interface CerebroAskResult {
  acceptedFollowupRef?: string;
  citationValidationPassed: boolean;
  deliveryAckRequired?: boolean;
  executionLane: "act" | "continue" | "converse" | "ignore" | "investigate" | "lookup";
  finalState?: "answered" | "blocked" | "needs_input" | "partial";
  followupOffer?: RustProactiveFollowupOffer;
  markdown: string;
  pendingApproval?: AgentApprovalRequest;
  safeRefusal: boolean;
  traceId?: string;
  workingState?: RustWorkingState;
}

export interface RustProactiveFollowupOffer {
  action: string;
  action_key: string;
  created_at: string;
  expires_at: string;
  grounding_refs: string[];
  offer_ref: string;
  schema_version: "proactive-followup-offer/v1";
  tenant_id: string;
  thread_ref: string;
  title: string;
  turn_ref: string;
}

export interface RustWakeExecutionReceipt {
  commitment_ref: string;
  request_id: string;
  schedule_generation: number;
  session_ref: string;
  state: "awaiting_delivery";
}

export interface RustAgentProgressUpdate {
  occurredAt: string;
  phase: "refining" | "scoping" | "working";
  sequence: number;
  status: string;
}

export interface RustWakeDeliveryLease {
  commitment_ref: string;
  delivery_attempt_ref: string;
  delivery_ref: string;
  fence: number;
  lease_expires_at: string;
  lease_owner: string;
  lease_token: string;
  payload_digest: string;
  request_id: string;
  schedule_generation: number;
  session_ref: string;
}

export interface RustPendingWakeDelivery {
  lease: RustWakeDeliveryLease;
  markdown: string;
  mode: "reconcile" | "send";
  tenant_id: string;
  thread_ref: string;
}

export interface AgentApprovalRequest {
  approvalRef: string;
  authority: AgentEffectAuthorityBinding;
  inputDigest: string;
  inputPreview?: string;
  purpose: string;
  toolId: string;
}

export interface AgentEffectAuthorityBinding {
  bindingDigest: string;
  evidenceDigest: string;
  evidenceRefs: string[];
  schemaVersion: "agent-effect-authority-binding/v1";
  targetRefs: string[];
  toolDefinitionDigest: string;
}

export interface CerebroAskHistoryMessage {
  actorRef?: string;
  content: string;
  messageRef?: string;
  receivedAt?: string;
  role: "assistant" | "user";
}

export interface CerebroAskClientOptions {
  agentRuntimeToken?: string;
  agentRuntimeUrl?: string;
  answerAuthority: SlackAnswerAuthorityPort;
  apiKey: string;
  baseUrl: string;
  fetchImpl?: typeof fetch;
  progressWatchdog?: {
    clock?: () => Date;
    heartbeatIntervalMs?: number;
    pollIntervalMs?: number;
    wait?: (milliseconds: number) => Promise<void>;
  };
  tenantId: string;
}

export class CerebroAskError extends Error {
  constructor(
    public readonly sourceState: AssistantTurnSourceGapState,
    message: string,
    public readonly turnCommitState: "not_committed" | "unknown" = "unknown",
  ) {
    super(message);
    this.name = "CerebroAskError";
  }
}

export class CerebroAnswerRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CerebroAnswerRejectedError";
  }
}

export class CerebroAskClient {
  private readonly fetchImpl: typeof fetch;
  private readonly progressClock: () => Date;
  private readonly progressHeartbeatIntervalMs: number;
  private readonly progressPollIntervalMs: number;
  private readonly progressWait: (milliseconds: number) => Promise<void>;

  constructor(private readonly options: CerebroAskClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.progressClock = options.progressWatchdog?.clock ?? (() => new Date());
    this.progressHeartbeatIntervalMs = positiveInterval(
      options.progressWatchdog?.heartbeatIntervalMs,
      30_000,
      "progress heartbeat interval",
    );
    this.progressPollIntervalMs = positiveInterval(
      options.progressWatchdog?.pollIntervalMs,
      750,
      "progress poll interval",
    );
    this.progressWait = options.progressWatchdog?.wait ?? delay;
  }

  get usesRustAgent(): boolean {
    return Boolean(this.options.agentRuntimeUrl);
  }

  async runAgentTurn(input: {
    actorRef: string;
    assessmentAt: string;
    contextScopeRef?: string;
    effectAuthorizations?: readonly AgentApprovalRequest[];
    followupAcceptance?: RustProactiveFollowupOffer;
    history?: readonly CerebroAskHistoryMessage[];
    question: string;
    requestId: string;
    signal: AbortSignal;
    threadRef: string;
    deadlineAt?: string;
    onProgress?: (update: RustAgentProgressUpdate) => Promise<void>;
    workingState?: {
      active_lane?: CerebroAskResult["executionLane"];
      current_request: string;
      last_blocker?: string;
      last_outcome: "blocked" | "completed" | "needs_user" | "owned" | "unknown";
      mission_ref: string;
      open_loops?: readonly string[];
      requires_current_evidence?: boolean;
    };
  }): Promise<CerebroAskResult> {
    if (!this.options.agentRuntimeUrl) {
      throw new CerebroAskError("not_configured", "The Rust agent runtime is not configured.");
    }
    const history = input.history ?? [];
    const attributedHistory = history.some((message) =>
      message.actorRef !== undefined
      || message.messageRef !== undefined
      || message.receivedAt !== undefined
    );
    let turnComplete = false;
    const progressTask = input.onProgress
      ? this.followAgentTurnProgress(input, () => turnComplete)
      : undefined;
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.options.agentRuntimeUrl}/v1/turns/run`, {
      method: "POST",
      headers: {
        ...this.agentRuntimeHeaders(true),
      },
      body: JSON.stringify({
        actor_ref: input.actorRef,
        assessment_at: input.assessmentAt,
        ...(input.contextScopeRef === undefined
          ? {}
          : { context_scope_ref: input.contextScopeRef }),
        effect_authorizations: (input.effectAuthorizations ?? []).map((authorization) => ({
          actor_ref: input.actorRef,
          approval_ref: authorization.approvalRef,
          input_digest: authorization.inputDigest,
          request_id: input.requestId,
          tenant_id: this.options.tenantId,
          thread_ref: input.threadRef,
          tool_id: authorization.toolId,
        })),
        capabilities: ["proactive_followup_offer/v1"],
        ...(input.followupAcceptance === undefined
          ? {}
          : {
              followup_acceptance: {
                offer: input.followupAcceptance,
                schema_version: "proactive-followup-acceptance/v1",
              },
            }),
        history: history.map(({ content, role }) => ({ content, role })),
        ...(attributedHistory
          ? {
              history_metadata: history.map((message) => ({
                ...(message.actorRef === undefined
                  ? {}
                  : { actor_ref: message.actorRef }),
                ...(message.messageRef === undefined
                  ? {}
                  : { message_ref: message.messageRef }),
                ...(message.receivedAt === undefined
                  ? {}
                  : { received_at: message.receivedAt }),
              })),
            }
          : {}),
        message: input.question,
        request_id: input.requestId,
        schema_version: "agent-turn-request/v1",
        tenant_id: this.options.tenantId,
        thread_ref: input.threadRef,
        working_state: input.workingState ?? null,
      }),
      signal: input.signal,
      }).catch((error: unknown) => {
        if (input.signal.aborted) {
          throw new CerebroAskError("timed_out", "The Rust agent did not finish before the turn deadline.");
        }
        throw new CerebroAskError("unavailable", errorMessage(error));
      });
    } finally {
      turnComplete = true;
      await progressTask;
    }
    if (!response.ok) {
      let turnCommitState: CerebroAskError["turnCommitState"] = "unknown";
      try {
        const failure = await response.clone().json() as { code?: unknown };
        if (failure.code === "followup_acceptance_not_committed") {
          turnCommitState = "not_committed";
        }
      } catch {
        // An intermediary or malformed response cannot prove whether Rust committed.
      }
      throw new CerebroAskError(
        response.status === 409 ? "busy" : sourceState(response.status),
        `The Rust agent failed with status ${response.status}.`,
        turnCommitState,
      );
    }
    let outcome: RustAgentTurnOutcome;
    try {
      outcome = await response.json() as RustAgentTurnOutcome;
    } catch (error: unknown) {
      if (input.signal.aborted) {
        throw new CerebroAskError(
          "timed_out",
          "The Rust agent did not finish before the turn deadline.",
        );
      }
      throw new CerebroAskError("unavailable", errorMessage(error));
    }
    if (outcome.outcome === "delivered" || outcome.outcome === "pending_delivery") {
      return {
        ...(outcome.accepted_followup_ref == null
          ? {}
          : { acceptedFollowupRef: outcome.accepted_followup_ref }),
        citationValidationPassed:
          outcome.final_state === "answered"
          && outcome.evidence_refs.length > 0,
        executionLane: outcome.lane,
        ...(outcome.outcome === "pending_delivery"
          ? { deliveryAckRequired: true }
          : {}),
        finalState: outcome.final_state,
        ...(outcome.proactive_followup_offer == null
          ? {}
          : {
              followupOffer: parseProactiveFollowupOffer(
                outcome.proactive_followup_offer,
                this.options.tenantId,
                input.threadRef,
              ),
            }),
        markdown: outcome.markdown,
        safeRefusal: outcome.final_state !== "answered",
        traceId: input.requestId,
        ...(outcome.working_state == null
          ? {}
          : { workingState: outcome.working_state }),
      };
    }
    if (outcome.outcome === "approval_required") {
      const approvalCode = approvalCommandCode(outcome.request.approval_ref);
      return {
        citationValidationPassed: false,
        executionLane: outcome.lane,
        finalState: "needs_input",
        markdown: [
          "**Approval required**",
          "",
          outcome.request.purpose,
          "",
          `Canonical targets: ${outcome.request.authority.target_refs.join(", ")}`,
          `Fresh evidence: ${outcome.request.authority.evidence_refs.join(", ")}`,
          `Authority binding: ${outcome.request.authority.binding_digest}`,
          "",
          `Exact input (${outcome.request.input_digest}):`,
          "```",
          safeApprovalPreview(outcome.request.input_preview),
          "```",
          "Sensitive fields are redacted here but remain included in the approved digest.",
          "",
          `To run the exact ${outcome.request.tool_id} operation, reply \`approve ${approvalCode}\`.`,
        ].join("\n"),
        pendingApproval: {
          approvalRef: outcome.request.approval_ref,
          authority: {
            bindingDigest: outcome.request.authority.binding_digest,
            evidenceDigest: outcome.request.authority.evidence_digest,
            evidenceRefs: outcome.request.authority.evidence_refs,
            schemaVersion: outcome.request.authority.schema_version,
            targetRefs: outcome.request.authority.target_refs,
            toolDefinitionDigest: outcome.request.authority.tool_definition_digest,
          },
          inputDigest: outcome.request.input_digest,
          inputPreview: outcome.request.input_preview,
          purpose: outcome.request.purpose,
          toolId: outcome.request.tool_id,
        },
        safeRefusal: true,
        traceId: input.requestId,
      };
    }
    return {
      citationValidationPassed: false,
      executionLane: "ignore",
      finalState: "needs_input",
      markdown: "Ask a concrete question or assign a bounded task.",
      safeRefusal: true,
      traceId: input.requestId,
    };
  }

  private async followAgentTurnProgress(
    input: {
      deadlineAt?: string;
      onProgress?: (update: RustAgentProgressUpdate) => Promise<void>;
      requestId: string;
      signal: AbortSignal;
      threadRef: string;
    },
    turnComplete: () => boolean,
  ): Promise<void> {
    if (!this.options.agentRuntimeUrl || !input.onProgress) return;
    let afterSequence = 0;
    let lastStatus = "";
    const startedAt = this.progressClock();
    let lastVisibleProgressAt = startedAt;
    const poll = async (): Promise<void> => {
      const query = new URLSearchParams({
        after_sequence: String(afterSequence),
        request_id: input.requestId,
        thread_ref: input.threadRef,
      });
      const response = await this.fetchImpl(
        `${this.options.agentRuntimeUrl}/v1/turns/progress?${query}`,
        { headers: this.agentRuntimeHeaders(false), signal: input.signal },
      );
      if (!response.ok) return;
      const progress = parseAgentTurnProgress(await response.json());
      afterSequence = progress.latestSequence;
      let visibleProgress = false;
      for (const update of progress.updates) {
        if (update.status === lastStatus) continue;
        try {
          await input.onProgress?.(update);
          lastStatus = update.status;
          visibleProgress = true;
        } catch {
          // A failed progress edit must not discard the terminal answer.
        }
      }
      if (visibleProgress) {
        lastVisibleProgressAt = this.progressClock();
      }
    };
    const emitHeartbeatIfDue = async (): Promise<void> => {
      const observedAt = this.progressClock();
      if (
        observedAt.getTime() - lastVisibleProgressAt.getTime()
          >= this.progressHeartbeatIntervalMs
      ) {
        try {
          await input.onProgress?.({
            occurredAt: observedAt.toISOString(),
            phase: "working",
            sequence: afterSequence,
            status: progressHeartbeatStatus(startedAt, observedAt, input.deadlineAt),
          });
          lastVisibleProgressAt = observedAt;
        } catch {
          // A failed liveness edit must not discard the terminal answer.
        }
      }
    };
    while (!turnComplete() && !input.signal.aborted) {
      await this.progressWait(this.progressPollIntervalMs);
      if (turnComplete() || input.signal.aborted) break;
      try {
        await poll();
      } catch {
        // Progress polling is best-effort; the exact turn remains authoritative.
      }
      await emitHeartbeatIfDue();
    }
    if (!input.signal.aborted) {
      try {
        await poll();
      } catch {
        // The final response can still be delivered when progress is unavailable.
      }
    }
  }

  async recordAgentTurnDelivery(input: {
    deliveredAt: string;
    deliveryRef: string;
    payloadDigest: string;
    requestId: string;
    signal: AbortSignal;
    threadRef: string;
  }): Promise<void> {
    if (!this.options.agentRuntimeUrl) return;
    const response = await this.fetchImpl(
      `${this.options.agentRuntimeUrl}/v1/turns/deliveries`,
      {
        method: "POST",
        headers: {
          ...this.agentRuntimeHeaders(true),
        },
        body: JSON.stringify({
          delivered_at: input.deliveredAt,
          delivery_ref: input.deliveryRef,
          payload_digest: input.payloadDigest,
          request_id: input.requestId,
          schema_version: "agent-delivery-receipt/v1",
          tenant_id: this.options.tenantId,
          thread_ref: input.threadRef,
          transport: "slack",
        }),
        signal: input.signal,
      },
    ).catch((error: unknown) => {
      throw new CerebroAskError("unavailable", errorMessage(error));
    });
    if (!response.ok) {
      throw new CerebroAskError(
        sourceState(response.status),
        `The Rust agent rejected the Slack delivery receipt with status ${response.status}.`,
      );
    }
  }

  async runDueWake(input: {
    signal: AbortSignal;
    workerRef: string;
  }): Promise<RustWakeExecutionReceipt | undefined> {
    const runtimeUrl = this.requiredAgentRuntimeUrl();
    const response = await this.fetchImpl(`${runtimeUrl}/v1/wakes/run`, {
      method: "POST",
      headers: {
        ...this.agentRuntimeHeaders(true),
      },
      body: JSON.stringify({ worker_ref: input.workerRef }),
      signal: input.signal,
    }).catch((error: unknown) => {
      throw new CerebroAskError("unavailable", errorMessage(error));
    });
    if (!response.ok) {
      throw new CerebroAskError(
        sourceState(response.status),
        `The Rust wake executor failed with status ${response.status}.`,
      );
    }
    return parseWakeRunResponse(await response.json());
  }

  async claimPendingWakeDelivery(input: {
    signal: AbortSignal;
    workerRef: string;
  }): Promise<RustPendingWakeDelivery | undefined> {
    const runtimeUrl = this.requiredAgentRuntimeUrl();
    const response = await this.fetchImpl(
      `${runtimeUrl}/v1/wakes/pending-deliveries/claim`,
      {
        method: "POST",
        headers: {
          ...this.agentRuntimeHeaders(true),
        },
        body: JSON.stringify({ worker_ref: input.workerRef }),
        signal: input.signal,
      },
    ).catch((error: unknown) => {
      throw new CerebroAskError("unavailable", errorMessage(error));
    });
    if (!response.ok) {
      throw new CerebroAskError(
        sourceState(response.status),
        `The Rust wake delivery claim failed with status ${response.status}.`,
      );
    }
    return parseWakeDeliveryClaim(await response.json(), this.options.tenantId);
  }

  async recordWakeDelivery(input: {
    deliveredAt: string;
    delivery: RustPendingWakeDelivery;
    destinationReceipt: string;
    signal: AbortSignal;
  }): Promise<void> {
    const runtimeUrl = this.requiredAgentRuntimeUrl();
    const response = await this.fetchImpl(`${runtimeUrl}/v1/wakes/deliveries`, {
      method: "POST",
      headers: {
        ...this.agentRuntimeHeaders(true),
      },
      body: JSON.stringify({
        lease: input.delivery.lease,
        receipt: {
          delivered_at: input.deliveredAt,
          delivery_ref: input.destinationReceipt,
          payload_digest: input.delivery.lease.payload_digest,
          request_id: input.delivery.lease.request_id,
          schema_version: "agent-delivery-receipt/v1",
          tenant_id: input.delivery.tenant_id,
          thread_ref: input.delivery.thread_ref,
          transport: "slack",
        },
      }),
      signal: input.signal,
    }).catch((error: unknown) => {
      throw new CerebroAskError("unavailable", errorMessage(error));
    });
    if (!response.ok) {
      throw new CerebroAskError(
        sourceState(response.status),
        `The Rust wake delivery receipt failed with status ${response.status}.`,
      );
    }
  }

  private requiredAgentRuntimeUrl(): string {
    if (!this.options.agentRuntimeUrl) {
      throw new CerebroAskError("not_configured", "The Rust agent runtime is not configured.");
    }
    return this.options.agentRuntimeUrl;
  }

  private agentRuntimeHeaders(jsonBody: boolean): Record<string, string> {
    return {
      Accept: "application/json",
      ...(jsonBody ? { "Content-Type": "application/json" } : {}),
      ...(this.options.agentRuntimeToken === undefined
        ? {}
        : { Authorization: `Bearer ${this.options.agentRuntimeToken}` }),
    };
  }

  async ask(
    requestId: string,
    question: string,
    signal: AbortSignal,
    history: readonly CerebroAskHistoryMessage[] = [],
    authorizedQuestion?: SlackQuestionDecision,
  ): Promise<CerebroAskResult> {
    const questionDecision = authorizedQuestion
      ?? await this.authorizeQuestion(requestId, question, history);
    if (
      questionDecision.request_id !== requestId
      || questionDecision.tenant_id !== this.options.tenantId
    ) {
      throw new CerebroAskError(
        "unauthorized",
        "Rust Slack authority returned a decision for another question request.",
      );
    }
    if (questionDecision.execution_lane === "converse") {
      return {
        citationValidationPassed: false,
        executionLane: "converse",
        markdown: questionDecision.answer,
        safeRefusal: false,
      };
    }
    const response = await this.fetchImpl(`${this.options.baseUrl}/grc/ask`, {
      method: "POST",
      headers: {
        Accept: "text/event-stream",
        Authorization: `Bearer ${this.options.apiKey}`,
        "Content-Type": "application/json",
        "X-Cerebro-Tenant": this.options.tenantId,
      },
      body: JSON.stringify({
        ...(history.length === 0
          ? {}
          : {
              history: history.map(({ content, role }) => ({ content, role })),
            }),
        question,
        tenant_id: this.options.tenantId,
      }),
      signal,
    }).catch((error: unknown) => {
      if (signal.aborted) {
        throw new CerebroAskError("timed_out", "Cerebro did not answer before the turn deadline.");
      }
      throw new CerebroAskError("unavailable", errorMessage(error));
    });

    if (!response.ok || response.body === null) {
      throw new CerebroAskError(sourceState(response.status), `Cerebro ask failed with status ${response.status}.`);
    }

    let summary: Omit<SlackAnswerCandidate, "completed" | "schema_version" | "trace_id"> | undefined;
    let done = false;
    let traceId = "";
    try {
      for await (const event of readSse(response.body)) {
        if (event.name === "summary") {
          const markdown = text(event.data.markdown);
          if (markdown) {
            summary = {
              ...(citationValidation(event.data.citation_validation) === undefined
                ? {}
                : { citation_validation: citationValidation(event.data.citation_validation) }),
              markdown,
              ...(unsupportedQuery(event.data.unsupported_query) === undefined
                ? {}
                : { unsupported_query: unsupportedQuery(event.data.unsupported_query) }),
            };
          }
        }
        if (event.name === "done") {
          done = true;
          traceId = text(event.data.trace_id);
          break;
        }
        if (event.name === "error") {
          throw new CerebroAskError("unavailable", text(event.data.message) || "Cerebro could not complete the request.");
        }
      }
    } catch (error: unknown) {
      if (error instanceof CerebroAskError) throw error;
      if (signal.aborted || isAbortError(error)) {
        throw new CerebroAskError("timed_out", "Cerebro did not answer before the turn deadline.");
      }
      throw new CerebroAskError("unavailable", errorMessage(error));
    }
    if (!done || !summary || !traceId) {
      throw new CerebroAskError("unavailable", "Cerebro ended the response before a verified summary was available.");
    }
    let decision;
    try {
      decision = await this.options.answerAuthority.validate({
        ...summary,
        completed: true,
        schema_version: "slack-answer-candidate/v1",
        trace_id: traceId,
      });
    } catch (error: unknown) {
      if (error instanceof SlackAnswerAuthorityError && error.candidateRejected) {
        throw new CerebroAnswerRejectedError(error.message);
      }
      throw new CerebroAskError("unavailable", errorMessage(error));
    }
    return {
      citationValidationPassed: decision.verified,
      executionLane: "lookup",
      markdown: summary.markdown,
      safeRefusal: decision.disposition === "safe_refusal",
      traceId: decision.trace_id,
    };
  }

  async authorizeQuestion(
    requestId: string,
    question: string,
    history: readonly CerebroAskHistoryMessage[] = [],
  ): Promise<SlackQuestionDecision> {
    try {
      return await this.options.answerAuthority.authorizeQuestion({
        history: history.map(({ content, role }) => ({ content, role })),
        question,
        request_id: requestId,
        schema_version: "slack-question-candidate/v1",
        tenant_id: this.options.tenantId,
      });
    } catch (error: unknown) {
      throw new CerebroAskError("unauthorized", errorMessage(error));
    }
  }
}

type RustAgentTurnOutcome =
  | {
      accepted_followup_ref: string | null;
      evidence_refs: string[];
      final_state: "answered" | "blocked" | "needs_input" | "partial";
      proactive_followup_offer: unknown | null;
      lane: CerebroAskResult["executionLane"];
      markdown: string;
      outcome: "delivered" | "pending_delivery";
      working_state: RustWorkingState | null;
    }
  | {
      lane: "act";
      outcome: "approval_required";
      request: {
        approval_ref: string;
        authority: {
          binding_digest: string;
          evidence_digest: string;
          evidence_refs: string[];
          schema_version: "agent-effect-authority-binding/v1";
          target_refs: string[];
          tool_definition_digest: string;
        };
        input_digest: string;
        input_preview: string;
        purpose: string;
        tool_id: string;
      };
    }
  | {
      outcome: "ignored";
    };

function parseProactiveFollowupOffer(
  value: unknown,
  tenantId: string,
  threadRef: string,
): RustProactiveFollowupOffer {
  const offer = objectWithKeys(value, [
    "action",
    "action_key",
    "created_at",
    "expires_at",
    "grounding_refs",
    "offer_ref",
    "schema_version",
    "tenant_id",
    "thread_ref",
    "title",
    "turn_ref",
  ], "proactive follow-up offer");
  if (
    offer.schema_version !== "proactive-followup-offer/v1"
    || offer.tenant_id !== tenantId
    || offer.thread_ref !== threadRef
    || !/^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(text(offer.action_key))
    || !boundedText(offer.action, 512)
    || !/^proactive-followup:\/\/sha256\/[a-f0-9]{64}$/u.test(text(offer.offer_ref))
    || !boundedText(offer.title, 512)
    || !boundedText(offer.turn_ref, 2_048)
    || !text(offer.turn_ref).startsWith("agent-turn://")
    || text(offer.turn_ref).length === "agent-turn://".length
    || !canonicalTimestamp(offer.created_at)
    || !canonicalTimestamp(offer.expires_at)
    || Date.parse(String(offer.created_at)) >= Date.parse(String(offer.expires_at))
    || !Array.isArray(offer.grounding_refs)
    || offer.grounding_refs.length === 0
    || offer.grounding_refs.length > 16
    || offer.grounding_refs.some((reference) => !boundedText(reference, 2_048))
  ) {
    throw new CerebroAskError("unavailable", "The Rust proactive follow-up offer is invalid.");
  }
  return offer as unknown as RustProactiveFollowupOffer;
}

function parseAgentTurnProgress(value: unknown): {
  latestSequence: number;
  updates: RustAgentProgressUpdate[];
} {
  const progress = objectWithKeys(value, [
    "latest_sequence",
    "schema_version",
    "updates",
  ], "agent turn progress");
  if (
    progress.schema_version !== "agent-turn-progress/v1"
    || !Number.isSafeInteger(progress.latest_sequence)
    || Number(progress.latest_sequence) < 0
    || !Array.isArray(progress.updates)
  ) {
    throw new CerebroAskError("unavailable", "The Rust agent progress response is invalid.");
  }
  const updates = progress.updates.map((value) => {
    const update = objectWithKeys(value, [
      "occurred_at",
      "phase",
      "sequence",
      "status",
    ], "agent turn progress update");
    if (
      !canonicalTimestamp(update.occurred_at)
      || !["refining", "scoping", "working"].includes(String(update.phase))
      || !positiveInteger(update.sequence)
      || !text(update.status)
    ) {
      throw new CerebroAskError("unavailable", "A Rust agent progress update is invalid.");
    }
    return {
      occurredAt: String(update.occurred_at),
      phase: update.phase as RustAgentProgressUpdate["phase"],
      sequence: Number(update.sequence),
      status: String(update.status),
    };
  });
  return { latestSequence: Number(progress.latest_sequence), updates };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function positiveInterval(value: number | undefined, fallback: number, label: string): number {
  const interval = value ?? fallback;
  if (!Number.isSafeInteger(interval) || interval <= 0) {
    throw new TypeError(`The ${label} must be a positive integer.`);
  }
  return interval;
}

function progressHeartbeatStatus(
  startedAt: Date,
  observedAt: Date,
  deadlineAt?: string,
): string {
  const elapsedMs = Math.max(0, observedAt.getTime() - startedAt.getTime());
  const elapsed = progressDuration(elapsedMs);
  if (deadlineAt !== undefined) {
    const remainingMs = new Date(deadlineAt).getTime() - observedAt.getTime();
    if (Number.isFinite(remainingMs) && remainingMs > 0) {
      return `Still working — ${elapsed} elapsed. This turn will stop in ${progressDuration(remainingMs)} if it does not finish.`;
    }
  }
  return `Still working — ${elapsed} elapsed. This turn remains bounded by its deadline.`;
}

function progressDuration(milliseconds: number): string {
  const seconds = Math.max(1, Math.ceil(milliseconds / 1_000));
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes === 0) return `${seconds}s`;
  if (remainingSeconds === 0) return `${minutes}m`;
  return `${minutes}m ${remainingSeconds}s`;
}

function parseWakeRunResponse(value: unknown): RustWakeExecutionReceipt | undefined {
  const response = objectWithKeys(value, ["wake"], "wake execution response");
  if (response.wake === null) return undefined;
  const wake = objectWithKeys(response.wake, [
    "commitment_ref",
    "request_id",
    "schedule_generation",
    "session_ref",
    "state",
  ], "wake execution receipt");
  if (
    !text(wake.commitment_ref)
    || !text(wake.request_id)
    || !positiveInteger(wake.schedule_generation)
    || !text(wake.session_ref)
    || wake.state !== "awaiting_delivery"
  ) {
    throw new CerebroAskError("unavailable", "The Rust wake execution receipt is invalid.");
  }
  return wake as unknown as RustWakeExecutionReceipt;
}

function parseWakeDeliveryClaim(
  value: unknown,
  tenantId: string,
): RustPendingWakeDelivery | undefined {
  const response = objectWithKeys(value, ["delivery"], "wake delivery claim response");
  if (response.delivery === null) return undefined;
  const delivery = objectWithKeys(response.delivery, [
    "lease",
    "markdown",
    "mode",
    "tenant_id",
    "thread_ref",
  ], "wake delivery claim");
  const lease = objectWithKeys(delivery.lease, [
    "commitment_ref",
    "delivery_attempt_ref",
    "delivery_ref",
    "fence",
    "lease_expires_at",
    "lease_owner",
    "lease_token",
    "payload_digest",
    "request_id",
    "schedule_generation",
    "session_ref",
  ], "wake delivery lease");
  if (
    !text(lease.commitment_ref)
    || !/^wake-delivery-attempt:\/\/sha256\/[a-f0-9]{64}$/u.test(
      text(lease.delivery_attempt_ref),
    )
    || !/^wake-delivery:\/\/sha256\/[a-f0-9]{64}$/u.test(text(lease.delivery_ref))
    || !positiveInteger(lease.fence)
    || !canonicalTimestamp(lease.lease_expires_at)
    || !text(lease.lease_owner)
    || !/^wake-delivery-lease:\/\/sha256\/[a-f0-9]{64}$/u.test(text(lease.lease_token))
    || !/^sha256:[a-f0-9]{64}$/u.test(text(lease.payload_digest))
    || !text(lease.request_id)
    || !positiveInteger(lease.schedule_generation)
    || !text(lease.session_ref)
    || !text(delivery.markdown)
    || (delivery.mode !== "send" && delivery.mode !== "reconcile")
    || delivery.tenant_id !== tenantId
    || !/^slack-scratchpad:\/\/sha256\/[a-f0-9]{64}$/u.test(text(delivery.thread_ref))
  ) {
    throw new CerebroAskError("unavailable", "The Rust wake delivery claim is invalid.");
  }
  return {
    lease: lease as unknown as RustWakeDeliveryLease,
    markdown: text(delivery.markdown),
    mode: delivery.mode,
    tenant_id: delivery.tenant_id,
    thread_ref: delivery.thread_ref as string,
  };
}

function objectWithKeys(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())
  ) {
    throw new CerebroAskError("unavailable", `The Rust ${label} is invalid.`);
  }
  return value as Record<string, unknown>;
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function canonicalTimestamp(value: unknown): boolean {
  return typeof value === "string"
    && Number.isFinite(Date.parse(value))
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value);
}

function citationValidation(
  value: unknown,
): SlackAnswerCandidate["citation_validation"] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const validation = value as Record<string, unknown>;
  if (
    typeof validation.ok !== "boolean"
    || !nonNegativeInteger(validation.referenced_urn_count)
    || !nonNegativeInteger(validation.row_urn_count)
  ) {
    return undefined;
  }
  return {
    ok: validation.ok,
    referenced_urn_count: validation.referenced_urn_count,
    row_urn_count: validation.row_urn_count,
  };
}

export function approvalCommandCode(approvalRef: string): string {
  const suffix = approvalRef.split("/").at(-1)?.trim();
  if (!suffix || !/^[a-f0-9]{64}$/u.test(suffix)) {
    throw new CerebroAskError("unavailable", "The Rust agent returned an invalid approval identity.");
  }
  return suffix.slice(0, 12);
}

function safeApprovalPreview(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("`", "\\u0060");
}

interface RustWorkingState {
  active_lane?: Exclude<CerebroAskResult["executionLane"], "continue" | "ignore"> | null;
  current_request: string;
  last_blocker?: string | null;
  last_outcome: "blocked" | "completed" | "needs_user" | "owned" | "unknown";
  mission_ref?: string;
  open_loops?: string[];
  requires_current_evidence?: boolean | null;
}

function unsupportedQuery(
  value: unknown,
): SlackAnswerCandidate["unsupported_query"] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const refusal = value as Record<string, unknown>;
  const supportedIntents = stringArray(refusal.supported_intents);
  const suggestedRewrites = stringArray(refusal.suggested_rewrites);
  const code = text(refusal.code);
  const reason = text(refusal.reason);
  const traceId = text(refusal.trace_id);
  if (!code || !reason || !traceId || !supportedIntents || !suggestedRewrites) return undefined;
  return {
    code,
    reason,
    suggested_rewrites: suggestedRewrites,
    supported_intents: supportedIntents,
    trace_id: traceId,
  };
}

function stringArray(value: unknown): string[] | undefined {
  if (
    !Array.isArray(value)
    || value.some((item) => typeof item !== "string" || item.trim() === "")
  ) {
    return undefined;
  }
  return value.map((item) => (item as string).trim());
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

interface SseEvent {
  data: Record<string, unknown>;
  name: string;
}

async function* readSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let completed = false;
  try {
    while (true) {
      const next = await reader.read();
      buffer += decoder.decode(next.value, { stream: !next.done });
      let separator = separatorIndex(buffer);
      while (separator >= 0) {
        const block = buffer.slice(0, separator);
        buffer = buffer.slice(separator + (buffer[separator] === "\r" ? 4 : 2));
        const event = parseSseBlock(block);
        if (event) yield event;
        separator = separatorIndex(buffer);
      }
      if (next.done) break;
    }
    completed = true;
    const finalEvent = parseSseBlock(buffer);
    if (finalEvent) yield finalEvent;
  } finally {
    if (!completed) {
      await reader.cancel().catch(() => undefined);
    }
    reader.releaseLock();
  }
}

function separatorIndex(value: string): number {
  const crlf = value.indexOf("\r\n\r\n");
  const lf = value.indexOf("\n\n");
  if (crlf < 0) return lf;
  if (lf < 0) return crlf;
  return Math.min(crlf, lf);
}

function parseSseBlock(block: string): SseEvent | undefined {
  let name = "message";
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith("event:")) name = line.slice(6).trim();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (data.length === 0) return undefined;
  try {
    const decoded: unknown = JSON.parse(data.join("\n"));
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) return undefined;
    return { data: decoded as Record<string, unknown>, name };
  } catch {
    throw new CerebroAskError("unavailable", "Cerebro returned an invalid response event.");
  }
}

function sourceState(status: number): AssistantTurnSourceGapState {
  if (status === 401 || status === 403) return "unauthorized";
  if (status === 404) return "not_found";
  if (status === 408 || status === 504) return "timed_out";
  return "unavailable";
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function boundedText(value: unknown, maxBytes: number): value is string {
  return typeof value === "string"
    && Boolean(value.trim())
    && Buffer.byteLength(value, "utf8") <= maxBytes;
}

function errorMessage(value: unknown): string {
  return value instanceof Error && value.message
    ? value.message
    : "Cerebro is unavailable.";
}

function isAbortError(value: unknown): boolean {
  return value instanceof DOMException && (value.name === "AbortError" || value.name === "TimeoutError");
}
import {
  SlackAnswerAuthorityError,
  type SlackAnswerAuthorityPort,
  type SlackAnswerCandidate,
  type SlackQuestionDecision,
} from "./slack-answer-authority-client.js";
