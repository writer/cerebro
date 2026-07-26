import {
  Agent,
  createMCPToolStaticFilter,
  MCPServerStreamableHttp,
  Runner,
  type AgentInputItem,
  type RunStreamEvent,
} from "@openai/agents";
import { NextRequest, NextResponse } from "next/server";

import {
  authHeadersFor,
  buildCerebroUrl,
  fetchCerebro,
  getCerebroProxyConfig,
} from "@/lib/cerebro-proxy";
import { agentAnswerSchema, collectUrns, validateAgentAnswer } from "@/lib/agent-answer";
import {
  AgentConversationOwnershipError,
  openAgentConversation,
  removeAgentConversation,
} from "@/lib/agent-conversation";
import {
  AGENT_TOOL_PACKS,
  selectAgentModelRoute,
  type AgentModelRoute,
} from "@/lib/agent-model-route";
import {
  type AskAgentContext,
  type AskRequest,
  normalizeAskError,
  normalizeAskModel,
} from "@/lib/ask";
import { askAgentRuntimeConfig, mcpUrlFromApiBase } from "@/lib/ask-agent-config";
import { ASK_AGENT_FALLBACK_STATUS } from "@/lib/ask-agent-status";
import { normalizeAskImages } from "@/lib/ask-images";
import {
  resolveSecurityProducerGuidance,
  securityProducerResponseCandidateHint,
} from "@/lib/security-producer-response";
import type { SecurityProducer, SecurityProducerCatalog } from "@/lib/security-producers";
import { runtimeSecurityProducerCatalog } from "@/lib/security-producers-runtime";
import {
  authorizationErrorResponse,
  authorizeCurrentUser,
  type AuthorizationDecision,
} from "@/lib/authorization";
import { resolveCurrentUserFromHeadersWithFallback, type CurrentUser } from "@/lib/identity";
import { currentUserServerAuditFields } from "@/lib/identity-server";
import { headersWithTrace, startWebSpan, type WebSpan } from "@/lib/observability";

export const runtime = "nodejs";
export const maxDuration = 300;

const encoder = new TextEncoder();
export const DEFAULT_AGENT_MODEL = "gpt-5.6-sol";

type NormalizedAgentRequest = AskRequest & {
  question: string;
  tenant_id: string;
};

type AgentStreamStats = {
  startedAt: number;
  toolCalls: number;
  toolResults: number;
  deltaCount: number;
  mcpConnectMs?: number;
  agentRunMs?: number;
  firstToolMs?: number;
  firstDeltaMs?: number;
  observedUrns: Set<string>;
};

const sse = (event: string, data: unknown) =>
  encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

const trimString = (value: unknown) =>
  typeof value === "string" ? value.trim() : "";

const instructionMetadata = (value: unknown, fallback = "unknown", maxLength = 512) => {
  const cleaned = trimString(value)
    .replace(/[\u0000-\u001F\u007F\u2028\u2029]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const normalized = cleaned || fallback;
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength)}...`;
};

const quotedInstructionMetadata = (value: unknown, fallback = "unknown", maxLength = 512) =>
  JSON.stringify(instructionMetadata(value, fallback, maxLength));

export const agentPayloadError = (payload: unknown) => {
  if (!payload || typeof payload !== "object") return "Ask requires a non-empty question.";
  const source = payload as Record<string, unknown>;
  if (!trimString(source.question)) return "Ask requires a non-empty question.";
  if (!normalizeAskImages(source.images)) {
    return "Attach up to 4 PNG, JPEG, WebP, or GIF images, 4 MB each and 8 MB total.";
  }
  return null;
};

const normalizePayload = (payload: unknown): NormalizedAgentRequest | null => {
  if (!payload || typeof payload !== "object") return null;
  const source = payload as Record<string, unknown>;
  const question = trimString(source.question);
  if (!question) return null;
  const images = normalizeAskImages(source.images);
  if (!images) return null;
  return {
    ...source,
    question,
    tenant_id: trimString(source.tenant_id) || "writer",
    scope_urn: trimString(source.scope_urn) || undefined,
    model: normalizeAskModel(trimString(source.model) || undefined),
    history: Array.isArray(source.history) ? source.history as AskRequest["history"] : undefined,
    context: normalizeContext(source.context),
    surface: trimString(source.surface) || "agent",
    conversation_id: trimString(source.conversation_id) || undefined,
    agent_mode: source.agent_mode === "deep" ? "deep" : "auto",
    images,
  };
};

const normalizeContext = (value: unknown): AskAgentContext | undefined => {
  if (!value || typeof value !== "object") return undefined;
  const context = value as AskAgentContext;
  const chips = Array.isArray(context.chips)
    ? context.chips
        .filter((chip) => chip && typeof chip === "object")
        .map((chip) => {
          const record = chip as Record<string, unknown>;
          return {
            label: trimString(record.label),
            value: trimString(record.value),
          };
        })
        .filter((chip) => chip.label && chip.value)
    : undefined;
  return {
    ...context,
    route: trimString(context.route) || undefined,
    routeLabel: trimString(context.routeLabel) || undefined,
    href: trimString(context.href) || undefined,
    title: trimString(context.title) || undefined,
    scopeUrn: trimString(context.scopeUrn) || undefined,
    findingId: trimString(context.findingId) || undefined,
    entityUrn: trimString(context.entityUrn) || undefined,
    resourceUrn: trimString(context.resourceUrn) || undefined,
    chips,
  };
};

export async function POST(request: NextRequest) {
  const span = startWebSpan("cerebro.agent.request", agentRequestSpanAttributes(request), request.headers.get("traceparent"));
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  const decision = authorizeCurrentUser(currentUser, "agent:ask");
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  if (!decision.allowed) {
    console.warn("agent ask denied", currentUserServerAuditFields(currentUser));
    return tracedAuthorizationError(decision, span);
  }

  const rawPayload = await request.json().catch(() => null);
  const payloadError = agentPayloadError(rawPayload);
  const payload = payloadError ? null : normalizePayload(rawPayload);
  if (!payload) {
    span.end("completed", {
      payload_valid: false,
      "http.response.status_code": 400,
    });
    const response = NextResponse.json(
      { error: payloadError ?? "Ask requires a non-empty question." },
      { status: 400 },
    );
    response.headers.set("x-cerebro-web-trace-id", span.traceId);
    return response;
  }

  span.annotate(agentPayloadSpanAttributes(payload));
  const runtimeConfig = resolvedAgentRuntimeConfig();
  const canRunAgent = runtimeConfig.canRunAgent;
  span.annotate({
    agent_mode: canRunAgent ? "agent" : "agent-fallback",
    mcp_configured: Boolean(runtimeConfig.mcpUrl),
    openai_configured: runtimeConfig.openAIConfigured,
  });
  let streamStatus: "completed" | "failed" | "cancelled" = "completed";
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        if (canRunAgent) {
          await streamAgentRun(
            controller,
            request,
            payload,
            currentUserServerAuditFields(currentUser).actorKey,
            runtimeConfig,
            span,
          );
        } else if (payload.images?.length) {
          controller.enqueue(sse("error", normalizeAskError(
            "image_input_unavailable",
            "Image analysis is unavailable because the agent runtime is not configured.",
            true,
          )));
        } else {
          await streamLegacyAsk(controller, request, payload, span);
        }
      } catch (error) {
        if (request.signal.aborted) {
          streamStatus = "cancelled";
          return;
        }
        streamStatus = "failed";
        span.captureException(error, {
          component: "agent-ask-route",
          operation: canRunAgent ? "agent_stream" : "legacy_stream",
        });
        const ownershipError = error instanceof AgentConversationOwnershipError;
        controller.enqueue(sse("error", normalizeAskError(
          ownershipError ? "agent_conversation_forbidden" : "agent_exception",
          ownershipError
            ? "This conversation is not available for the current identity and tenant."
            : error instanceof Error ? error.message : "Cerebro agent failed",
          !ownershipError,
        )));
      } finally {
        span.annotate({
          stream_status: streamStatus,
        });
        span.end(streamStatus, {
          mode: canRunAgent ? "agent" : "agent-fallback",
          "http.response.status_code": 200,
        });
        controller.close();
      }
    },
    cancel() {
      request.signal.throwIfAborted?.();
    },
  });

  return new NextResponse(stream, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-cerebro-web-surface": canRunAgent ? "agent" : "agent-fallback",
      "x-cerebro-web-trace-id": span.traceId,
    },
  });
}

export async function DELETE(request: NextRequest) {
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  const decision = authorizeCurrentUser(currentUser, "agent:ask");
  if (!decision.allowed) return authorizationErrorResponse(decision);
  const rawPayload = await request.json().catch(() => null) as Record<string, unknown> | null;
  const conversationId = trimString(rawPayload?.conversation_id);
  const tenantId = trimString(rawPayload?.tenant_id) || "writer";
  if (!conversationId) {
    return NextResponse.json({ error: "conversation_id is required" }, { status: 400 });
  }
  try {
    const removed = await removeAgentConversation({
      actorKey: currentUserServerAuditFields(currentUser).actorKey,
      conversationId,
      tenantId,
    });
    return NextResponse.json({ removed });
  } catch (error) {
    if (error instanceof AgentConversationOwnershipError) {
      return NextResponse.json(
        { error: "This conversation is not available for the current identity and tenant." },
        { status: 403 },
      );
    }
    throw error;
  }
}

async function streamAgentRun(
  controller: ReadableStreamDefaultController<Uint8Array>,
  request: NextRequest,
  payload: NormalizedAgentRequest,
  actorKey: string,
  runtimeConfig: ReturnType<typeof resolvedAgentRuntimeConfig>,
  span: WebSpan,
) {
  const startedAt = Date.now();
  const stats: AgentStreamStats = {
    startedAt,
    toolCalls: 0,
    toolResults: 0,
    deltaCount: 0,
    observedUrns: new Set(),
  };
  const mcpUrl = runtimeConfig.mcpUrl;
  if (!mcpUrl) {
    span.annotate({
      mcp_connected: false,
      mcp_missing_url: true,
    });
    await streamLegacyAsk(controller, request, payload, span);
    return;
  }

  const route = selectAgentModelRoute(
    {
      question: payload.question,
      mode: payload.agent_mode,
      context: payload.context,
      scopeUrn: payload.scope_urn,
      imageCount: payload.images?.length,
    },
    runtimeConfig.modelOverride,
  );
  const conversation = await openAgentConversation({
    actorKey,
    conversationId: payload.conversation_id,
    tenantId: payload.tenant_id,
  });
  span.annotate({
    agent_model: route.model,
    agent_profile: route.profile,
    agent_route_reason: route.selectionReason,
    agent_tool_pack: route.toolPack,
    conversation_resumed: Boolean(payload.conversation_id?.startsWith("conv_")),
  });
  const mcpHeaders = headersWithTrace(headersForMcp(request, runtimeConfig.mcpToken), span);
  const server = new MCPServerStreamableHttp({
    url: mcpUrl,
    name: "Cerebro MCP",
    cacheToolsList: true,
    requestInit: { headers: Object.fromEntries(mcpHeaders.entries()) },
    timeout: 60_000,
    toolFilter: createMCPToolStaticFilter({ allowed: AGENT_TOOL_PACKS[route.toolPack] }),
    useStructuredContent: true,
  });

  controller.enqueue(sse("agent_status", {
    stage: "connect",
    label: "Connecting to graph tools",
    detail: new URL(mcpUrl).pathname,
    mode: "agent",
  }));

  try {
    const connectStartedAt = Date.now();
    await server.connect();
    stats.mcpConnectMs = Date.now() - connectStartedAt;
    span.annotate({
      mcp_connected: true,
      mcp_path_family: new URL(mcpUrl).pathname.split("/").filter(Boolean).slice(0, 3).join("/") || "/",
    });
    controller.enqueue(sse("agent_status", {
      stage: "plan",
      label: "Reading graph context",
      detail: contextLabel(payload),
      mode: "agent",
    }));
    const runtimeInstructions = buildRuntimeAgentInstructions(payload);
    span.annotate({
      security_producer_catalog_state: runtimeInstructions.catalogState,
    });

    const agent = new Agent({
      name: "Cerebro Operator",
      instructions: runtimeInstructions.instructions,
      model: route.model,
      modelSettings: route.modelSettings,
      outputType: agentAnswerSchema,
      mcpServers: [server],
      mcpConfig: {
        convertSchemasToStrict: true,
        includeServerInToolNames: false,
      },
    });
    const runner = new Runner({
      workflowName: "Cerebro Web Agent",
      traceIncludeSensitiveData: false,
      groupId: conversation.conversationId,
    });
    const result = await runner.run(agent, buildAgentInput(payload, route), {
      stream: true,
      signal: request.signal,
      maxTurns: route.maxTurns,
      session: conversation.session,
    });

    const agentRunStartedAt = Date.now();
    for await (const event of result) {
      emitAgentStreamEvent(controller, event, stats);
    }
    await result.completed;
    stats.agentRunMs = Date.now() - agentRunStartedAt;

    const summary = validateAgentAnswer(result.finalOutput, stats.observedUrns);
    if (summary.markdown) {
      span.annotate({
        final_output_chars: summary.markdown.length,
        citation_count: summary.citations.length,
        evidence_gap_count: summary.evidence_gaps?.length ?? 0,
      });
      controller.enqueue(sse("summary", summary));
    }
    const usage = result.state.usage;
    span.annotate(agentStreamStatsAttributes(stats));
    span.annotate({
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens,
      total_tokens: usage.totalTokens,
    });
    controller.enqueue(sse("done", {
      trace_id: span.traceId,
      total_ms: Date.now() - startedAt,
      cypher_refused: false,
      timings: compactTimings(stats),
      tool_calls: stats.toolCalls,
      tool_results: stats.toolResults,
      delta_count: stats.deltaCount,
      conversation_id: conversation.conversationId,
      agent_profile: route.profile,
      model_route: route.model,
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens,
      total_tokens: usage.totalTokens,
    }));
  } finally {
    await server.close().catch(() => undefined);
  }
}

async function streamLegacyAsk(
  controller: ReadableStreamDefaultController<Uint8Array>,
  request: NextRequest,
  payload: NormalizedAgentRequest,
  span: WebSpan,
) {
  controller.enqueue(sse("agent_status", ASK_AGENT_FALLBACK_STATUS));

  const response = await fetchCerebro(buildCerebroUrl("grc/ask"), {
    method: "POST",
    headers: headersWithTrace({
      ...authHeadersFor(request),
      "content-type": "application/json",
      accept: "text/event-stream",
      "x-cerebro-web-surface": "ask-agent-fallback",
    }, span),
    body: JSON.stringify(legacyAskPayload(payload)),
    cache: "no-store",
    signal: request.signal,
  });

  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => "");
    span.annotate({
      legacy_ask_error: true,
      legacy_ask_status_code: response.status,
      legacy_ask_error_body_size: byteLength(text),
    });
    const failure = legacyAskFailure(response.status, text);
    controller.enqueue(sse("error", normalizeAskError(failure.code, failure.message, failure.retryable)));
    return;
  }

  const { chunkCount, streamedBytes } = await forwardLegacyAskBody(response.body, (value) => {
    controller.enqueue(value);
  });
  span.annotate({
    legacy_ask_chunk_count: chunkCount,
    legacy_ask_streamed_bytes: streamedBytes,
    legacy_ask_status_code: response.status,
  });
}

export async function forwardLegacyAskBody(
  body: ReadableStream<Uint8Array>,
  enqueue: (value: Uint8Array) => void,
) {
  const reader = body.getReader();
  let chunkCount = 0;
  let streamedBytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunkCount += 1;
      streamedBytes += value.byteLength;
      enqueue(value);
    }
    return { chunkCount, streamedBytes };
  } catch (error) {
    await reader.cancel(error).catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

const legacyAskPayload = (payload: NormalizedAgentRequest) => ({
  tenant_id: payload.tenant_id,
  question: payload.question,
  scope_urn: payload.scope_urn,
  model: normalizeAskModel(payload.model),
  history: payload.history,
});

const legacyAskFailure = (status: number, body: string) => {
  if (status === 400) {
    return {
      code: "ask_request_rejected",
      message: "Ask could not run because the graph Ask endpoint rejected the request.",
      retryable: false,
    };
  }
  if (status === 401 || status === 403) {
    return {
      code: "ask_not_authorized",
      message: "Ask is not authorized for the current identity.",
      retryable: false,
    };
  }
  if (status === 404) {
    return {
      code: "ask_endpoint_unavailable",
      message: "Graph Ask is not available on this Cerebro API.",
      retryable: false,
    };
  }
  if (status === 408 || status === 429) {
    return {
      code: "ask_rate_limited",
      message: "Graph Ask is busy. Retry the request in a moment.",
      retryable: true,
    };
  }
  if (status === 503) {
    return {
      code: "ask_runtime_unavailable",
      message: "Graph Ask is unavailable because a required runtime dependency is not configured.",
      retryable: true,
    };
  }
  return {
    code: `http_${status}`,
    message: body.trim() ? "Graph Ask returned an unexpected error." : `Ask request failed (${status}).`,
    retryable: status >= 500,
  };
};

const resolvedAgentRuntimeConfig = () => {
  const config = askAgentRuntimeConfig();
  if (config.mcpUrl) return config;
  const { apiBase } = getCerebroProxyConfig();
  const mcpUrl = mcpUrlFromApiBase(apiBase);
  return { ...config, mcpUrl, canRunAgent: Boolean(config.openAIConfigured && mcpUrl) };
};

const headersForMcp = (request: NextRequest, configuredToken: string) => {
  const headers = new Headers(authHeadersFor(request));
  const token = configuredToken.trim();
  if (token) {
    headers.set("authorization", token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`);
  }
  headers.set("accept", "application/json, text/event-stream");
  return headers;
};

export const buildAgentInstructions = (
  payload: NormalizedAgentRequest,
  catalog: SecurityProducerCatalog = { state: "invalid" },
) => `
You are Cerebro AI, the security graph operator inside the Cerebro web platform.

Use the Cerebro MCP tools as the source of truth for findings, assets, evidence, risk summaries, graph neighborhoods, impact paths, and investigation context. Do not invent graph facts, identifiers, evidence, ownership, or counts that are not returned by a tool. Treat tenant-forbidden, not-found, and redacted values as hard boundaries.

Prefer narrow, high-signal tool calls. If the user is on a scoped screen, start with that entity, finding, resource, or route context before broad search. For changes or refreshes, only use propose/dry-run tools and clearly label the result as a proposal.

Fast tool routing:
${buildFastToolGuidance(payload, catalog.state === "ready" ? catalog.producers : [])}
- Avoid decomposing a request into findings, evidence, asset, and graph calls when one bundled tool already returns the needed context.

Return the required structured answer. Put the concise, actionable answer in markdown. Cite only URNs present in tool results. List missing or conflicting evidence in evidence_gaps; use an empty list only when the requested claim is fully supported. Mention MCP tool names only when it helps auditability.

Current request metadata:
- Tenant: ${quotedInstructionMetadata(payload.tenant_id, "writer", 128)}
- Surface: ${quotedInstructionMetadata(payload.surface, "agent", 80)}
- Scope URN: ${quotedInstructionMetadata(payload.scope_urn ?? payload.context?.scopeUrn, "none", 512)}
- Route: ${quotedInstructionMetadata(payload.context?.route, "unknown", 256)}
- Page title: ${quotedInstructionMetadata(payload.context?.title ?? payload.context?.routeLabel, "unknown", 256)}
`;

export const buildRuntimeAgentInstructions = (payload: NormalizedAgentRequest) => {
  const catalog = runtimeSecurityProducerCatalog();
  return {
    catalogState: catalog.state,
    instructions: buildAgentInstructions(payload, catalog),
  };
};

const buildFastToolGuidance = (
  payload: NormalizedAgentRequest,
  producers: SecurityProducer[],
) => {
  const findingId = instructionMetadata(payload.context?.findingId, "", 256);
  const route = payload.context?.route ?? "";
  const scopedUrn = instructionMetadata(
    payload.scope_urn ?? payload.context?.scopeUrn ?? payload.context?.resourceUrn ?? payload.context?.entityUrn,
    "",
    512,
  );
  const oauthAppID = instructionMetadata(contextString(payload.context, "oauth_app_id"), "", 256);
  const oauthGrantID = instructionMetadata(contextString(payload.context, "oauth_grant_id"), "", 256);
  const requestedSecurityProducerID = instructionMetadata(contextString(payload.context, "security_producer_id"), "", 256);
  const requestedResponseActionCandidates = contextStringList(payload.context, "response_action_candidates")
    .map((candidate) => instructionMetadata(candidate, "", 160))
    .filter(Boolean);
  const producerGuidance = resolveSecurityProducerGuidance(
    requestedSecurityProducerID,
    requestedResponseActionCandidates,
    producers,
  );
  const securityProducerID = producerGuidance?.producer.id ?? "";
  const responseActionCandidates = producerGuidance?.candidates ?? [];
  const responseActionCandidateHint = producerGuidance
    ? securityProducerResponseCandidateHint(responseActionCandidates, producerGuidance.producer)
    : "";
  const hints = [
    findingId
      ? `- For this finding-scoped request, call cerebro.investigation.context first with finding_id=${JSON.stringify(findingId)} and compact=true unless the user explicitly asks for raw evidence.`
      : "",
    securityProducerID
      ? `- This request carries configured security producer context (security_producer_id=${JSON.stringify(securityProducerID)}). Preserve that producer as the proposal owner when explaining status or next actions.`
      : "",
    oauthAppID || oauthGrantID
      ? `- For OAuth risk questions, prioritize grant, app, user, scope, and resource-family relationships before generic asset search (${[
          oauthAppID ? `oauth_app_id=${JSON.stringify(oauthAppID)}` : "",
          oauthGrantID ? `oauth_grant_id=${JSON.stringify(oauthGrantID)}` : "",
        ].filter(Boolean).join(", ")}).`
      : "",
    responseActionCandidates.length > 0
      ? `- For response or remediation requests with configured producer context, do not claim direct execution. Treat these as proposal workflows, preserve dry-run and approval requirements, and include target identifiers. Candidate actions: ${responseActionCandidateHint}.`
      : "",
    route.includes("risk") || route.includes("dashboard") || route.includes("inbox")
      ? "- For risk dashboard or inbox questions without a specific finding, start with cerebro.risk.summary before broad finding search."
      : "",
    scopedUrn
      ? `- For scoped asset or graph questions, start from the provided URN (${JSON.stringify(scopedUrn)}) and prefer cerebro.assets.get before using cerebro.graph.neighborhood for relationship detail.`
      : "",
  ].filter(Boolean);
  return hints.length ? hints.join("\n") : "- Start with the narrowest MCP tool that matches the current page context before broad search.";
};

const contextString = (context: AskAgentContext | undefined, key: string) => {
  const value = context?.[key];
  return typeof value === "string" ? value.trim() : "";
};

const contextStringList = (context: AskAgentContext | undefined, key: string) => {
  const value = context?.[key];
  if (Array.isArray(value)) {
    return value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
  }
  if (typeof value === "string") {
    return value.split(/[,;|]/).map((item) => item.trim()).filter(Boolean);
  }
  return [];
};

export const buildAgentInput = (
  payload: NormalizedAgentRequest,
  route?: Pick<AgentModelRoute, "imageDetail">,
): AgentInputItem[] => {
  const context = payload.context
    ? JSON.stringify(payload.context, null, 2)
    : "{}";
  const text = [
    `Question: ${payload.question}`,
    `Context JSON:\n${context}`,
  ].join("\n\n");
  return [{
    role: "user",
    content: [
      { type: "input_text", text },
      ...(payload.images ?? []).map((image) => ({
        type: "input_image" as const,
        image: image.data_url,
        detail: route?.imageDetail ?? "auto",
      })),
    ],
  }];
};

const contextLabel = (payload: NormalizedAgentRequest) => {
  if (payload.context?.title) return payload.context.title;
  if (payload.context?.routeLabel) return payload.context.routeLabel;
  if (payload.scope_urn) return payload.scope_urn;
  return payload.context?.route ?? "current screen";
};

const emitAgentStreamEvent = (
  controller: ReadableStreamDefaultController<Uint8Array>,
  event: RunStreamEvent,
  stats: AgentStreamStats,
) => {
  if (event.type === "raw_model_stream_event") {
    // Structured output streams partial JSON. Keep it out of the operator-facing answer.
    return;
  }

  if (event.type === "agent_updated_stream_event") {
    controller.enqueue(sse("agent_status", {
      stage: "handoff",
      label: `Running ${event.agent.name}`,
      mode: "agent",
    }));
    return;
  }

  if (event.type === "run_item_stream_event") {
    if (event.name === "tool_called") {
      stats.toolCalls += 1;
      stats.firstToolMs ??= Date.now() - stats.startedAt;
      controller.enqueue(sse("agent_tool", {
        name: toolNameFromItem(event.item),
        status: "started",
        detail: "Calling graph tools",
      }));
    }
    if (event.name === "tool_output") {
      stats.toolResults += 1;
      for (const urn of collectUrns(toolOutputFromItem(event.item))) stats.observedUrns.add(urn);
      controller.enqueue(sse("agent_tool", {
        name: toolNameFromItem(event.item),
        status: "completed",
        detail: "Result received",
      }));
    }
    if (event.name === "reasoning_item_created") {
      controller.enqueue(sse("agent_status", {
        stage: "reasoning",
        label: "Planning next graph step",
        mode: "agent",
      }));
    }
  }
};

const compactTimings = (stats: AgentStreamStats) => {
  const timings: Record<string, number> = {};
  if (typeof stats.mcpConnectMs === "number") timings.mcp_connect_ms = stats.mcpConnectMs;
  if (typeof stats.agentRunMs === "number") timings.agent_run_ms = stats.agentRunMs;
  if (typeof stats.firstToolMs === "number") timings.first_tool_ms = stats.firstToolMs;
  if (typeof stats.firstDeltaMs === "number") timings.first_delta_ms = stats.firstDeltaMs;
  return timings;
};

const toolNameFromItem = (item: unknown) => {
  if (!item || typeof item !== "object") return "cerebro.tool";
  const record = item as Record<string, unknown>;
  const rawItem = record.rawItem;
  if (rawItem && typeof rawItem === "object") {
    const raw = rawItem as Record<string, unknown>;
    if (typeof raw.name === "string" && raw.name) return raw.name;
  }
  if (typeof record.name === "string" && record.name) return record.name;
  return "cerebro.tool";
};

const toolOutputFromItem = (item: unknown) => {
  if (!item || typeof item !== "object") return undefined;
  const record = item as Record<string, unknown>;
  const rawItem = record.rawItem;
  if (rawItem && typeof rawItem === "object" && "output" in rawItem) {
    return (rawItem as Record<string, unknown>).output;
  }
  return record.output;
};

function agentRequestSpanAttributes(request: NextRequest) {
  const url = new URL(request.url);
  return {
    main: true,
    wide_event: true,
    component: "agent-ask-route",
    operation: "POST",
    "http.request.body.size": requestBodySize(request),
    "http.request.header.accept": request.headers.get("accept") ?? "",
    "http.request.header.content_type": request.headers.get("content-type") ?? "",
    "http.request.header.user_agent": request.headers.get("user-agent") ?? "",
    "http.request.method": "POST",
    "network.protocol.name": url.protocol.replace(":", ""),
    "server.address": url.hostname,
    "url.path_family": "/api/agent",
    "user_agent.family": userAgentFamily(request.headers.get("user-agent")),
  };
}

function tracedAuthorizationError(decision: AuthorizationDecision, span: WebSpan) {
  const response = authorizationErrorResponse(decision);
  response.headers.set("x-cerebro-web-trace-id", span.traceId);
  span.end("completed", {
    ...authorizationDecisionAttributes(decision),
    "http.response.header.cache_control": response.headers.get("cache-control") ?? "",
    "http.response.status_code": response.status,
  });
  return response;
}

function authorizationSpanAttributes(decision: AuthorizationDecision, user: CurrentUser | null) {
  const audit = currentUserServerAuditFields(user);
  return {
    ...authorizationDecisionAttributes(decision),
    "enduser.id_hash": audit.actorKey,
    identity_authenticated: audit.authenticated,
    identity_claim_count: audit.claimCount,
    identity_confidence: audit.confidence,
    identity_conflict_count: audit.conflictCount,
    identity_group_count: audit.groupCount,
    identity_header_count: audit.headerCount,
    identity_provider: audit.provider,
    identity_role_count: audit.roleCount,
    identity_scope_count: audit.scopeCount,
    identity_source: audit.source,
    identity_warning_count: audit.warningCount,
  };
}

function authorizationDecisionAttributes(decision: AuthorizationDecision) {
  return {
    authorization_allowed: decision.allowed,
    authorization_code: decision.code,
    authorization_permission: decision.permission,
    authorization_status_code: decision.status,
  };
}

function agentPayloadSpanAttributes(payload: NormalizedAgentRequest) {
  return {
    context_chip_count: payload.context?.chips?.length ?? 0,
    context_has_entity_urn: Boolean(payload.context?.entityUrn),
    context_has_finding_id: Boolean(payload.context?.findingId),
    context_has_resource_urn: Boolean(payload.context?.resourceUrn),
    context_has_scope_urn: Boolean(payload.context?.scopeUrn || payload.scope_urn),
    context_route_family: routeFamily(payload.context?.route),
    conversation_present: Boolean(payload.conversation_id),
    image_count: payload.images?.length ?? 0,
    history_count: payload.history?.length ?? 0,
    payload_valid: true,
    question_chars: payload.question.length,
    request_model: payload.model ?? "default",
    surface: payload.surface ?? "agent",
    tenant_id: payload.tenant_id,
  };
}

function agentStreamStatsAttributes(stats: AgentStreamStats) {
  return {
    agent_delta_count: stats.deltaCount,
    agent_first_delta_ms: stats.firstDeltaMs,
    agent_first_tool_ms: stats.firstToolMs,
    agent_run_ms: stats.agentRunMs,
    agent_tool_call_count: stats.toolCalls,
    agent_tool_result_count: stats.toolResults,
    mcp_connect_ms: stats.mcpConnectMs,
    total_stream_ms: Date.now() - stats.startedAt,
  };
}

function requestBodySize(request: NextRequest) {
  const raw = request.headers.get("content-length");
  if (!raw) {
    return 0;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function byteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function routeFamily(route: string | undefined) {
  const segments = (route ?? "").split(/[?#]/, 1)[0].split("/").filter(Boolean).slice(0, 2);
  return segments.length ? `/${segments.join("/")}` : "unknown";
}

function userAgentFamily(value: string | null) {
  const normalized = (value ?? "").toLowerCase();
  if (!normalized) return "none";
  if (normalized.includes("bot") || normalized.includes("crawler") || normalized.includes("spider")) return "bot";
  if (normalized.includes("edge") || normalized.includes("edg/")) return "edge";
  if (normalized.includes("chrome")) return "chrome";
  if (normalized.includes("safari")) return "safari";
  if (normalized.includes("firefox")) return "firefox";
  if (normalized.includes("curl")) return "curl";
  if (normalized.includes("node")) return "node";
  return "other";
}
