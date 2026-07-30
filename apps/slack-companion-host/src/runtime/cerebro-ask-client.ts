export type AssistantTurnSourceGapState =
  | "not_configured"
  | "not_found"
  | "timed_out"
  | "unauthorized"
  | "unavailable";

export interface CerebroAskResult {
  citationValidationPassed: boolean;
  executionLane: "converse" | "lookup";
  markdown: string;
  safeRefusal: boolean;
  traceId?: string;
}

export interface CerebroAskHistoryMessage {
  content: string;
  role: "assistant" | "user";
}

export interface CerebroAskClientOptions {
  answerAuthority: SlackAnswerAuthorityPort;
  apiKey: string;
  baseUrl: string;
  fetchImpl?: typeof fetch;
  tenantId: string;
}

export class CerebroAskError extends Error {
  constructor(
    public readonly sourceState: AssistantTurnSourceGapState,
    message: string,
  ) {
    super(message);
    this.name = "CerebroAskError";
  }
}

export class CerebroAskClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: CerebroAskClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
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
    const response = await this.fetchImpl(`${this.options.baseUrl}/grc/ask`, {
      method: "POST",
      headers: {
        Accept: "text/event-stream",
        Authorization: `Bearer ${this.options.apiKey}`,
        "Content-Type": "application/json",
        "X-Cerebro-Tenant": this.options.tenantId,
      },
      body: JSON.stringify({
        ...(history.length === 0 ? {} : { history }),
        question,
        surface: "slack",
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
              ...(conversationValidation(event.data.conversation_validation) === undefined
                ? {}
                : {
                    conversation_validation: conversationValidation(
                      event.data.conversation_validation,
                    ),
                  }),
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
      throw new CerebroAskError("unavailable", errorMessage(error));
    }
    return {
      citationValidationPassed: decision.verified,
      executionLane: decision.disposition === "conversational" ? "converse" : "lookup",
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
        history: history.map((message) => ({ ...message })),
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

function conversationValidation(
  value: unknown,
): SlackAnswerCandidate["conversation_validation"] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const validation = value as Record<string, unknown>;
  const policyCheckIds = stringArray(validation.policy_check_ids);
  if (
    validation.ok !== true
    || validation.route !== "converse"
    || (
      validation.route_reason !== "self_context"
      && validation.route_reason !== "thread_continuation"
    )
    || !positiveBoundedInteger(validation.router_attempts, 2)
    || !nonNegativeBoundedInteger(validation.draft_attempts, 2)
    || !nonNegativeBoundedInteger(validation.critic_attempts, 2)
    || typeof validation.critic_approved !== "boolean"
    || typeof validation.fallback_used !== "boolean"
    || validation.requires_graph_query !== false
    || policyCheckIds === undefined
  ) {
    return undefined;
  }
  return {
    critic_approved: validation.critic_approved,
    critic_attempts: validation.critic_attempts,
    draft_attempts: validation.draft_attempts,
    fallback_used: validation.fallback_used,
    ok: true,
    policy_check_ids: policyCheckIds,
    requires_graph_query: false,
    route: "converse",
    route_reason: validation.route_reason,
    router_attempts: validation.router_attempts,
  };
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

function nonNegativeBoundedInteger(value: unknown, maximum: number): value is number {
  return nonNegativeInteger(value) && Number(value) <= maximum;
}

function positiveBoundedInteger(value: unknown, maximum: number): value is number {
  return nonNegativeBoundedInteger(value, maximum) && Number(value) > 0;
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

function errorMessage(value: unknown): string {
  return value instanceof Error && value.message
    ? value.message
    : "Cerebro is unavailable.";
}

function isAbortError(value: unknown): boolean {
  return value instanceof DOMException && (value.name === "AbortError" || value.name === "TimeoutError");
}
import {
  type SlackAnswerAuthorityPort,
  type SlackAnswerCandidate,
  type SlackQuestionDecision,
} from "./slack-answer-authority-client.js";
