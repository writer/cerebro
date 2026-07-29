export type AssistantTurnSourceGapState =
  | "not_configured"
  | "not_found"
  | "timed_out"
  | "unauthorized"
  | "unavailable";

export interface CerebroAskResult {
  citationValidationPassed: boolean;
  markdown: string;
  safeRefusal: boolean;
  traceId?: string;
}

export interface CerebroAskHistoryMessage {
  content: string;
  role: "assistant" | "user";
}

export interface CerebroAskClientOptions {
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
    question: string,
    signal: AbortSignal,
    history: readonly CerebroAskHistoryMessage[] = [],
  ): Promise<CerebroAskResult> {
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

    let summary: CerebroAskResult | undefined;
    let done = false;
    try {
      for await (const event of readSse(response.body)) {
        if (event.name === "summary") {
          const markdown = text(event.data.markdown);
          if (markdown) {
            summary = {
              citationValidationPassed: event.data.citation_validation === undefined
                ? false
                : event.data.citation_validation !== null
                  && typeof event.data.citation_validation === "object"
                  && (event.data.citation_validation as Record<string, unknown>).ok === true,
              markdown,
              safeRefusal: isStructuredSafeRefusal(event.data.unsupported_query),
            };
          }
        }
        if (event.name === "done") {
          done = true;
          const traceId = text(event.data.trace_id);
          if (summary && traceId) summary.traceId = traceId;
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
    if (!done || !summary) {
      throw new CerebroAskError("unavailable", "Cerebro ended the response before a verified summary was available.");
    }
    if (!summary.citationValidationPassed && !summary.safeRefusal) {
      throw new CerebroAskError("unavailable", "Cerebro returned an answer without validated citations.");
    }
    return summary;
  }
}

function isStructuredSafeRefusal(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const refusal = value as Record<string, unknown>;
  return text(refusal.code) !== ""
    && text(refusal.reason) !== ""
    && text(refusal.trace_id) !== ""
    && stringArray(refusal.supported_intents)
    && stringArray(refusal.suggested_rewrites);
}

function stringArray(value: unknown): boolean {
  return Array.isArray(value)
    && value.every((item) => typeof item === "string" && item.trim() !== "");
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
