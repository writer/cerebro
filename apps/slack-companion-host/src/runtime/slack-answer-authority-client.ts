export interface SlackAnswerCandidate {
  citation_validation?: {
    ok: boolean;
    referenced_urn_count: number;
    row_urn_count: number;
  };
  completed: boolean;
  markdown: string;
  schema_version: "slack-answer-candidate/v1";
  trace_id: string;
  unsupported_query?: {
    code: string;
    reason: string;
    suggested_rewrites: string[];
    supported_intents: string[];
    trace_id: string;
  };
}

export interface SlackAnswerDecision {
  disposition: "grounded" | "safe_refusal";
  schema_version: "slack-answer-decision/v1";
  trace_id: string;
  verified: boolean;
}

export interface SlackAnswerAuthorityPort {
  validate(candidate: SlackAnswerCandidate): Promise<SlackAnswerDecision>;
}

export interface SlackAnswerAuthorityClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

export class SlackAnswerAuthorityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlackAnswerAuthorityError";
  }
}

export class SlackAnswerAuthorityClient implements SlackAnswerAuthorityPort {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: SlackAnswerAuthorityClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async validate(candidate: SlackAnswerCandidate): Promise<SlackAnswerDecision> {
    const response = await this.fetchImpl(
      `${this.options.baseUrl}/v1/answers/validate`,
      {
        body: JSON.stringify(candidate),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
        signal: AbortSignal.timeout(2_000),
      },
    ).catch((error: unknown) => {
      throw new SlackAnswerAuthorityError(errorMessage(error));
    });
    if (!response.ok) {
      throw new SlackAnswerAuthorityError(
        `Rust Slack answer authority rejected the candidate with status ${response.status}.`,
      );
    }
    const decision: unknown = await response.json().catch(() => undefined);
    if (!validDecision(decision, candidate.trace_id)) {
      throw new SlackAnswerAuthorityError(
        "Rust Slack answer authority returned an invalid decision.",
      );
    }
    return decision;
  }
}

function validDecision(
  value: unknown,
  expectedTraceId: string,
): value is SlackAnswerDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const decision = value as Record<string, unknown>;
  if (
    decision.schema_version !== "slack-answer-decision/v1"
    || decision.trace_id !== expectedTraceId
    || (decision.disposition !== "grounded" && decision.disposition !== "safe_refusal")
    || typeof decision.verified !== "boolean"
  ) {
    return false;
  }
  return decision.disposition === "grounded"
    ? decision.verified
    : !decision.verified;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Rust Slack answer authority is unavailable.";
}
