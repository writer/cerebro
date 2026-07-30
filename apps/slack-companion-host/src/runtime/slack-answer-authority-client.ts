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

export interface SlackQuestionCandidate {
  history: {
    content: string;
    role: "assistant" | "user";
  }[];
  question: string;
  request_id: string;
  schema_version: "slack-question-candidate/v1";
  tenant_id: string;
}

export type SlackQuestionDecision =
  | {
      answer: string;
      authorized: true;
      execution_lane: "converse";
      request_id: string;
      schema_version: "slack-question-decision/v1";
      tenant_id: string;
    }
  | {
      authorized: true;
      execution_lane: "lookup";
      request_id: string;
      schema_version: "slack-question-decision/v1";
      tenant_id: string;
    };

export interface SlackAnswerAuthorityPort {
  authorizeQuestion(candidate: SlackQuestionCandidate): Promise<SlackQuestionDecision>;
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

  async authorizeQuestion(candidate: SlackQuestionCandidate): Promise<SlackQuestionDecision> {
    const response = await this.post("/v1/questions/authorize", candidate);
    if (!response.ok) {
      throw new SlackAnswerAuthorityError(
        `Rust Slack authority rejected the question with status ${response.status}.`,
      );
    }
    const decision: unknown = await response.json().catch(() => undefined);
    if (!validQuestionDecision(decision, candidate)) {
      throw new SlackAnswerAuthorityError(
        "Rust Slack authority returned an invalid question decision.",
      );
    }
    return decision;
  }

  async validate(candidate: SlackAnswerCandidate): Promise<SlackAnswerDecision> {
    const response = await this.post("/v1/answers/validate", candidate);
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

  private async post(path: string, body: unknown): Promise<Response> {
    return this.fetchImpl(`${this.options.baseUrl}${path}`, {
      body: JSON.stringify(body),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      method: "POST",
      signal: AbortSignal.timeout(2_000),
    }).catch((error: unknown) => {
      throw new SlackAnswerAuthorityError(errorMessage(error));
    });
  }
}

function validQuestionDecision(
  value: unknown,
  candidate: SlackQuestionCandidate,
): value is SlackQuestionDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const decision = value as Record<string, unknown>;
  return decision.schema_version === "slack-question-decision/v1"
    && decision.authorized === true
    && (
      (
        decision.execution_lane === "lookup"
        && decision.answer === undefined
      )
      || (
        decision.execution_lane === "converse"
        && typeof decision.answer === "string"
        && decision.answer.trim() !== ""
      )
    )
    && decision.request_id === candidate.request_id
    && decision.tenant_id === candidate.tenant_id;
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
