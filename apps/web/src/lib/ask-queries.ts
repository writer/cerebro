export type AskQuery = {
  id: string;
  tenant_id: string;
  name: string;
  question: string;
  scope_urn?: string;
  model?: string;
  pinned: boolean;
  created_at: string;
  updated_at: string;
};

export type AskQueryListResponse = { queries: AskQuery[] };
export type AskQueryResponse = { query: AskQuery };

export const ASK_QUERY_MAX_NAME_LENGTH = 200;
export const ASK_QUERY_MAX_QUESTION_LENGTH = 4000;

// defaultAskQueryName derives a concise saved-query name from a question by
// collapsing whitespace and truncating to a readable length.
export const defaultAskQueryName = (question: string): string => {
  const collapsed = question.replace(/\s+/g, " ").trim();
  if (collapsed.length <= 60) {
    return collapsed;
  }
  return `${collapsed.slice(0, 57).trimEnd()}…`;
};

export type AskQueryNameValidation = { ok: true; name: string } | { ok: false; error: string };

export const validateAskQueryName = (name: string): AskQueryNameValidation => {
  const trimmed = name.trim();
  if (trimmed === "") {
    return { ok: false, error: "Name is required." };
  }
  if (trimmed.length > ASK_QUERY_MAX_NAME_LENGTH) {
    return { ok: false, error: `Name must be at most ${ASK_QUERY_MAX_NAME_LENGTH} characters.` };
  }
  return { ok: true, name: trimmed };
};

// sortAskQueries orders saved queries for display: pinned first, then most
// recently created. It does not mutate the input array.
export const sortAskQueries = (queries: AskQuery[]): AskQuery[] =>
  [...queries].sort((a, b) => {
    if (a.pinned !== b.pinned) {
      return a.pinned ? -1 : 1;
    }
    return (b.created_at ?? "").localeCompare(a.created_at ?? "");
  });

// summarizeQuestion collapses whitespace and truncates a question for compact
// display in the saved-questions list.
export const summarizeQuestion = (question: string, max = 140): string => {
  const collapsed = question.replace(/\s+/g, " ").trim();
  if (collapsed.length <= max) {
    return collapsed;
  }
  return `${collapsed.slice(0, max - 1).trimEnd()}…`;
};

// askQueryCreatePayload builds the POST body for saving a new ask query,
// omitting empty optional fields so the server stores clean values.
export const askQueryCreatePayload = (input: {
  name: string;
  question: string;
  scopeUrn?: string;
  model?: string;
  pinned?: boolean;
}): Record<string, unknown> => {
  const payload: Record<string, unknown> = {
    name: input.name.trim(),
    question: input.question.trim(),
  };
  const scope = (input.scopeUrn ?? "").trim();
  if (scope !== "") {
    payload.scope_urn = scope;
  }
  const model = (input.model ?? "").trim();
  if (model !== "") {
    payload.model = model;
  }
  if (input.pinned) {
    payload.pinned = true;
  }
  return payload;
};
