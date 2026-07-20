export const ASK_AGENT_FALLBACK_STATUS = {
  stage: "fallback",
  label: "Using Graph Ask",
  detail: "Graph Ask is handling this request.",
  mode: "legacy",
} as const;

export type AskAgentReadiness = {
  detail: string;
  label: string;
  mode: "agent" | "legacy";
};

export const ASK_AGENT_READY_STATUS = {
  label: "Agent path ready",
  detail: "New questions use graph tools first.",
  mode: "agent",
} as const satisfies AskAgentReadiness;

export const ASK_AGENT_FALLBACK_READINESS = {
  label: ASK_AGENT_FALLBACK_STATUS.label,
  detail: "New questions use Graph Ask.",
  mode: ASK_AGENT_FALLBACK_STATUS.mode,
} as const satisfies AskAgentReadiness;

export const askAgentReadiness = ({ canRunAgent }: { canRunAgent: boolean }): AskAgentReadiness =>
  canRunAgent ? ASK_AGENT_READY_STATUS : ASK_AGENT_FALLBACK_READINESS;
