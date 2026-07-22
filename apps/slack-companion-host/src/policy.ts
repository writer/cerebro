import type { CanonicalWorkToolPolicy } from "./types.js";

export const CANONICAL_WORK_TOOL_POLICIES = {
  operator_security_case_command: {
    allowed_intents: ["response_action"],
    approval_required: false,
    tier: "autonomy_write",
  },
  operator_security_case_execute_command: {
    allowed_intents: ["response_action"],
    approval_required: true,
    tier: "approval",
  },
  operator_security_case_list: {
    allowed_intents: ["security_answer", "code_change", "response_action"],
    approval_required: false,
    tier: "read",
  },
  operator_security_case_open_work_item: {
    allowed_intents: ["security_answer", "code_change", "response_action"],
    approval_required: false,
    tier: "autonomy_write",
  },
  operator_security_case_work_item_status: {
    allowed_intents: ["security_answer", "code_change", "response_action"],
    approval_required: false,
    tier: "read",
  },
} as const satisfies Record<string, CanonicalWorkToolPolicy>;

export type CanonicalWorkToolName = keyof typeof CANONICAL_WORK_TOOL_POLICIES;

export const REQUIRED_CANONICAL_WORK_TOOL_IDS = Object.freeze(
  Object.keys(CANONICAL_WORK_TOOL_POLICIES).sort() as CanonicalWorkToolName[],
);
