import { createHash } from "node:crypto";
import type { SlackActionInputV1 } from "../projections/blocks.js";

export interface SlackEffectApprovalInputV1 {
  readonly approval_ref: string;
  readonly expires_at: string;
  readonly input_digest: string;
  readonly purpose: string;
  readonly requester_ref: string;
  readonly target_ref: string;
  readonly tool_id: string;
}

export interface SlackEffectApprovalProjectionV1 {
  readonly actions: readonly SlackActionInputV1[];
  readonly approval_ref: string;
  readonly input_digest: string;
  readonly schema_version: "slack-effect-approval-projection/v1";
  readonly sections: readonly string[];
}

export class SlackEffectApprovalProjectionError extends Error {}

/** Projects exact-input approval controls; the host still authenticates the click and reloads the record. */
export function projectSlackEffectApproval(
  input: SlackEffectApprovalInputV1,
): SlackEffectApprovalProjectionV1 {
  const approvalRef = ref(input.approval_ref, "approval_ref");
  const requesterRef = ref(input.requester_ref, "requester_ref");
  const targetRef = ref(input.target_ref, "target_ref");
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.input_digest)) {
    throw new SlackEffectApprovalProjectionError("input_digest is invalid.");
  }
  if (!/^[a-z][a-z0-9._-]{0,127}$/u.test(input.tool_id)) {
    throw new SlackEffectApprovalProjectionError("tool_id is invalid.");
  }
  const purpose = text(input.purpose, 600);
  const expiresAt = canonicalTime(input.expires_at);
  const binding = createHash("sha256").update(JSON.stringify({
    approval_ref: approvalRef, expires_at: expiresAt, input_digest: input.input_digest,
    requester_ref: requesterRef, target_ref: targetRef, tool_id: input.tool_id,
  })).digest("hex");
  const value = JSON.stringify({ binding, approval_ref: approvalRef });
  return Object.freeze({
    actions: Object.freeze([
      Object.freeze({ action_key: "approve_effect", label: "Approve", style: "primary", value }),
      Object.freeze({ action_key: "deny_effect", label: "Deny", style: "danger", value }),
    ]),
    approval_ref: approvalRef,
    input_digest: input.input_digest,
    schema_version: "slack-effect-approval-projection/v1",
    sections: Object.freeze([
      purpose,
      `Tool: ${input.tool_id}\nTarget: ${targetRef}\nInput: ${input.input_digest}\nExpires: ${expiresAt}`,
    ]),
  });
}

function ref(value: string, field: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\/[^\s\u0000-\u001f]{1,500}$/u.test(value)) {
    throw new SlackEffectApprovalProjectionError(`${field} is invalid.`);
  }
  return value;
}
function canonicalTime(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new SlackEffectApprovalProjectionError("expires_at is invalid.");
  }
  return value;
}
function text(value: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new SlackEffectApprovalProjectionError("purpose is invalid.");
  }
  return normalized;
}
