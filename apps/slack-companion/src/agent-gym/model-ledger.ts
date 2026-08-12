import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymModelInvocationReceiptV1 } from "./model-invocation.js";

export interface AgentGymModelInvocationLedgerV1 {
  readonly blocked_invocation_count: number;
  readonly input_tokens: number;
  readonly invocation_count: number;
  readonly invocation_refs: readonly string[];
  readonly latency_ms: number;
  readonly output_tokens: number;
  readonly recorded_invocation_count: number;
  readonly schema_version: "agent-gym-model-invocation-ledger/v1";
  readonly total_tokens: number;
}

/** Aggregates invocation receipts while retaining their immutable identities. */
export function createAgentGymModelInvocationLedger(
  receipts: readonly AgentGymModelInvocationReceiptV1[],
): AgentGymModelInvocationLedgerV1 {
  if (!Array.isArray(receipts) || receipts.length > 10_000) invalid();
  const invocationRefs = receipts.map((receipt) => receipt.invocation_ref);
  if (new Set(invocationRefs).size !== invocationRefs.length) invalid();
  return Object.freeze({
    blocked_invocation_count: receipts.filter((receipt) => !receipt.budget.allowed).length,
    input_tokens: sum(receipts.map((receipt) => receipt.token_usage.input_tokens)),
    invocation_count: receipts.length,
    invocation_refs: Object.freeze([...invocationRefs].sort()),
    latency_ms: sum(receipts.map((receipt) => receipt.latency_ms)),
    output_tokens: sum(receipts.map((receipt) => receipt.token_usage.output_tokens)),
    recorded_invocation_count: receipts.filter(
      (receipt) => receipt.response_source === "recorded",
    ).length,
    schema_version: "agent-gym-model-invocation-ledger/v1",
    total_tokens: sum(receipts.map((receipt) => receipt.token_usage.total_tokens)),
  });
}

function sum(values: readonly number[]): number {
  const total = values.reduce((current, value) => current + value, 0);
  if (!Number.isSafeInteger(total) || total < 0) invalid();
  return total;
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym model invocation ledger is invalid.");
}
