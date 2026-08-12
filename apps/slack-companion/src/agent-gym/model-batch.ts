import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymModelBudgetV1 } from "./model-budget.js";
import {
  invokeAgentGymModel,
  type AgentGymModelInvocationResultV1,
} from "./model-invocation.js";
import {
  createAgentGymModelInvocationLedger,
  type AgentGymModelInvocationLedgerV1,
} from "./model-ledger.js";
import type {
  AgentGymModelInvocationRequestV1,
  AgentGymModelPort,
} from "./model-runtime.js";

export interface AgentGymModelBatchResultV1 {
  readonly batch_ref: string;
  readonly ledger: AgentGymModelInvocationLedgerV1;
  readonly results: readonly AgentGymModelInvocationResultV1[];
  readonly schema_version: "agent-gym-model-batch-result/v1";
}

/** Replays a stable request sequence without Slack, provider concurrency, or wall time. */
export async function runAgentGymModelBatch(
  batchRef: string,
  requests: readonly AgentGymModelInvocationRequestV1[],
  budget: AgentGymModelBudgetV1,
  model: AgentGymModelPort,
  evaluatedAt: string,
): Promise<AgentGymModelBatchResultV1> {
  reference(batchRef);
  if (!Array.isArray(requests) || requests.length < 1 || requests.length > 10_000
    || new Set(requests.map((request) => request.invocation_ref)).size !== requests.length) {
    invalid();
  }
  const results: AgentGymModelInvocationResultV1[] = [];
  for (const request of requests) {
    results.push(await invokeAgentGymModel(request, budget, model, evaluatedAt));
  }
  const frozenResults = Object.freeze(results);
  return Object.freeze({
    batch_ref: batchRef,
    ledger: createAgentGymModelInvocationLedger(
      frozenResults.map((result) => result.receipt),
    ),
    results: frozenResults,
    schema_version: "agent-gym-model-batch-result/v1",
  });
}

function reference(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 240
    || /[\u0000-\u001f\u007f]/u.test(value) || !value.includes("://")) invalid();
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym model batch is invalid.");
}
